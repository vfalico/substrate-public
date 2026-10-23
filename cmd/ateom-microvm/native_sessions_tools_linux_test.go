//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/agent-substrate/substrate/cmd/ateom-microvm/internal/kata"
	"github.com/agent-substrate/substrate/internal/actorlog"
	"github.com/agent-substrate/substrate/internal/ateomnet"
	"github.com/agent-substrate/substrate/internal/ateomnet/dns"
	"github.com/agent-substrate/substrate/internal/ateomtunnel"
	"github.com/agent-substrate/substrate/internal/nodepath"
	"github.com/agent-substrate/substrate/internal/proto/ateletpb"
	"github.com/agent-substrate/substrate/internal/proto/ateompb"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Opt-in native owning-compute qualification. Default drives Sessions harnesswire;
// explicit NATIVE_ATELET/CONTROL/ROUTER/KAIMAHI flags add those real layers.
// Test-owned discovery/credentials are not cluster rollout acceptance.
func TestNativeMicroVMSessionsTools(t *testing.T) {
	root := os.Getenv("EXECUTION_MICROVM_ROOT")
	if root == "" {
		t.Skip("explicit native task resources required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := url.Parse("spiffe://task.local/native")
	template := &x509.Certificate{URIs: []*url.URL{identity}, SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "task-owned-native"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})
	bundle, trust := filepath.Join(root, "bundle.pem"), filepath.Join(root, "trust.pem")
	mustWrite := func(p string, b []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(bundle, append(cert, private...))
	mustWrite(trust, cert)
	ingressAddress := "127.0.0.1:0"
	if os.Getenv("EXECUTION_NATIVE_ROUTER") == "1" {
		ingressAddress = "10.207.8.1:29443"
	}
	if os.Getenv("EXECUTION_NATIVE_ROUTER") == "1" {
		namespace := fmt.Sprintf("poc-ing-%d", os.Getpid())
		hostLink := fmt.Sprintf("t8h%d", os.Getpid())
		peerLink := fmt.Sprintf("t8p%d", os.Getpid())
		command := func(args ...string) error {
			out, err := exec.Command("ip", args...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("ip %v: %w %s", args, err, out)
			}
			return nil
		}
		if err := command("netns", "add", namespace); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := command("netns", "delete", namespace); err != nil {
				t.Error(err)
			}
		}()
		if err := command("link", "add", hostLink, "type", "veth", "peer", "name", peerLink); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := command("link", "delete", hostLink); err != nil {
				t.Error(err)
			}
		}()
		for _, args := range [][]string{{"link", "set", peerLink, "netns", namespace}, {"addr", "add", "10.207.8.1/30", "dev", hostLink}, {"link", "set", hostLink, "up"}, {"-n", namespace, "addr", "add", "10.207.8.2/30", "dev", peerLink}, {"-n", namespace, "link", "set", peerLink, "up"}, {"-n", namespace, "link", "set", "lo", "up"}} {
			if err := command(args...); err != nil {
				t.Fatal(err)
			}
		}
		relayCtx, relayCancel := context.WithCancel(context.Background())
		defer relayCancel()
		relay := exec.CommandContext(relayCtx, "ip", "netns", "exec", namespace, os.Getenv("EXECUTION_NATIVE_ROUTER_BINARY"), "-test.run=^TestNativeTunnelRelay$", "-test.timeout=180s")
		relay.Env = append(os.Environ(), "EXECUTION_NATIVE_RELAY=1")
		relayLog, err := os.OpenFile(filepath.Join(root, "relay.log"), os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer relayLog.Close()
		relay.Stdout = relayLog
		relay.Stderr = relayLog
		if err = relay.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { relayCancel(); _ = relay.Wait() }()
		if err = os.Setenv("EXECUTION_NATIVE_WORKER_IP", "10.207.8.2"); err != nil {
			t.Fatal(err)
		}
	}
	tunnel, err := ateomtunnel.Start(ctx, ateomtunnel.Config{ListenAddress: ingressAddress, ConnectListenAddress: "127.0.0.1:0", CredentialBundle: bundle, TrustBundle: trust, ClientIdentity: "spiffe://task.local/native", EgressListenAddress: "127.0.0.1:29444"}, ateomnet.ActorHTTPUpstream)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := dns.NewRelayForUpstreams([]string{os.Getenv("EXECUTION_MICROVM_DNS_UPSTREAM")})
	if err != nil {
		t.Fatal(err)
	}
	tunnel.DNSRelay = relay
	logs, err := os.OpenFile(filepath.Join(root, "guest-output.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer logs.Close()
	s := NewService("native-task", "/opt/kata/bin/cloud-hypervisor", true, 128, 2, tunnel, actorlog.NewActorLogger(logs, false))
	s.actorCgroups = true

	// TEST-only fault controller: use the existing trusted debug console on the
	// exact fixture-owned guest. Never kill the unrelated host assessor or
	// remove the shared VMM transport. No production fault/control endpoint.
	faultDone := make(chan struct{})
	faultQuit := make(chan struct{})
	runGuestFault := func() {
		defer close(faultDone)
		if os.Getenv("EXECUTION_GUEST_ENFORCER_FAULT") != "service-stop" {
			return
		}
		tick := time.NewTicker(25 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-faultQuit:
				return
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			if _, e := os.Stat(filepath.Join(root, "restart-request")); os.IsNotExist(e) {
				continue
			} else if e != nil {
				t.Error(e)
				return
			}
			s.actorsMu.RLock()
			var actor string
			for id, h := range s.actors {
				if h.vm != nil {
					if actor != "" {
						s.actorsMu.RUnlock()
						t.Error("ambiguous fault target")
						return
					}
					actor = id
				}
			}
			s.actorsMu.RUnlock()
			if actor == "" {
				t.Error("no owned guest for fault")
				return
			}
			c, e := s.executionClient()
			if e != nil {
				t.Error(e)
				return
			}
			record, e := c.GuestCleanupRecord(actor)
			if e != nil {
				t.Error(e)
				return
			}
			if record.Socket != kata.VsockSocketPath(actor) || record.Port != 1030 || record.Locator != "/sys/fs/cgroup/ateomchv" {
				t.Error("fault target locator mismatch")
				return
			}
			if e = c.ValidateGuestCleanup(ctx, record); e != nil {
				t.Error("pre-fault target", e)
				return
			}
			proof := map[string]any{"classification": "TEST-only actual guest unit stop/restart, not process crash", "actor_uid": actor, "socket": record.Socket, "port": record.Port, "operation": record.Operation, "target": record.Target}
			saveFault := func() error {
				raw, err := json.Marshal(proof)
				if err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(root, "guest-service-fault-stages.json"), raw, 0600)
			}
			// Arm restoration BEFORE stop: a lost stop acknowledgement must
			// not leave the exact guest unit stopped. One bounded restoration
			// attempt, never a semantic-refusal retry or fabricated authority.
			restorationAttempted := false
			restore := func() error {
				restorationAttempted = true
				restoreCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				up := kata.DebugConsoleDump(restoreCtx, record.Socket, `systemctl start agentsuite-guardd-guest.service; test "$(systemctl show -p ActiveState --value agentsuite-guardd-guest.service)" = active && echo T807_UNIT_RESTARTED`)
				proof["restart_output"] = up
				if err := saveFault(); err != nil {
					return fmt.Errorf("persist restart output: %w", err)
				}
				if !strings.Contains(up, "\nT807_UNIT_RESTARTED\r") {
					proof["restart_activation_error"] = "active-unit marker absent"
					if err := saveFault(); err != nil {
						return fmt.Errorf("persist activation error: %w", err)
					}
					return fmt.Errorf("guest unit activation unqualified: %s", up)
				}
				// Unit-active is not listener/target readiness. Preserve the
				// exact first readback error; no blanket EOF/identity retry.
				check, checkCancel := context.WithTimeout(restoreCtx, 10*time.Second)
				defer checkCancel()
				if err := c.ValidateGuestCleanup(check, record); err != nil {
					proof["restart_readback_error"] = err.Error()
					if saveErr := saveFault(); saveErr != nil {
						return errors.Join(fmt.Errorf("guest exact-target readback: %w", err), saveErr)
					}
					return fmt.Errorf("guest exact-target readback: %w", err)
				}
				proof["restored_same_target"] = true
				return saveFault()
			}
			defer func() {
				if !restorationAttempted {
					if err := restore(); err != nil {
						t.Error("fault finally restoration", err)
					}
				}
			}()
			// systemctl targets this guest's exact unit; stop does not detach BPF.
			down := kata.DebugConsoleDump(ctx, record.Socket, `preserve=$(systemctl show -p RuntimeDirectoryPreserve --value agentsuite-guardd-guest.service) && printf "RuntimeDirectoryPreserve=%s\n" "$preserve" && test "$preserve" = yes && systemctl stop agentsuite-guardd-guest.service && test "$(systemctl show -p ActiveState --value agentsuite-guardd-guest.service)" = inactive && echo T807_UNIT_STOPPED`)
			proof["stop_output"] = down
			if err := saveFault(); err != nil {
				t.Error("persist stop output", err)
				return
			}
			if !strings.Contains(down, "\nT807_UNIT_STOPPED\r") {
				t.Errorf("guest unit stop unqualified: %s", down)
				return
			}

			raw, e := json.Marshal(proof)
			if e != nil {
				t.Error(e)
				return
			}
			if e = os.WriteFile(filepath.Join(root, "restart-stopped"), raw, 0600); e != nil {
				t.Error(e)
				return
			}
			wait := time.NewTimer(25 * time.Second)
			defer wait.Stop()
			for {
				if _, e = os.Stat(filepath.Join(root, "restart-continue")); e == nil {
					break
				} else if !os.IsNotExist(e) {
					t.Error(e)
					return
				}
				select {
				case <-faultQuit:
					return
				case <-ctx.Done():
					return
				case <-wait.C:
					t.Error("guest outage discriminator did not complete")
					return
				case <-tick.C:
				}
			}
			if e = restore(); e != nil {
				t.Error(e)
				return
			}
			proof["restored_same_target"] = true
			raw, e = json.Marshal(proof)
			if e != nil {
				t.Error(e)
				return
			}
			if e = os.WriteFile(filepath.Join(root, "restart-ready"), raw, 0600); e != nil {
				t.Error(e)
			}
			return
		}
	}
	// Registered before nested-service/actor cleanup defers, hence runs last.
	// A failed/timeout exit cannot manufacture a zero-owner cleanup proof.
	defer func() {
		s.actorsMu.RLock()
		count := len(s.actors)
		s.actorsMu.RUnlock()
		proof := map[string]any{"exact_actor_count": count, "nested_cleanup_complete": !t.Failed() && count == 0}
		raw, err := json.Marshal(proof)
		if err != nil {
			t.Error(err)
			return
		}
		if err = os.WriteFile(filepath.Join(root, "owning-completion.json"), raw, 0600); err != nil {
			t.Error(err)
		}
	}()
	old := nodepath.StaticFilesDir
	nodepath.StaticFilesDir = filepath.Join(root, "assets")
	defer func() { nodepath.StaticFilesDir = old }()
	assets := map[string]string{}
	for name, src := range map[string]string{assetKernel: "/opt/kata/share/kata-containers/vmlinux.container", assetImage: "/opt/kata/share/kata-containers/kata-containers.img", assetVirtiofsd: "/opt/kata/libexec/virtiofsd"} {
		if override := os.Getenv("EXECUTION_NATIVE_ASSET_" + name); override != "" {
			src = override
		}
		real, err := filepath.EvalSymlinks(src)
		if err != nil {
			t.Fatal(err)
		}
		dest := filepath.Join(nodepath.StaticFilesDir, name)
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(real, dest); err != nil {
			t.Fatal(err)
		}
		assets[name] = dest
	}

	raw, err := os.ReadFile(os.Getenv("EXECUTION_MICROVM_REQUIREMENT"))
	if err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("poc-tool-%d", os.Getpid())
	dirs := &ateompb.ActorDirs{RootDir: filepath.Join(root, "tools"), OciBundleDir: filepath.Join(root, "tools", "oci"), CheckpointDir: filepath.Join(root, "tools", "checkpoint"), RestoreDir: filepath.Join(root, "tools", "restore"), DurableDirVolumeMountsDir: filepath.Join(root, "tools", "durable"), SystemInfoVolumeRootsDir: filepath.Join(root, "tools", "sysinfo"), VolumesDir: filepath.Join(root, "tools", "volumes")}
	bundleRoot := filepath.Join(dirs.OciBundleDir, "probe")
	rootfs := filepath.Join(bundleRoot, "rootfs")
	for _, d := range []string{rootfs, filepath.Join(rootfs, "etc"), dirs.CheckpointDir, dirs.RestoreDir, dirs.DurableDirVolumeMountsDir, dirs.SystemInfoVolumeRootsDir, dirs.VolumesDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(filepath.Join(root, "guest-probe"), filepath.Join(rootfs, "probe")); err != nil {
		t.Fatal(err)
	}
	harnessAddress := ":8080"
	if os.Getenv("EXECUTION_NATIVE_ROUTER") == "1" {
		harnessAddress = ":80"
	}
	env := []string{"PATH=/", "HARNESS_KIND=toolchat", "HARNESS_MODEL=fixture", "HARNESS_MODEL_PLACEMENT=native", "HARNESS_MODEL_BASE_URL=http://169.254.17.1:28292", "HARNESS_MODEL_PATH=/responses", "HARNESS_ADDR=" + harnessAddress, "HARNESS_READYZ=:8081"}
	spec := specs.Spec{Version: "1.2.0", Hostname: "native-toolchat", Root: &specs.Root{Path: "rootfs"}, Process: &specs.Process{Args: []string{"/probe"}, Cwd: "/", Env: env, User: specs.User{UID: 0, GID: 0}}, Linux: &specs.Linux{Namespaces: []specs.LinuxNamespace{{Type: specs.PIDNamespace}, {Type: specs.MountNamespace}, {Type: specs.UTSNamespace}, {Type: specs.IPCNamespace}, {Type: specs.NetworkNamespace}}}}
	encoded, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(filepath.Join(bundleRoot, "config.json"), encoded)
	mustWrite(filepath.Join(root, "fixture-native-config.json"), encoded)
	receiverCtx, receiverCancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer receiverCancel()
	ready := make(chan struct{})
	receiverDone := make(chan error, 1)
	go func() {
		if os.Getenv("EXECUTION_PUBLIC_NATIVE_SCENARIO") == "lost-create" {
			// A suspended Create reply cut must never prepare or boot a guest. This
			// is pre-release identity qualification, not packet-denial evidence.
			<-receiverCtx.Done()
			s.actorsMu.RLock()
			n := len(s.actors)
			s.actorsMu.RUnlock()
			if n != 0 {
				receiverDone <- fmt.Errorf("lost Create booted %d native guests", n)
				return
			}
			guest, e := os.ReadFile(filepath.Join(root, "guest-output.log"))
			if e != nil || len(guest) != 0 {
				receiverDone <- fmt.Errorf("lost Create had native guest output: %d %v", len(guest), e)
				return
			}
			receiverDone <- nil
			return
		}
		ns := ""
		// Actor discovery is bounded by receiverCtx (180s). Bootstrap of
		// Control/PostgreSQL is not namespace readiness time: start that
		// deadline only once an actual owned Actor exists.
		var deadline time.Time
		for {
			s.actorsMu.RLock()
			for actorID := range s.actors {
				ns = nodepath.ActorNetNSPath(actorID)
				break
			}
			s.actorsMu.RUnlock()
			if ns != "" {
				if deadline.IsZero() {
					deadline = time.Now().Add(50 * time.Second)
				}
				if _, err := os.Stat(ns); err == nil {
					output, e := exec.Command("/usr/sbin/ip", "netns", "exec", filepath.Base(ns), "ip", "-4", "addr", "show").CombinedOutput()
					_ = os.WriteFile(filepath.Join(root, "receiver-namespace-probe.log"), append([]byte(fmt.Sprintf("ns=%s err=%v\n", ns, e)), output...), 0600)
					if e == nil && strings.Contains(string(output), "169.254.17.1/") {
						break
					}
				}
			}
			if !deadline.IsZero() && time.Now().After(deadline) {
				receiverDone <- fmt.Errorf("namespace not ready")
				return
			}
			select {
			case <-receiverCtx.Done():
				receiverDone <- receiverCtx.Err()
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
		script := `import http.server,socketserver,threading,json,signal,sys,os,socket
counts={'model':0,'allow':0,'deny':0}
lock=threading.Lock()
class Handler(http.server.BaseHTTPRequestHandler):
 def handle(self):
  first=self.request.recv(24,socket.MSG_PEEK)
  if first.startswith(b'T807RAW'):
   data=self.request.recv(100)
   with lock:counts['allow' if self.server.server_port==28296 else 'deny']+=1
   print('RAW_NATIVE_RECEIVER',self.server.server_port,repr(data),flush=True,file=sys.stderr)
   self.request.sendall(b'tool-native-ok\n');return
  return super().handle()
 def log_message(self,*args):pass
 def reply(self,value):
  raw=json.dumps(value).encode();self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
 def do_POST(self):
  raw=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
  with lock:counts['model']+=1
  prompt=json.dumps(raw.get('input',[]))
  if (counts['model']%2==0 if os.environ.get('EXECUTION_PUBLIC_NATIVE_SCENARIO') in ('restart','sessions-restart') else any(x.get('type')=='function_call_output' for x in raw.get('input',[]))):
   output=[{'type':'message','id':'final','role':'assistant','content':[{'type':'output_text','text':'complete'}]}]
  else:
   port=28293 if 'deny' in prompt else 28292
   output=[{'type':'function_call','id':'call-item','call_id':'fetch-'+str(counts['model']),'name':'http_get','arguments':json.dumps({'url':'http://169.254.17.1:'+str(port)+'/tool'})}]
  self.reply({'status':'completed','output':output})
 def do_GET(self):
  with lock:counts['allow' if self.server.server_port==28292 else 'deny']+=1
  raw=b'tool-native-ok';self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
class LiteralServer(http.server.ThreadingHTTPServer):
 def server_bind(self):
  socketserver.TCPServer.server_bind(self)
  self.server_name='native-literal';self.server_port=self.server_address[1]
servers=[]
for port in ([28292,28293,28296] if os.environ.get('EXECUTION_NATIVE_RAW_TCP')=='1' else [28292,28293]):
 s=LiteralServer(('169.254.17.1',port),Handler);servers.append(s);threading.Thread(target=s.serve_forever,daemon=True).start()
if os.environ.get('EXECUTION_NATIVE_RAW_TCP')=='1':
 for port in [28296,28293]:
  c=socket.create_connection(('169.254.17.1',port),2);c.sendall(b'T807RAW');reply=c.recv(100);c.close()
  if reply!=b'tool-native-ok\n':raise RuntimeError('raw control failed')
  print('RAW_UNRESTRICTED_CONTROL_ACK',port,flush=True,file=sys.stderr)
 with lock:counts['allow']=0;counts['deny']=0
print('READY',flush=True)
def finish(*args):
 print(json.dumps(counts),flush=True);sys.exit(0)
signal.signal(signal.SIGTERM,finish)
threading.Event().wait()`
		command := exec.Command("/usr/sbin/ip", "netns", "exec", filepath.Base(ns), "/usr/bin/python3", "-u", "-c", script)
		output, err := command.StdoutPipe()
		if err != nil {
			receiverDone <- err
			return
		}
		command.Stderr = os.Stderr
		_ = os.WriteFile(filepath.Join(root, "receiver-stage.log"), []byte("starting receiver\n"), 0600)
		if err = command.Start(); err != nil {
			receiverDone <- err
			return
		}
		defer func() {
			if command.ProcessState == nil {
				_ = command.Process.Kill()
				_ = command.Wait()
			}
		}()
		_ = os.WriteFile(filepath.Join(root, "receiver-stage.log"), []byte(fmt.Sprintf("receiver pid=%d waiting stdout\n", command.Process.Pid)), 0600)
		first := make([]byte, 6)
		if _, err = io.ReadFull(output, first); err != nil || string(first) != "READY\n" {
			receiverDone <- fmt.Errorf("receiver readiness %q %v", first, err)
			return
		}
		if err := os.WriteFile(filepath.Join(root, "native-receiver-ready"), nil, 0600); err != nil {
			receiverDone <- err
			return
		}
		close(ready)
		<-receiverCtx.Done() // exact tracked process; no process-name signalling
		// SIGTERM is handled to emit truthful receiver counts before exit.
		_ = command.Process.Signal(syscall.SIGTERM)
		rest, readErr := io.ReadAll(output)
		waitErr := command.Wait()
		if err = os.WriteFile(filepath.Join(root, "tool-receiver.log"), append(first, rest...), 0600); err != nil {
			receiverDone <- err
			return
		}
		if readErr != nil || waitErr != nil {
			receiverDone <- fmt.Errorf("receiver completion %v %v", readErr, waitErr)
			return
		}
		var counts map[string]int
		if err = json.Unmarshal(bytes.TrimSpace(rest), &counts); err != nil {
			receiverDone <- err
			return
		}
		expectedModel := 3
		if os.Getenv("EXECUTION_NATIVE_KAIMAHI") == "1" {
			expectedModel = 2
			switch os.Getenv("EXECUTION_PUBLIC_NATIVE_SCENARIO") {
			case "sessions-restart":
				expectedModel = 4
			case "restart":
				// Failed proof elects native stop. No inference/tool may run on the
				// retired operation after Guardd returns; only the initial allowed turn.
				expectedModel = 2
			case "deny":
				expectedModel = 1
			case "empty", "lost-resume":
				expectedModel = 0
			}
		}
		expectedAllowed := 1
		if os.Getenv("EXECUTION_PUBLIC_NATIVE_SCENARIO") == "sessions-restart" {
			expectedAllowed = 2
		}

		if scenario := os.Getenv("EXECUTION_PUBLIC_NATIVE_SCENARIO"); scenario == "deny" || scenario == "empty" || scenario == "lost-resume" || scenario == "lost-create" {
			expectedAllowed = 0
		}
		if os.Getenv("EXECUTION_NATIVE_NETWORK_INDEPENDENT") == "1" {
			// Evidence-only alternative guest: no model request, exactly one native
			// tool attempt. Same binary for deny-all and useful allow control.
			expectedModel = 0
			expectedAllowed = 1
			marker := "NETWORK_INDEPENDENT_NATIVE_PROBE_ALLOWED"
			if os.Getenv("EXECUTION_PUBLIC_NATIVE_SCENARIO") == "empty" {
				expectedAllowed = 0
				marker = "NETWORK_INDEPENDENT_NATIVE_PROBE_DENIED"
			}
			guestLog, err := os.ReadFile(filepath.Join(root, "guest-output.log"))
			if err != nil || !strings.Contains(string(guestLog), "NETWORK_INDEPENDENT_NATIVE_PROBE_ATTEMPT") || !strings.Contains(string(guestLog), marker) {
				receiverDone <- fmt.Errorf("network-independent guest did not run expected native attempt: %s %v", marker, err)
				return
			}
		}
		if counts["model"] != expectedModel || counts["allow"] != expectedAllowed || counts["deny"] != 0 {
			receiverDone <- fmt.Errorf("wrong real receiver counts %v", counts)
			return
		}
		receiverDone <- nil
	}()
	var run func() error
	var terminate func(context.Context) error
	if os.Getenv("EXECUTION_NATIVE_ATELET") == "1" {
		// The child serves ordinary atelet image-cache/OCI and Run RPC, and reaches
		// this actual microVM service over its generated Ateom transport.
		ateomListener, err := net.Listen("unix", filepath.Join(root, "ateom-rpc.sock"))
		if err != nil {
			t.Fatal(err)
		}
		server := grpc.NewServer()
		ateompb.RegisterAteomServer(server, s)
		go func() { _ = server.Serve(ateomListener) }()
		defer server.Stop()
		// atelet and ateom use their ordinary shared ActorDirs layout, all task-owned.
		nodepath.ActorsDir = filepath.Join(root, "actors")
		nodepath.StaticFilesDir = filepath.Join(root, "assets")
		childCtx, childCancel := context.WithTimeout(context.Background(), 180*time.Second)
		defer childCancel()
		child := exec.CommandContext(childCtx, os.Getenv("EXECUTION_NATIVE_ATELET_BINARY"), "-test.run=^TestNativeAteletRPC$", "-test.v", "-test.timeout=160s")
		child.Env = append(os.Environ(), "EXECUTION_ATELET_NATIVE_ROOT="+root)
		childLog, err := os.OpenFile(filepath.Join(root, "atelet.log"), os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer childLog.Close()
		child.Stdout = childLog
		child.Stderr = childLog
		if err = child.Start(); err != nil {
			t.Fatal(err)
		}
		childDone := make(chan error, 1)
		go func() { childDone <- child.Wait() }()
		defer func() {
			if err := os.WriteFile(filepath.Join(root, "atelet-stop"), nil, 0600); err != nil {
				t.Error(err)
			}
			select {
			case err := <-childDone:
				if err != nil {
					t.Error("atelet exit", err)
				}
			case <-time.After(10 * time.Second):
				childCancel()
				<-childDone
				t.Error("atelet did not stop")
			}
		}()
		var info struct {
			Image  string                         `json:"image"`
			Assets map[string]*ateletpb.AssetFile `json:"assets"`
		}
		for {
			if data, err := os.ReadFile(filepath.Join(root, "atelet-ready.json")); err == nil {
				if err = json.Unmarshal(data, &info); err != nil {
					t.Fatal(err)
				}
				break
			}
			select {
			case err := <-childDone:
				t.Fatalf("atelet exited before ready: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(50 * time.Millisecond):
			}
		}
		conn, err := grpc.NewClient("unix://"+filepath.Join(root, "atelet-rpc.sock"), grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		client := ateletpb.NewAteomHerderClient(conn)
		envMap := []*ateletpb.EnvEntry{}
		for _, value := range env {
			k, v, ok := strings.Cut(value, "=")
			if !ok {
				t.Fatal("bad env")
			}
			envMap = append(envMap, &ateletpb.EnvEntry{Name: k, Value: v})
		}
		if os.Getenv("EXECUTION_NATIVE_CONTROL") == "1" {
			controlEnv := []*ateapipb.EnvVar{}
			for _, entry := range envMap {
				controlEnv = append(controlEnv, &ateapipb.EnvVar{Name: entry.Name, Value: entry.Value})
			}
			config, err := json.Marshal(struct {
				Env []*ateapipb.EnvVar `json:"env"`
			}{controlEnv})
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(root, "native-control-config.json"), config, 0600); err != nil {
				t.Fatal(err)
			}
			controlCtx, controlCancel := context.WithTimeout(context.Background(), 180*time.Second)
			defer controlCancel()
			control := exec.CommandContext(controlCtx, os.Getenv("EXECUTION_NATIVE_CONTROL_BINARY"), "-test.run=^TestNativeControlRPC$", "-test.v", "-test.timeout=170s")
			control.Env = append(os.Environ(), "EXECUTION_CONTROL_NATIVE_ROOT="+root)
			logFile, err := os.OpenFile(filepath.Join(root, "control.log"), os.O_CREATE|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer logFile.Close()
			control.Stdout = logFile
			control.Stderr = logFile
			if err = control.Start(); err != nil {
				t.Fatal(err)
			}
			controlDone := make(chan error, 1)
			go func() { controlDone <- control.Wait() }()
			defer func() {
				if err := os.WriteFile(filepath.Join(root, "control-stop"), nil, 0600); err != nil {
					t.Error(err)
				}
				select {
				case err := <-controlDone:
					if err != nil {
						t.Error("control exit", err)
					}
				case <-time.After(15 * time.Second):
					controlCancel()
					<-controlDone
					t.Error("control did not stop")
				}
			}()
			for {
				if _, err := os.Stat(filepath.Join(root, "control-ready")); err == nil {
					break
				}
				select {
				case <-controlCtx.Done():
					t.Fatal(controlCtx.Err())
				case <-time.After(50 * time.Millisecond):
				}
			}
			controlConn, err := grpc.NewClient("unix://"+filepath.Join(root, "control-rpc.sock"), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatal(err)
			}
			defer controlConn.Close()
			c := ateapipb.NewControlClient(controlConn)
			actorRef := &ateapipb.ObjectRef{Atespace: "native", Name: "tools"}
			run = func() error {
				actor, err := c.CreateActor(ctx, &ateapipb.CreateActorRequest{Actor: &ateapipb.Actor{Metadata: &ateapipb.ResourceMetadata{Atespace: "native", Name: "tools"}, ActorTemplate: &ateapipb.ObjectRef{Atespace: "native", Name: "toolchat"}, ExecutionRequirement: raw}})
				if err != nil {
					return err
				}
				id = actor.Metadata.Uid
				resumed, err := c.ResumeActor(ctx, &ateapipb.ResumeActorRequest{Actor: actorRef})
				if err != nil {
					return err
				}
				if resumed.Actor.GetStatus().GetState() != ateapipb.ActorState_ACTOR_STATE_RUNNING {
					return fmt.Errorf("control actor not RUNNING")
				}
				if !bytes.Equal(resumed.Actor.ExecutionRequirement, raw) {
					return fmt.Errorf("control requirement drift")
				}
				return nil
			}
			terminate = func(clean context.Context) error {
				_, err := c.DeleteActor(clean, &ateapipb.DeleteActorRequest{Actor: actorRef, AnyState: true})
				return err
			}
		} else {
			spec := &ateletpb.WorkloadSpec{ExecutionRequirement: raw, Containers: []*ateletpb.Container{{Name: "probe", Image: info.Image, Command: []string{"/probe"}, Env: envMap}}}
			run = func() error {
				_, err := client.Run(ctx, &ateletpb.RunRequest{Atespace: "native", ActorName: "tools", ActorUid: id, WorkerPodUid: "11111111-1111-4111-8111-111111111111", SandboxAssets: &ateletpb.SandboxAssets{SandboxClass: "microvm", Assets: map[string]*ateletpb.ArchAssets{"amd64": {Files: info.Assets}}}, MemoryBytes: 1024 * 1024 * 1024, CpuMilli: 1000, Spec: spec})
				return err
			}
			terminate = func(clean context.Context) error {
				_, err := client.Terminate(clean, &ateletpb.TerminateRequest{Atespace: "native", ActorName: "tools", ActorUid: id, WorkerPodUid: "11111111-1111-4111-8111-111111111111", Spec: spec})
				return err
			}
		}

	} else {
		req := &ateompb.RunWorkloadRequest{Atespace: "native", ActorName: "tools", ActorUid: id, ActorDirs: dirs, RuntimeAssetPaths: assets, MemoryBytes: 1024 * 1024 * 1024, CpuMilli: 1000, Spec: &ateompb.WorkloadSpec{ExecutionRequirement: raw, Containers: []*ateompb.Container{{Name: "probe", ContainerSpec: &ateompb.ContainerSpec{Args: []string{"/probe"}, Env: env}}}}}
		run = func() error { _, err := s.RunWorkload(ctx, req); return err }
		terminate = func(clean context.Context) error {
			_, err := s.TerminateWorkload(clean, &ateompb.TerminateWorkloadRequest{ActorUid: id, ActorDirs: dirs})
			return err
		}
	}
	if os.Getenv("EXECUTION_NATIVE_KAIMAHI") == "1" {
		run = func() error { return nil }
		terminate = func(clean context.Context) error {
			s.actorsMu.RLock()
			ids := []string{}
			for uid := range s.actors {
				ids = append(ids, uid)
			}
			s.actorsMu.RUnlock()
			var failures []error
			for _, uid := range ids {
				_, err := s.TerminateWorkload(clean, &ateompb.TerminateWorkloadRequest{Atespace: "native", ActorName: "tools", ActorUid: uid, ActorDirs: &ateompb.ActorDirs{RootDir: filepath.Join(nodepath.ActorsDir, uid), OciBundleDir: filepath.Join(nodepath.ActorsDir, uid, "bundles"), CheckpointDir: filepath.Join(nodepath.ActorsDir, uid, "checkpoint"), RestoreDir: filepath.Join(nodepath.ActorsDir, uid, "restore"), DurableDirVolumeMountsDir: filepath.Join(nodepath.ActorsDir, uid, "durable-dir"), SystemInfoVolumeRootsDir: filepath.Join(nodepath.ActorsDir, uid, "system-info"), VolumesDir: filepath.Join(nodepath.ActorsDir, uid, "volumes")}})
				if err != nil {
					failures = append(failures, err)
				}
			}
			return errors.Join(failures...)
		}
	}

	// Teardown is registered before Run so partial startup cannot orphan compute.
	defer func() {
		clean, c := context.WithTimeout(context.Background(), 20*time.Second)
		defer c()
		if err := terminate(clean); err != nil {
			if os.Getenv("EXECUTION_GUEST_ENFORCER_FAULT") == "service-stop" {
				raw, encodeErr := json.Marshal(map[string]string{"stage": "owning Actor retirement", "error": err.Error()})
				if encodeErr != nil {
					t.Error("encode retirement error", encodeErr)
				} else if writeErr := os.WriteFile(filepath.Join(root, "guest-service-retirement-error.json"), raw, 0600); writeErr != nil {
					t.Error("persist retirement error", writeErr)
				}
			}
			t.Error("native termination", err)
			// A failing transport may not leave a real VMM orphaned. Exact
			// in-process owning-compute cleanup remains available here.
			fallback, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			_, err = s.TerminateWorkload(fallback, &ateompb.TerminateWorkloadRequest{Atespace: "native", ActorName: "tools", ActorUid: id, ActorDirs: &ateompb.ActorDirs{RootDir: filepath.Join(nodepath.ActorsDir, id), OciBundleDir: filepath.Join(nodepath.ActorsDir, id, "bundles"), CheckpointDir: filepath.Join(nodepath.ActorsDir, id, "checkpoint"), RestoreDir: filepath.Join(nodepath.ActorsDir, id, "restore"), DurableDirVolumeMountsDir: filepath.Join(nodepath.ActorsDir, id, "durable-dir"), SystemInfoVolumeRootsDir: filepath.Join(nodepath.ActorsDir, id, "system-info"), VolumesDir: filepath.Join(nodepath.ActorsDir, id, "volumes")}})
			if err != nil {
				t.Error("exact fallback retirement", err)
			}
		}
	}()
	if err = run(); err != nil {
		t.Fatal("native execution startup", err)
	}
	var dialer func(context.Context, string, string) (net.Conn, error)
	if os.Getenv("EXECUTION_NATIVE_KAIMAHI") != "1" {

		select {
		case <-ready:
		case err := <-receiverDone:
			t.Fatal("receiver", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		s.actorsMu.RLock()
		hosted := s.actors[id]
		network := hosted.network
		s.actorsMu.RUnlock()
		dialer = network.Dialer()
	}

	// Test-only bridge drives real remote Sessions controller/harnesswire over ordinary
	// gRPC. It does not manufacture Control-plane or public Kaimahi acceptance.
	cmd := exec.CommandContext(ctx, os.Getenv("EXECUTION_SESSIONS_CLIENT"))
	if os.Getenv("EXECUTION_NATIVE_KAIMAHI") == "1" {
		cmd = exec.CommandContext(ctx, os.Getenv("EXECUTION_NATIVE_KAIMAHI_BINARY"), "-test.run=^TestSuiteToolchatPublicNativeIntegration$", "-test.v", "-test.timeout=90s")
	}
	if os.Getenv("EXECUTION_NATIVE_ROUTER") == "1" {
		routerCtx, routerCancel := context.WithCancel(ctx)
		defer routerCancel()
		router := exec.CommandContext(routerCtx, os.Getenv("EXECUTION_NATIVE_ROUTER_BINARY"), "-test.run=^TestNativeRouterRPC$", "-test.v", "-test.timeout=140s")
		router.Env = append(os.Environ(), "EXECUTION_ROUTER_NATIVE_ROOT="+root)
		log, err := os.OpenFile(filepath.Join(root, "router.log"), os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer log.Close()
		router.Stdout = log
		router.Stderr = log
		if err = router.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- router.Wait() }()
		defer func() {
			if err := os.WriteFile(filepath.Join(root, "router-stop"), nil, 0600); err != nil {
				t.Error(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Error("router exit", err)
				}
			case <-time.After(10 * time.Second):
				routerCancel()
				<-done
				t.Error("router did not stop")
			}
		}()
		var address []byte
		for {
			if raw, err := os.ReadFile(filepath.Join(root, "router-ready")); err == nil {
				address = raw
				break
			}
			select {
			case err := <-done:
				done <- err
				t.Fatalf("router exited before readiness: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(50 * time.Millisecond):
			}
		}
		cmd.Env = append(os.Environ(), "SESSIONS_NATIVE_ROUTER="+string(address), "SESSIONS_NATIVE_ACTOR_UID="+id, "EXECUTION_PUBLIC_NATIVE_ROOT="+root, "EXECUTION_NATIVE_COMPUTE_SOURCE="+filepath.Join(os.Getenv("EXECUTION_TASK_ROOT"), "sources/substrate-sessions/cmd/ateom-microvm/native_sessions_tools_linux_test.go"))
	} else {
		cmd.Env = append(os.Environ(), "SESSIONS_NATIVE_PROXY="+filepath.Join(root, "bridge.sock"))
		bridge := newNativeHarnessBridge(t, ctx, filepath.Join(root, "bridge.sock"), dialer)
		defer bridge()
	}
	// Register after all owning support/Actor teardown defers: LIFO joins the
	// fault controller (including its bounded restoration) before any teardown.
	// Start here so earlier setup failure cannot leave an unjoined controller.
	go runGuestFault()
	defer func() { close(faultQuit); <-faultDone }()
	output, err := cmd.CombinedOutput()
	if writeErr := os.WriteFile(filepath.Join(root, "sessions-native-client.log"), output, 0600); writeErr != nil {
		t.Fatal(writeErr)
	}
	marker := "NATIVE_SESSIONS_TOOL_PASS"
	if os.Getenv("EXECUTION_NATIVE_KAIMAHI") == "1" {
		marker = "PUBLIC_KAIMAHI_REAL_NATIVE_TOOLCHAT_REPLAY_PASS"
		if scenario := os.Getenv("EXECUTION_PUBLIC_NATIVE_SCENARIO"); scenario == "deny" || scenario == "empty" || scenario == "lost-resume" || scenario == "lost-create" {
			marker = "PUBLIC_KAIMAHI_REAL_NATIVE_" + strings.ToUpper(scenario) + "_REFUSAL_NO_RECEIPT_PASS"
		}
	}
	if os.Getenv("EXECUTION_NATIVE_NETWORK_INDEPENDENT") == "1" {
		marker = "PUBLIC_ORDINARY_DAEMON_NETWORK_INDEPENDENT_NO_INFERENCE_RECEIPT"
	}
	if err != nil || !strings.Contains(string(output), marker) {
		select {
		case receiverErr := <-receiverDone:
			t.Logf("receiver failed: %v", receiverErr)
		default:
			s.actorsMu.RLock()
			for uid := range s.actors {
				t.Logf("receiver current actor=%s ns=%s", uid, nodepath.ActorNetNSPath(uid))
			}
			s.actorsMu.RUnlock()
		}
		t.Fatalf("Sessions native exchange %v %s", err, output)
	}
	receiverCancel()
	if err := <-receiverDone; err != nil {
		t.Fatal(err)
	}
	if os.Getenv("EXECUTION_NATIVE_KAIMAHI") == "1" {
		t.Log("REAL_MICROVM_PUBLIC_KAIMAHI_" + os.Getenv("EXECUTION_PUBLIC_NATIVE_SCENARIO") + "_PASS")
	} else {
		t.Log("REAL_MICROVM_SESSIONS_NATIVE_MODEL_TOOL_REPLAY_DENY_PASS")
	}
}

func newNativeHarnessBridge(t *testing.T, ctx context.Context, path string, dial func(context.Context, string, string) (net.Conn, error)) func() {
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var conns []net.Conn
	acceptDone := make(chan struct{})
	bridgeCtx, bridgeCancel := context.WithCancel(ctx)
	go func() {
		defer close(acceptDone)
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				mu.Lock()
				conns = append(conns, c)
				mu.Unlock()
				dialCtx, dialCancel := context.WithTimeout(bridgeCtx, 5*time.Second)
				defer dialCancel()
				up, e := dial(dialCtx, "tcp", "169.254.17.2:8080")
				if e != nil {
					return
				}
				defer up.Close()
				mu.Lock()
				conns = append(conns, up)
				mu.Unlock()
				done := make(chan struct{})
				go func() { _, _ = io.Copy(up, c); close(done) }()
				_, _ = io.Copy(c, up)
				up.Close()
				c.Close()
				<-done
			}()
		}
	}()
	return func() {
		bridgeCancel()
		listener.Close()
		<-acceptDone
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
		os.Remove(path)
	}
}
