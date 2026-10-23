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
	template := &x509.Certificate{URIs: []*url.URL{identity}, SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "task-owned-native"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
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
	vmmBinary := "/opt/kata/bin/cloud-hypervisor"
	if os.Getenv("EXECUTION_CURRENT_VMM") != "" {
		vmmBinary = os.Getenv("EXECUTION_CURRENT_VMM")
	}
	s := NewService("native-task", vmmBinary, true, 128, 2, tunnel, actorlog.NewActorLogger(logs, false))
	s.actorCgroups = true
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
	if os.Getenv("EXECUTION_NATIVE_KAGENT_A2A") == "1" {
		extra, e := os.ReadFile(os.Getenv("EXECUTION_KAGENT_ENV"))
		if e != nil {
			t.Fatal(e)
		}
		var additions []string
		if e = json.Unmarshal(extra, &additions); e != nil {
			t.Fatal(e)
		}
		env = append([]string{"PATH=/bin:/", "HOME=/data"}, additions...)
	}
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
	if os.Getenv("EXECUTION_CURRENT_GOLDEN") != "1" || os.Getenv("EXECUTION_CURRENT_PUBLIC") == "1" {
		go func() {
			ns := ""
			deadline := time.Now().Add(50 * time.Second)
			for {
				s.actorsMu.RLock()
				for actorID, hosted := range s.actors {
					if os.Getenv("EXECUTION_CURRENT_PUBLIC") == "1" && !strings.HasPrefix(hosted.attribution.Ref.Name, "session-") {
						continue
					}
					ns = nodepath.ActorNetNSPath(actorID)
					break
				}
				s.actorsMu.RUnlock()
				if ns != "" {
					if _, err := os.Stat(ns); err == nil {
						output, e := exec.Command("/usr/sbin/ip", "netns", "exec", filepath.Base(ns), "ip", "-4", "addr", "show").CombinedOutput()
						_ = os.WriteFile(filepath.Join(root, "receiver-namespace-probe.log"), append([]byte(fmt.Sprintf("ns=%s err=%v\n", ns, e)), output...), 0600)
						if e == nil && strings.Contains(string(output), "169.254.17.1/") {
							break
						}
					}
				}
				if time.Now().After(deadline) {
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

			if os.Getenv("EXECUTION_CURRENT_PUBLIC") == "1" {
				capture := exec.CommandContext(receiverCtx, "ip", "netns", "exec", filepath.Base(ns), "tcpdump", "-U", "-i", "tap0_kata", "-w", filepath.Join(root, "compiled-public.pcap"))
				if err := capture.Start(); err != nil {
					receiverDone <- err
					return
				}
				defer func() { _ = capture.Process.Kill(); _ = capture.Wait() }()
			}
			script := `import http.server,socketserver,threading,json,signal,sys,os,socket,select
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
  if os.environ.get('EXECUTION_NATIVE_KAGENT_A2A')=='1':
   self.send_response(200);self.send_header('Content-Type','text/event-stream');self.end_headers()
   def emit(v):self.wfile.write(('data: '+json.dumps(v)+'\n\n').encode());self.wfile.flush()
   outputs=[x for x in raw.get('input',[]) if x.get('type')=='function_call_output']
   if counts['model']%2==1:
    tool=next((x for x in raw.get('tools',[]) if x.get('name') in ['exec_command','shell_command','shell']),None)
    if not tool:print('NO_NATIVE_SHELL_TOOL',raw,flush=True);return
    command='/bin/busybox wget -qO- http://169.254.17.1:28292/tool; /bin/busybox wget -T 2 -qO- http://169.254.17.1:28293/denied; echo NATIVE_PROBE_DONE'
    if os.environ.get('EXECUTION_CURRENT_SEPARATE')=='1':command=command.replace(':28292/tool',':28296/tool').replace('wget -qO-', 'wget -T 2 -qO-')
    if os.environ.get('EXECUTION_CURRENT_RAW_TCP')=='1':command="printf T807RAW | /bin/busybox nc -w 2 169.254.17.1 28296; printf T807RAW | /bin/busybox nc -w 2 169.254.17.1 28293; echo NATIVE_PROBE_DONE"
    if os.environ.get('EXECUTION_KAGENT_NATIVE_SCENARIO')=='deny':command='/bin/busybox wget -T 2 -qO- http://169.254.17.1:28293/denied; echo NATIVE_PROBE_DONE'
    args={'command':command,'timeout_ms':6000} if tool['name']=='shell_command' else ({'cmd':command,'yield_time_ms':10000,'max_output_tokens':2000} if tool['name']=='exec_command' else {'command':['/bin/sh','-c',command],'timeout_ms':6000})
    item={'type':'function_call','id':'native-call-'+str(counts['model']),'call_id':'native-network-'+str(counts['model']),'name':tool['name'],'arguments':json.dumps(args)}
    emit({'type':'response.created','response':{'id':'tool'}});emit({'type':'response.output_item.added','output_index':0,'item':dict(item,arguments='')});emit({'type':'response.output_item.done','output_index':0,'item':item});emit({'type':'response.completed','response':{'id':'tool','output':[item],'usage':{'input_tokens':10,'output_tokens':10,'total_tokens':20}}})
   else:
    print('NATIVE_FUNCTION_RESULT',json.dumps(outputs),flush=True)
    if os.environ.get('EXECUTION_KAGENT_NATIVE_SCENARIO')=='deny' or os.environ.get('EXECUTION_CURRENT_TOOL_DENY')=='1':
     if any('tool-native-ok' in x.get('output','') for x in outputs) or not any('NATIVE_PROBE_DONE' in x.get('output','') for x in outputs):print('INVALID_DENIED_NATIVE_RESULT',flush=True);return
    elif not any('tool-native-ok' in x.get('output','') and 'NATIVE_PROBE_DONE' in x.get('output','') for x in outputs):print('INVALID_NATIVE_RESULT',flush=True);return
    answer='blocked' if os.environ.get('EXECUTION_KAGENT_NATIVE_SCENARIO')=='deny' or os.environ.get('EXECUTION_CURRENT_TOOL_DENY')=='1' else 'complete'
    item={'type':'message','id':'answer','role':'assistant','content':[{'type':'output_text','text':answer}]}
    emit({'type':'response.created','response':{'id':'answer'}});emit({'type':'response.output_item.added','output_index':0,'item':item});emit({'type':'response.output_text.delta','item_id':'answer','output_index':0,'content_index':0,'delta':answer});emit({'type':'response.output_item.done','output_index':0,'item':item});emit({'type':'response.completed','response':{'id':'answer','usage':{'input_tokens':10,'output_tokens':10,'total_tokens':20}}})
   return
  prompt=json.dumps(raw.get('input',[]))
  if any(x.get('type')=='function_call_output' for x in raw.get('input',[])):
   output=[{'type':'message','id':'final','role':'assistant','content':[{'type':'output_text','text':'complete'}]}]
  else:
   port=28293 if 'deny' in prompt else 28292
   output=[{'type':'function_call','id':'call-item','call_id':'fetch-1','name':'http_get','arguments':json.dumps({'url':'http://169.254.17.1:'+str(port)+'/tool'})}]
  self.reply({'status':'completed','output':output})
 def do_GET(self):
  with lock:counts['allow' if self.server.server_port in [28292,28294,28296] else 'deny']+=1
  raw=b'tool-native-ok';self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
class LiteralServer(http.server.ThreadingHTTPServer):
 def server_bind(self):
  socketserver.TCPServer.server_bind(self)
  self.server_name='native-literal';self.server_port=self.server_address[1]
class Mux(socketserver.ThreadingTCPServer):allow_reuse_address=True
class Forward(socketserver.BaseRequestHandler):
 def handle(self):
  first=self.request.recv(24,socket.MSG_PEEK)
  if first.startswith(b'PRI * HTTP/2.0'):
   up=socket.socket(socket.AF_UNIX);up.connect(open(os.path.join(os.environ['EXECUTION_MICROVM_ROOT'],'kagent-control-path')).read())
  else:
   up=socket.create_connection(('169.254.17.1',28294))
  try:
   while True:
    ready,_,_=select.select([self.request,up],[],[],15)
    if not ready:return
    for src in ready:
     data=src.recv(65536)
     if not data:return
     (up if src is self.request else self.request).sendall(data)
  finally:up.close()
servers=[]
if os.environ.get('EXECUTION_NATIVE_KAGENT_A2A')=='1':
 mux=Mux(('169.254.17.1',28292),Forward);servers.append(mux);threading.Thread(target=mux.serve_forever,daemon=True).start()
for port in ([28295,28296,28293] if os.environ.get('EXECUTION_CURRENT_SEPARATE')=='1' else ([28294,28293] if os.environ.get('EXECUTION_NATIVE_KAGENT_A2A')=='1' else [28292,28293])):
 s=LiteralServer(('169.254.17.1',port),Handler);servers.append(s);threading.Thread(target=s.serve_forever,daemon=True).start()
if os.environ.get('EXECUTION_CURRENT_OVERLAP')=='1':
 class Bridge(socketserver.BaseRequestHandler):
  def handle(self):
   up=socket.create_connection(('169.254.17.1',self.server.port))
   try:
    while True:
     ready,_,_=select.select([self.request,up],[],[],30)
     if not ready:return
     for src in ready:
      data=src.recv(65536)
      if not data:return
      (up if src is self.request else self.request).sendall(data)
   finally:up.close()
 for port in [28292,28295,28296,28293]:
  b=socketserver.ThreadingUnixStreamServer(os.path.join(os.environ['EXECUTION_MICROVM_ROOT'],'bridge-'+str(port)),Bridge);b.port=port;servers.append(b);threading.Thread(target=b.serve_forever,daemon=True).start()
if os.environ.get('EXECUTION_CURRENT_RAW_TCP')=='1':
 for port in [28296,28293]:
  c=socket.create_connection(('169.254.17.1',port),2);c.sendall(b'T807RAW');reply=c.recv(100);c.close()
  if reply!=b'tool-native-ok\n':raise RuntimeError('raw unrestricted control failed')
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
			if os.Getenv("EXECUTION_CURRENT_OVERLAP") == "1" {
				secondNS := ""
				deadline := time.Now().Add(35 * time.Second)
				for secondNS == "" {
					s.actorsMu.RLock()
					for actorID, h := range s.actors {
						candidate := nodepath.ActorNetNSPath(actorID)
						if strings.HasPrefix(h.attribution.Ref.Name, "session-") && candidate != ns {
							secondNS = candidate
							break
						}
					}
					s.actorsMu.RUnlock()
					if time.Now().After(deadline) {
						receiverDone <- fmt.Errorf("second receiver namespace not found")
						return
					}
					if secondNS == "" {
						time.Sleep(50 * time.Millisecond)
					}
				}
				bridgeScript := `import socket,socketserver,threading,select,sys
root=sys.argv[1]
class Forward(socketserver.BaseRequestHandler):
 def handle(self):
  up=socket.socket(socket.AF_UNIX);up.connect(root+'/bridge-'+str(self.server.server_address[1]))
  try:
   while True:
    ready,_,_=select.select([self.request,up],[],[],30)
    if not ready:return
    for src in ready:
     data=src.recv(65536)
     if not data:return
     (up if src is self.request else self.request).sendall(data)
  finally:up.close()
class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True
servers=[]
for port in [28292,28295,28296,28293]:
 s=Server(('169.254.17.1',port),Forward);servers.append(s);threading.Thread(target=s.serve_forever,daemon=True).start()
print('READY',flush=True)
threading.Event().wait()`
				bridge := exec.CommandContext(receiverCtx, "ip", "netns", "exec", filepath.Base(secondNS), "python3", "-u", "-c", bridgeScript, root)
				pipe, err := bridge.StdoutPipe()
				if err != nil {
					receiverDone <- err
					return
				}
				bridge.Stderr = os.Stderr
				if err := bridge.Start(); err != nil {
					receiverDone <- err
					return
				}
				defer func() { _ = bridge.Process.Kill(); _ = bridge.Wait() }()
				first := make([]byte, 6)
				if _, err := io.ReadFull(pipe, first); err != nil || string(first) != "READY\n" {
					receiverDone <- fmt.Errorf("second receiver bridge failed: %q %v", first, err)
					return
				}
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
			countLines := bytes.Split(bytes.TrimSpace(rest), []byte("\n"))
			if err = json.Unmarshal(countLines[len(countLines)-1], &counts); err != nil {
				receiverDone <- err
				return
			}
			expectedModel := 3
			if os.Getenv("EXECUTION_NATIVE_KAGENT_A2A") == "1" {
				expectedModel = 4
				if os.Getenv("EXECUTION_KAGENT_NATIVE_SCENARIO") == "deny" {
					expectedModel = 2
				}
			}
			if os.Getenv("EXECUTION_NATIVE_KAIMAHI") == "1" {
				expectedModel = 2
				switch os.Getenv("EXECUTION_PUBLIC_NATIVE_SCENARIO") {
				case "deny":
					expectedModel = 1
				case "empty":
					expectedModel = 0
				}
			}
			expectedAllowed := 1
			if os.Getenv("EXECUTION_NATIVE_KAGENT_A2A") == "1" {
				expectedAllowed = 2
				if os.Getenv("EXECUTION_KAGENT_NATIVE_SCENARIO") == "deny" {
					expectedAllowed = 0
				}
			}
			if scenario := os.Getenv("EXECUTION_PUBLIC_NATIVE_SCENARIO"); scenario == "deny" || scenario == "empty" {
				expectedAllowed = 0
			}
			if os.Getenv("EXECUTION_CURRENT_PUBLIC") == "1" {
				expectedModel = 2
				expectedAllowed = 1
			}
			if os.Getenv("EXECUTION_CURRENT_RECOVERY") == "1" {
				expectedModel = 4
				expectedAllowed = 2
			}
			if os.Getenv("EXECUTION_CURRENT_OVERLAP") == "1" {
				expectedModel = 10
				expectedAllowed = 5
			}
			// Overlap invokes the exchange three times, but the third is a
			// survivor continuation: it replays its original recovery Task.
			// Two fresh Sessions add one recovery exchange each, not three.
			if os.Getenv("EXECUTION_CURRENT_OVERLAP") == "1" && os.Getenv("EXECUTION_CURRENT_RECOVERY") == "1" {
				expectedModel = 14
				expectedAllowed = 7
			}
			if os.Getenv("EXECUTION_CURRENT_TOOL_DENY") == "1" {
				expectedAllowed = 0
			}
			if os.Getenv("EXECUTION_CURRENT_MODEL_DENY") == "1" {
				expectedModel = 0
				expectedAllowed = 0
			}
			if counts["model"] != expectedModel || counts["allow"] != expectedAllowed || counts["deny"] != 0 {
				receiverDone <- fmt.Errorf("wrong real receiver counts %v", counts)
				return
			}
			receiverDone <- nil
		}()
	}
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
				_, err := client.Run(ctx, &ateletpb.RunRequest{Atespace: "native", ActorName: "tools", ActorUid: id, SandboxAssets: &ateletpb.SandboxAssets{SandboxClass: "microvm", Assets: map[string]*ateletpb.ArchAssets{"amd64": {Files: info.Assets}}}, MemoryBytes: 1024 * 1024 * 1024, CpuMilli: 1000, Spec: spec})
				return err
			}
			terminate = func(clean context.Context) error {
				_, err := client.Terminate(clean, &ateletpb.TerminateRequest{Atespace: "native", ActorName: "tools", ActorUid: id, Spec: spec})
				return err
			}
		}

	} else {
		req := &ateompb.RunWorkloadRequest{Atespace: "native", ActorName: "tools", ActorUid: id, ActorDirs: dirs, RuntimeAssetPaths: assets, MemoryBytes: 1024 * 1024 * 1024, CpuMilli: 1000, Spec: &ateompb.WorkloadSpec{ExecutionRequirement: raw, Containers: []*ateompb.Container{{Name: "probe"}}}}
		run = func() error { _, err := s.RunWorkload(ctx, req); return err }
		terminate = func(clean context.Context) error {
			_, err := s.TerminateWorkload(clean, &ateompb.TerminateWorkloadRequest{ActorUid: id, ActorDirs: dirs})
			return err
		}
	}
	if os.Getenv("EXECUTION_NATIVE_KAIMAHI") == "1" || os.Getenv("EXECUTION_NATIVE_KAGENT") == "1" {
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
	if os.Getenv("EXECUTION_NATIVE_KAIMAHI") != "1" && os.Getenv("EXECUTION_NATIVE_KAGENT") != "1" {

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
	if os.Getenv("EXECUTION_NATIVE_KAGENT") == "1" {
		if os.Getenv("EXECUTION_NATIVE_KAGENT_A2A") == "1" {
			cmd = exec.CommandContext(ctx, os.Getenv("EXECUTION_KAGENT_NATIVE_CLIENT"), "-test.run=^TestPublicKaimahiNativeA2A$", "-test.v", "-test.timeout=115s")
		} else {
			cmd = exec.CommandContext(ctx, os.Getenv("EXECUTION_NATIVE_KAGENT_BINARY"), "-test.run=^TestPublicSessionNativeCompute$", "-test.v", "-test.timeout=120s")
		}
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
		cmd.Env = append(os.Environ(), "SESSIONS_NATIVE_ROUTER="+string(address), "SESSIONS_NATIVE_ACTOR_UID="+id, "EXECUTION_PUBLIC_NATIVE_ROOT="+root, "EXECUTION_KAGENT_NATIVE_ROOT="+root, "EXECUTION_NATIVE_COMPUTE_SOURCE="+filepath.Join(os.Getenv("EXECUTION_TASK_ROOT"), "sources/substrate-sessions/cmd/ateom-microvm/native_sessions_tools_linux_test.go"))
	} else {
		cmd.Env = append(os.Environ(), "SESSIONS_NATIVE_PROXY="+filepath.Join(root, "bridge.sock"))
		bridge := newNativeHarnessBridge(t, ctx, filepath.Join(root, "bridge.sock"), dialer)
		defer bridge()
	}

	if os.Getenv("EXECUTION_CURRENT_GOLDEN") == "1" {
		cmd = exec.CommandContext(ctx, os.Getenv("EXECUTION_CURRENT_RECONCILER_BINARY"), "-test.v", "-test.run=^TestCurrentKaimahiCodexRealAdmission$", "-test.timeout=110s")
		cmd.Dir = filepath.Join(os.Getenv("EXECUTION_TASK_ROOT"), "sources/kagent/go/core/internal/controller")
		cmd.Env = append(os.Environ(), "KMX_TEMPLATE_CONTROL_ROOT="+root, "KMX_CODEX_RENDER_CAPTURE="+os.Getenv("EXECUTION_CURRENT_RENDER"), "KUBEBUILDER_ASSETS=/tmp/suite-policy-implementation/envtest/controller-tools/envtest")
	}
	output, err := cmd.CombinedOutput()
	if writeErr := os.WriteFile(filepath.Join(root, "sessions-native-client.log"), output, 0600); writeErr != nil {
		t.Fatal(writeErr)
	}
	marker := "NATIVE_SESSIONS_TOOL_PASS"
	if os.Getenv("EXECUTION_NATIVE_KAGENT") == "1" {
		marker = "PUBLIC_KAGENT_SESSION_NATIVE_COMPUTE_PASS"
		if os.Getenv("EXECUTION_NATIVE_KAGENT_A2A") == "1" {
			marker = "PUBLIC_KAIMAHI_KAGENT_A2A_NATIVE_PASS"
		}
	}
	if os.Getenv("EXECUTION_NATIVE_KAIMAHI") == "1" {
		marker = "PUBLIC_KAIMAHI_REAL_NATIVE_TOOLCHAT_REPLAY_PASS"
		if scenario := os.Getenv("EXECUTION_PUBLIC_NATIVE_SCENARIO"); scenario == "deny" || scenario == "empty" {
			marker = "PUBLIC_KAIMAHI_REAL_NATIVE_" + strings.ToUpper(scenario) + "_REFUSAL_NO_RECEIPT_PASS"
		}
	}
	if os.Getenv("EXECUTION_CURRENT_GOLDEN") == "1" {
		marker = "CURRENT_REAL_NATIVE_GOLDEN_PREPARATION_READY_PASS"
	}
	if err != nil || !strings.Contains(string(output), marker) {
		select {
		case receiverErr := <-receiverDone:
			t.Logf("receiver failed: %v", receiverErr)
		default:
			s.actorsMu.RLock()
			for uid := range s.actors {
				for _, file := range []string{"console.log", "serial.log"} {
					if data, e := os.ReadFile(filepath.Join("/run/vc/vm", uid, file)); e == nil {
						_ = os.WriteFile(filepath.Join(root, uid+"-"+file), data, 0600)
					}
				}
				t.Logf("receiver current actor=%s ns=%s", uid, nodepath.ActorNetNSPath(uid))
			}
			s.actorsMu.RUnlock()
		}
		t.Fatalf("Sessions native exchange %v %s", err, output)
	}
	if os.Getenv("EXECUTION_CURRENT_GOLDEN") == "1" {
		t.Log("CURRENT_REAL_NATIVE_GOLDEN_PREPARATION_READY_PASS")
		if os.Getenv("EXECUTION_CURRENT_PUBLIC") == "1" {
			receiverCancel()
			if err := <-receiverDone; err != nil {
				t.Fatal(err)
			}
		}
		return
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
