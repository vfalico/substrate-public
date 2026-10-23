//go:build linux

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/agent-substrate/substrate/internal/actorlog"
	"github.com/agent-substrate/substrate/internal/ateomnet"
	"github.com/agent-substrate/substrate/internal/ateomnet/dns"
	"github.com/agent-substrate/substrate/internal/ateomtunnel"
	"github.com/agent-substrate/substrate/internal/nodepath"
	"github.com/agent-substrate/substrate/internal/proto/ateompb"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This is an owning-compute qualification, NOT public Kaimahi/runtime acceptance.
// No lifecycle hook is mocked. The normal RunWorkload path starts CH, virtiofsd,
// kata-agent and the static task-owned guest packet probe.
func TestNativeMicroVMExecutionBoundary(t *testing.T) {
	root := os.Getenv("EXECUTION_MICROVM_ROOT")
	if root == "" {
		t.Skip("explicit native microVM qualification required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("native root setup required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Second)
	defer cancel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "task-owned-native"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
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
	tunnel, err := ateomtunnel.Start(ctx, ateomtunnel.Config{ListenAddress: "127.0.0.1:0", ConnectListenAddress: "127.0.0.1:0", CredentialBundle: bundle, TrustBundle: trust, ClientIdentity: "spiffe://task.local/native", EgressListenAddress: "127.0.0.1:29444"}, ateomnet.ActorHTTPUpstream)
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
	old := nodepath.StaticFilesDir
	nodepath.StaticFilesDir = filepath.Join(root, "assets")
	defer func() { nodepath.StaticFilesDir = old }()
	assets := map[string]string{}
	for name, src := range map[string]string{assetKernel: "/opt/kata/share/kata-containers/vmlinux.container", assetImage: "/opt/kata/share/kata-containers/kata-containers.img", assetVirtiofsd: "/opt/kata/libexec/virtiofsd"} {
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
	for _, mode := range []string{"control", "governed", "empty", "bad-digest"} {
		governed := mode != "control"
		var requirement []byte
		if mode == "governed" {
			requirement = raw
		}
		if mode == "empty" {
			var err error
			requirement, err = os.ReadFile(os.Getenv("EXECUTION_MICROVM_EMPTY_REQUIREMENT"))
			if err != nil {
				t.Fatal(err)
			}
		}
		if mode == "bad-digest" {
			var envelope map[string]json.RawMessage
			if err := json.Unmarshal(raw, &envelope); err != nil {
				t.Fatal(err)
			}
			envelope["digest"] = json.RawMessage(`"sha256:0000000000000000000000000000000000000000000000000000000000000000"`)
			var err error
			requirement, err = json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
		}
		id := fmt.Sprintf("poc-native-%d-%s", os.Getpid(), mode)
		dirs := &ateompb.ActorDirs{RootDir: filepath.Join(root, mode), OciBundleDir: filepath.Join(root, mode, "oci"), CheckpointDir: filepath.Join(root, mode, "checkpoint"), RestoreDir: filepath.Join(root, mode, "restore"), DurableDirVolumeMountsDir: filepath.Join(root, mode, "durable"), SystemInfoVolumeRootsDir: filepath.Join(root, mode, "sysinfo"), VolumesDir: filepath.Join(root, mode, "volumes")}
		ctrBundle := filepath.Join(dirs.OciBundleDir, "probe")
		rootfs := filepath.Join(ctrBundle, "rootfs")
		for _, d := range []string{rootfs, filepath.Join(rootfs, "etc"), dirs.CheckpointDir, dirs.RestoreDir, dirs.DurableDirVolumeMountsDir, dirs.SystemInfoVolumeRootsDir, dirs.VolumesDir} {
			if err := os.MkdirAll(d, 0755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Link(filepath.Join(root, "guest-probe"), filepath.Join(rootfs, "probe")); err != nil {
			t.Fatal(err)
		}
		spec := specs.Spec{Version: "1.2.0", Hostname: "native-probe", Root: &specs.Root{Path: "rootfs"}, Process: &specs.Process{Capabilities: &specs.LinuxCapabilities{Bounding: []string{"CAP_NET_ADMIN"}, Effective: []string{"CAP_NET_ADMIN"}, Permitted: []string{"CAP_NET_ADMIN"}}, Args: []string{"/probe"}, Cwd: "/", Env: []string{"PATH=/"}, User: specs.User{UID: 0, GID: 0}}, Linux: &specs.Linux{Namespaces: []specs.LinuxNamespace{{Type: specs.PIDNamespace}, {Type: specs.MountNamespace}, {Type: specs.UTSNamespace}, {Type: specs.IPCNamespace}, {Type: specs.NetworkNamespace}}}}
		sr, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		mustWrite(filepath.Join(ctrBundle, "config.json"), sr)
		receiverDone := make(chan error, 1)
		go func() {
			ns := nodepath.ActorNetNSPath(id)
			deadline := time.Now().Add(60 * time.Second)
			for {
				if _, err := os.Stat(ns); err == nil {
					break
				}
				if time.Now().After(deadline) {
					receiverDone <- fmt.Errorf("namespace not ready")
					return
				}
				select {
				case <-ctx.Done():
					receiverDone <- ctx.Err()
					return
				case <-time.After(50 * time.Millisecond):
				}
			}
			script := `import socket,select,time,json,subprocess
# Readiness includes all live endpoints and explicit IPv6 neighbour reachability.
subprocess.run(['ip','addr','replace','169.254.17.0/32','dev','tap0_kata'],check=True)
subprocess.run(['ip','-6','addr','replace','fd80:807::1/64','dev','tap0_kata','nodad'],check=True)
ls=[]
for family,kind,address,port in [(socket.AF_INET,socket.SOCK_STREAM,'169.254.17.1',28292),(socket.AF_INET,socket.SOCK_STREAM,'169.254.17.1',28293),(socket.AF_INET,socket.SOCK_STREAM,'169.254.17.0',28292),(socket.AF_INET,socket.SOCK_DGRAM,'169.254.17.1',28294),(socket.AF_INET6,socket.SOCK_STREAM,'fd80:807::1',28295),(socket.AF_INET6,socket.SOCK_DGRAM,'fd80:807::1',28296)]:
 s=socket.socket(family,kind);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((address,port))
 if kind==socket.SOCK_STREAM:s.listen(4)
 ls.append(s)
print('READY',flush=True);result=[];deadline=time.monotonic()+100
while time.monotonic()<deadline and not __import__('os').path.exists(__import__('sys').argv[1]):
 ready,_,_=select.select(ls,[],[],.1)
 for s in ready:
  if s.type==socket.SOCK_STREAM:
   c,_=s.accept();c.settimeout(2);data=c.recv(80);c.sendall(data);c.close()
  else:
   data,peer=s.recvfrom(80);s.sendto(data,peer)
  result.append([s.getsockname()[1],data.decode()])
print(json.dumps(result),flush=True)`
			cmd := exec.CommandContext(ctx, "/usr/sbin/ip", "netns", "exec", filepath.Base(ns), "/usr/bin/python3", "-c", script, filepath.Join(root, mode+"-receiver-stop"))
			output, err := cmd.CombinedOutput()
			if err != nil {
				receiverDone <- fmt.Errorf("receiver: %w %s", err, output)
				return
			}
			if e := os.WriteFile(filepath.Join(root, mode+"-receiver.log"), output, 0600); e != nil {
				receiverDone <- e
				return
			}
			text := strings.TrimSpace(strings.TrimPrefix(string(output), "READY\n"))
			var arrivals [][]any
			if e := json.Unmarshal([]byte(text), &arrivals); e != nil {
				receiverDone <- e
				return
			}
			expected := 6
			if governed {
				expected = 1
			}
			if mode == "empty" || mode == "bad-digest" {
				expected = 0
			}
			if len(arrivals) != expected {
				receiverDone <- fmt.Errorf("%s receiver arrivals %s", mode, output)
				return
			}
			seen := map[int]bool{}
			for _, a := range arrivals {
				seen[int(a[0].(float64))] = true
			}
			if (mode != "empty" && mode != "bad-digest" && !seen[28292]) || (!governed && !seen[28293]) || governed && seen[28293] || mode == "empty" && seen[28292] {
				receiverDone <- fmt.Errorf("wrong ports %v", seen)
				return
			}
			receiverDone <- nil
		}()
		req := &ateompb.RunWorkloadRequest{Atespace: "native", ActorName: mode, ActorUid: id, ActorDirs: dirs, RuntimeAssetPaths: assets, MemoryBytes: 1024 * 1024 * 1024, CpuMilli: 1000, Spec: &ateompb.WorkloadSpec{ExecutionRequirement: requirement, Containers: []*ateompb.Container{{Name: "probe"}}}}
		beforeDNS, err := os.ReadFile(os.Getenv("EXECUTION_MICROVM_DNS_LOG"))
		if err != nil {
			t.Fatal(err)
		}
		_, runErr := s.RunWorkload(ctx, req)
		if mode == "bad-digest" {
			if err := os.WriteFile(filepath.Join(root, mode+"-receiver-stop"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			receiveErr := <-receiverDone
			cleanupCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			_, cleanErr := s.TerminateWorkload(cleanupCtx, &ateompb.TerminateWorkloadRequest{Atespace: "native", ActorName: mode, ActorUid: id, ActorDirs: dirs})
			stop()
			if runErr == nil {
				t.Fatal("invalid digest released workload")
			}
			if receiveErr != nil || cleanErr != nil {
				t.Fatal("negative control receiver/cleanup", receiveErr, cleanErr)
			}
			output, err := os.ReadFile(filepath.Join(root, "guest-output.log"))
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(string(output), "\n") {
				var logged struct {
					Labels  map[string]string `json:"labels"`
					Message string            `json:"message"`
				}
				if json.Unmarshal([]byte(line), &logged) == nil && logged.Labels["ate.actor.uid"] == id && strings.Contains(logged.Message, "MICROVM_GUEST_RESULT") {
					t.Fatal("refused guest executed", line)
				}
			}
			afterDNS, err := os.ReadFile(os.Getenv("EXECUTION_MICROVM_DNS_LOG"))
			if err != nil {
				t.Fatal(err)
			}
			if len(afterDNS) < len(beforeDNS) || strings.Count(string(afterDNS[len(beforeDNS):]), `"probe": true`) != 0 {
				t.Fatal("refused guest reached DNS upstream")
			}
			t.Log("REAL_MICROVM_PRE_RELEASE_REFUSAL_PASS", mode, runErr)
			continue
		}

		cleanupCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		if runErr != nil {
			_, cleanErr := s.TerminateWorkload(cleanupCtx, &ateompb.TerminateWorkloadRequest{Atespace: "native", ActorName: mode, ActorUid: id, ActorDirs: dirs})
			stop()
			t.Fatalf("RunWorkload %s: %v; cleanup: %v", mode, runErr, cleanErr)
		}
		// Wait for this exact guest incarnation, not a fixed pre-boot sleep.
		guestDeadline := time.Now().Add(45 * time.Second)
		for {
			output, err := os.ReadFile(filepath.Join(root, "guest-output.log"))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, line := range strings.Split(string(output), "\n") {
				var logged struct {
					Labels  map[string]string `json:"labels"`
					Message string            `json:"message"`
				}
				if json.Unmarshal([]byte(line), &logged) == nil && logged.Labels["ate.actor.uid"] == id && strings.HasPrefix(logged.Message, "MICROVM_GUEST_RESULT ") {
					found = true
					break
				}
			}
			if found {
				break
			}
			if time.Now().After(guestDeadline) {
				t.Fatal("exact guest result deadline", id)
			}
			time.Sleep(50 * time.Millisecond)
		}
		if err := os.WriteFile(filepath.Join(root, mode+"-receiver-stop"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		receiveErr := <-receiverDone
		if mode == "governed" {
			if err := os.WriteFile(filepath.Join(root, "restart-request"), []byte("restart tracked enforcer"), 0600); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(12 * time.Second)
			for {
				_, err := os.Stat(filepath.Join(root, "restart-ready"))
				if err == nil {
					break
				}
				if !os.IsNotExist(err) || time.Now().After(deadline) {
					t.Fatal("real enforcer restart failed", err)
				}
				time.Sleep(50 * time.Millisecond)
			}
			t.Log("REAL_ENFORCER_RESTART_BEFORE_TERMINATION")
			// Actual live journal must defeat an omitted policy on both reuse
			// RPCs, including after an independent enforcer process restart.
			_, checkpointErr := s.CheckpointWorkload(ctx, &ateompb.CheckpointWorkloadRequest{ActorUid: id, ActorDirs: dirs})
			if checkpointErr == nil || !strings.Contains(checkpointErr.Error(), "governed reuse") {
				t.Fatal("governed checkpoint omission bypassed retained authority", checkpointErr)
			}
			_, restoreErr := s.RestoreWorkload(ctx, &ateompb.RestoreWorkloadRequest{ActorUid: id, ActorDirs: dirs})
			if restoreErr == nil || !strings.Contains(restoreErr.Error(), "governed reuse") {
				t.Fatal("governed restore omission bypassed retained authority", restoreErr)
			}
			entries, err := os.ReadDir(dirs.CheckpointDir)
			if err != nil || len(entries) != 0 {
				t.Fatal("refused checkpoint wrote artifacts", entries, err)
			}
			omittedRun := *req
			omittedRun.Spec = &ateompb.WorkloadSpec{Containers: req.Spec.Containers}
			_, runRetryErr := s.RunWorkload(ctx, &omittedRun)
			if runRetryErr == nil || !strings.Contains(runRetryErr.Error(), "governed reuse") {
				t.Fatal("cold-run retry omitted retained authority", runRetryErr)
			}
			_, exactRetryErr := s.RunWorkload(ctx, req)
			if exactRetryErr == nil || !strings.Contains(exactRetryErr.Error(), "governed reuse") {
				t.Fatal("cold-run retry reused retained governed incarnation", exactRetryErr)
			}
			t.Log("REAL_RETAINED_AUTHORITY_REFUSES_OMITTED_CHECKPOINT_RESTORE_AND_COLD_RUN")

		}
		_, cleanErr := s.TerminateWorkload(cleanupCtx, &ateompb.TerminateWorkloadRequest{Atespace: "native", ActorName: mode, ActorUid: id, ActorDirs: dirs})
		stop()
		if cleanErr != nil {
			t.Fatal("exact normal teardown", cleanErr)
		}
		if receiveErr != nil {
			t.Fatal(receiveErr)
		}
		output, err := os.ReadFile(filepath.Join(root, "guest-output.log"))
		if err != nil || !strings.Contains(string(output), "MICROVM_GUEST_RESULT") {
			t.Fatal("guest result missing", err)
		}
		// Match this incarnation's actual streamed guest result; a prior run's
		// line cannot satisfy a later mode. UDP send success is NOT receipt.
		found := false
		for _, line := range strings.Split(string(output), "\n") {
			var logged struct {
				Labels  map[string]string `json:"labels"`
				Message string            `json:"message"`
			}
			if json.Unmarshal([]byte(line), &logged) != nil || logged.Labels["ate.actor.uid"] != id || !strings.HasPrefix(logged.Message, "MICROVM_GUEST_RESULT ") {
				continue
			}
			found = true
			var attempts map[string]string
			if err := json.Unmarshal([]byte(strings.TrimPrefix(logged.Message, "MICROVM_GUEST_RESULT ")), &attempts); err != nil {
				t.Fatal(err)
			}
			for _, endpoint := range []string{"tcp4/169.254.17.1:28292", "tcp4/169.254.17.1:28293", "tcp4/169.254.17.0:28292", "tcp4/169.254.17.1:53", "udp4/169.254.17.1:53", "udp4/169.254.17.1:28294", "tcp6/[fd80:807::1]:28295", "udp6/[fd80:807::1]:28296"} {
				value, ok := attempts[endpoint]
				if !ok {
					t.Fatal("guest omitted endpoint", endpoint)
				}
				allowed := mode == "control" || mode == "governed" && endpoint == "tcp4/169.254.17.1:28292"
				if (value == "echo-confirmed") != allowed {
					t.Fatalf("guest echo/errors don't match %s %s: %v", mode, endpoint, attempts)
				}
			}
		}
		if !found {
			t.Fatal("current guest result absent", id)
		}
		afterDNS, err := os.ReadFile(os.Getenv("EXECUTION_MICROVM_DNS_LOG"))
		if err != nil {
			t.Fatal(err)
		}
		delta := string(afterDNS[len(beforeDNS):])
		expectedDNS := 0
		if mode == "control" {
			expectedDNS = 2
		}
		if strings.Count(delta, `"probe": true`) != expectedDNS {
			t.Fatalf("independent DNS upstream mismatch %s: %s", mode, delta)
		}
		if err := os.WriteFile(filepath.Join(root, mode+"-dns-upstream.log"), []byte(delta), 0600); err != nil {
			t.Fatal(err)
		}
		t.Log("REAL_MICROVM_MODE_PASS", mode)
	}

}
