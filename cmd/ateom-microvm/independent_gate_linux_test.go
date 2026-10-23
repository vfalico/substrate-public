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
	"github.com/agent-substrate/substrate/cmd/ateom-microvm/internal/ch"
	"github.com/agent-substrate/substrate/cmd/ateom-microvm/internal/kata"
	"github.com/agent-substrate/substrate/internal/actorlog"
	"github.com/agent-substrate/substrate/internal/ateomnet"
	"github.com/agent-substrate/substrate/internal/ateomtunnel"
	"github.com/agent-substrate/substrate/internal/executionpolicy"
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

// Real RunWorkload gate using an independent TEST peer; no network enforcement claim.
func TestIndependentOpaquePeerNativeComputeGate(t *testing.T) {
	root := os.Getenv("EXECUTION_PEER_GATE_ROOT")
	if root == "" {
		t.Skip("explicit independent peer native compute setup required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root native setup required")
	}
	ctx, cancel := context.WithCancel(t.Context())
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
		// Explicit TEST-only image carries an independently implemented opaque
		// peer. Never replace installed assets or claim network enforcement.
		if name == assetImage && os.Getenv("EXECUTION_PEER_GUEST_IMAGE") != "" {
			src = os.Getenv("EXECUTION_PEER_GUEST_IMAGE")
		}
		if name == assetKernel && os.Getenv("EXECUTION_PEER_GUEST_KERNEL") != "" {
			src = os.Getenv("EXECUTION_PEER_GUEST_KERNEL")
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

	raw := []byte(`{"format":"test.opaque/v1","bytes":"bm90LWEtU3VpdGUtcG9saWN5AA==","capabilities":["test/opaque/v1"],"digest":"producer-owned-opaque-digest"}`)
	for _, mode := range []string{"supported", "refused", "refused-retire-once", "partial-create-retire-once", "policy-free-enforcer-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			ctx, caseCancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer caseCancel()
			requirement := append([]byte(nil), raw...)
			if mode == "refused" {
				requirement = []byte(`{"format":"test.opaque/v1","bytes":"bm90LWEtU3VpdGUtcG9saWN5AA==","capabilities":["test/opaque/v1","test/refuse-activation"],"digest":"producer-owned-opaque-digest"}`)
			}
			if mode == "refused-retire-once" || mode == "partial-create-retire-once" {
				requirement = []byte(`{"format":"test.opaque/v1","bytes":"bm90LWEtU3VpdGUtcG9saWN5AA==","capabilities":["test/opaque/v1","test/refuse-activation","test/retire-once"],"digest":"producer-owned-opaque-digest"}`)
			}
			if mode == "partial-create-retire-once" {
				requirement = []byte(`{"format":"test.opaque/v1","bytes":"bm90LWEtU3VpdGUtcG9saWN5AA==","capabilities":["test/opaque/v1","test/retire-once"],"digest":"producer-owned-opaque-digest"}`)
			}
			if mode == "policy-free-enforcer-unavailable" {
				requirement = nil
				// Normal protected config points at a port with no guest listener.
				// A policy-free target must not call the enforcer to run or stop.
				config, err := os.ReadFile(os.Getenv("SUBSTRATE_EXECUTION_ENFORCER_CONFIG"))
				if err != nil {
					t.Fatal(err)
				}
				var locator executionpolicy.Config
				if err := json.Unmarshal(config, &locator); err != nil {
					t.Fatal(err)
				}
				locator.GuestPort = 1031
				config, err = json.Marshal(locator)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(root, "policy-free-unavailable-config.json")
				mustWrite(path, config)
				t.Setenv("SUBSTRATE_EXECUTION_ENFORCER_CONFIG", path)
			}
			id := fmt.Sprintf("poc-peer-%d-%s", os.Getpid(), mode)
			dirs := &ateompb.ActorDirs{RootDir: filepath.Join(root, mode), OciBundleDir: filepath.Join(root, mode, "oci"), CheckpointDir: filepath.Join(root, mode, "checkpoint"), RestoreDir: filepath.Join(root, mode, "restore"), DurableDirVolumeMountsDir: filepath.Join(root, mode, "durable"), SystemInfoVolumeRootsDir: filepath.Join(root, mode, "sysinfo"), VolumesDir: filepath.Join(root, mode, "volumes")}
			bundle := filepath.Join(dirs.OciBundleDir, "probe")
			rootfs := filepath.Join(bundle, "rootfs")
			for _, dir := range []string{rootfs, filepath.Join(rootfs, "etc"), dirs.CheckpointDir, dirs.RestoreDir, dirs.DurableDirVolumeMountsDir, dirs.SystemInfoVolumeRootsDir, dirs.VolumesDir} {
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Link(filepath.Join(root, "entry-probe"), filepath.Join(rootfs, "probe")); err != nil {
				t.Fatal(err)
			}
			spec := specs.Spec{Version: "1.2.0", Root: &specs.Root{Path: "rootfs"}, Process: &specs.Process{Capabilities: &specs.LinuxCapabilities{}, Args: []string{"/probe"}, Cwd: "/", Env: []string{"PATH=/"}}, Linux: &specs.Linux{Namespaces: []specs.LinuxNamespace{{Type: specs.PIDNamespace}, {Type: specs.MountNamespace}, {Type: specs.UTSNamespace}, {Type: specs.IPCNamespace}, {Type: specs.NetworkNamespace}}}}
			sr, err := json.Marshal(spec)
			if err != nil {
				t.Fatal(err)
			}
			mustWrite(filepath.Join(bundle, "config.json"), sr)
			cleanup := func() {
				cleanCtx, stop := context.WithTimeout(context.Background(), 20*time.Second)
				defer stop()
				_, err := s.TerminateWorkload(cleanCtx, &ateompb.TerminateWorkloadRequest{Atespace: "native", ActorName: mode, ActorUid: id, ActorDirs: dirs})
				if err != nil {
					t.Error("exact cleanup", err)
				}
			}
			defer cleanup()
			req := &ateompb.RunWorkloadRequest{Atespace: "native", ActorName: mode, ActorUid: id, ActorDirs: dirs, RuntimeAssetPaths: assets, MemoryBytes: 512 * 1024 * 1024, CpuMilli: 1000, Spec: &ateompb.WorkloadSpec{ExecutionRequirement: requirement, Containers: []*ateompb.Container{{Name: "probe"}}}}
			if mode == "partial-create-retire-once" {
				// Actual Kata/runc Create succeeds for first container, then the
				// second's nonexistent cwd fails Create before any Start dispatch.
				// The peer's first retire refusal preserves exact owner for a
				// genuinely fresh-process cleanup using only the durable inventory.
				second := filepath.Join(dirs.OciBundleDir, "unprepared")
				if err := os.MkdirAll(filepath.Join(second, "rootfs"), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(filepath.Join(root, "entry-probe"), filepath.Join(second, "rootfs", "probe")); err != nil {
					t.Fatal(err)
				}
				broken := spec
				process := *spec.Process
				process.Cwd = "/definitely-absent-create-cwd"
				broken.Process = &process
				b, err := json.Marshal(broken)
				if err != nil {
					t.Fatal(err)
				}
				mustWrite(filepath.Join(second, "config.json"), b)
				req.Spec.Containers = append(req.Spec.Containers, &ateompb.Container{Name: "unprepared"})
			}
			_, runErr := s.RunWorkload(ctx, req)
			hasEntry := func() bool {
				output, err := os.ReadFile(filepath.Join(root, "guest-output.log"))
				if err != nil {
					t.Fatal(err)
				}
				for _, line := range strings.Split(string(output), "\n") {
					var logged struct {
						Labels  map[string]string `json:"labels"`
						Message string            `json:"message"`
					}
					if json.Unmarshal([]byte(line), &logged) == nil && logged.Labels["ate.actor.uid"] == id && strings.Contains(logged.Message, "INDEPENDENT_OPAQUE_GUEST_ENTRY") {
						return true
					}
				}
				return false
			}
			if mode == "partial-create-retire-once" {
				if runErr == nil {
					t.Fatal("invalid second Create unexpectedly succeeded")
				}

				client, err := s.executionClient()
				if err != nil {
					t.Fatal(err)
				}
				owner, err := client.GuestCleanupRecord(id)
				if err != nil || owner.Phase != "retiring" || len(owner.Containers) != 2 {
					t.Fatal("missing complete pre-Create cleanup inventory", owner, err)
				}
				if owner.Containers[0] != "probe" || owner.Containers[1] != "unprepared" {
					t.Fatal("intended inventory changed", owner.Containers)
				}
				if err := client.LookupGuest(ctx, id, requirement); err == nil {
					t.Fatal("failed preparation owner allowed dispatch")
				}

				t.Log("REAL_PARTIAL_CREATE_SECOND_CONTAINER_FAILED_PRESTART_DURABLE_OWNER")
			}
			if strings.HasPrefix(mode, "refused") || mode == "partial-create-retire-once" {
				if runErr == nil {
					t.Fatal("independent peer refusal released workload")
				}
				if hasEntry() {
					t.Fatal("entrypoint after refused gate")
				}
			} else {
				if runErr != nil {
					t.Fatal(runErr)
				}
				deadline := time.Now().Add(15 * time.Second)
				for !hasEntry() {
					if time.Now().After(deadline) {
						t.Fatal("released guest entrypoint absent")
					}
					time.Sleep(25 * time.Millisecond)
				}
				if err := s.lookupExecution(ctx, id); err != nil {
					t.Fatal("exact warm lookup", err)
				}
				if mode != "policy-free-enforcer-unavailable" {
					if err := s.refuseGovernedReuse(id); err == nil {
						t.Fatal("governed replacement accepted")
					}
				}
			}
			if mode == "refused-retire-once" || mode == "partial-create-retire-once" {
				// Real peer failed the first cleanup after activation refusal.
				// The exact trusted guest must stay alive, owned and un-dispatchable.
				h := s.lookupActor(id)
				if h == nil || !h.cleanupPending || s.runningVM(id) == nil {
					t.Fatal("failed retirement lost exact live bootstrap owner")
				}
				if err := s.refuseGovernedReuse(id); err == nil {
					t.Fatal("failed retirement owner reused")
				}
				if err := s.lookupExecution(ctx, id); err == nil {
					t.Fatal("failed retirement owner granted warm dispatch")
				}
				records, err := os.ReadDir(os.Getenv("EXECUTION_PEER_STATE_ROOT"))
				if err != nil || len(records) != 1 {
					t.Fatal("failed retirement lost original operation", records, err)
				}
			}
			if mode == "refused-retire-once" || mode == "partial-create-retire-once" {
				// A genuinely separate process has no actors/runningActor map.
				// Its only authority is the original durable cleanup record.
				payload, err := json.Marshal(dirs)
				if err != nil {
					t.Fatal(err)
				}
				command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestIndependentOpaqueGuestCleanupFreshProcess$", "-test.v", "-test.timeout=45s")
				command.Env = append(os.Environ(), "EXECUTION_FRESH_CLEANUP_ID="+id, "EXECUTION_FRESH_CLEANUP_DIRS="+string(payload))
				output, err := command.CombinedOutput()
				if writeErr := os.WriteFile(filepath.Join(root, "fresh-cleanup.log"), output, 0600); writeErr != nil {
					t.Fatal(writeErr)
				}
				if err != nil {
					t.Fatal("fresh cleanup process", err, string(output))
				}
				client, err := executionpolicy.Load(os.Getenv("SUBSTRATE_EXECUTION_ENFORCER_CONFIG"))
				if err != nil {
					t.Fatal(err)
				}
				record, err := client.GuestCleanupRecord(id)
				if err != nil || record.Phase != "retired" || !record.ContainersStopped {
					t.Fatal("fresh cleanup lost monotonic checkpoint", record, err)
				}
				if state, err := ch.NewClient(kata.CLHSocketPath(id)).State(ctx); err == nil && state == "Running" {
					t.Fatal("fresh cleanup left compute running")
				}
			}
			cleanup()
			records, err := os.ReadDir(os.Getenv("EXECUTION_PEER_STATE_ROOT"))
			if err != nil || len(records) != 0 {
				t.Fatal("journal residue", records, err)
			}
			t.Log("INDEPENDENT_OPAQUE_NATIVE_COMPUTE_GATE_PASS", mode, "normal RunWorkload gate and exact cleanup; NO kernel policy claim")
		})
	}
}

// This process cannot consult the producer's in-memory cleanup inventory.
func TestIndependentOpaqueGuestCleanupFreshProcess(t *testing.T) {
	id := os.Getenv("EXECUTION_FRESH_CLEANUP_ID")
	if id == "" {
		t.Skip("explicit native fault subprocess required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root task-owned native setup required")
	}
	var dirs ateompb.ActorDirs
	if err := json.Unmarshal([]byte(os.Getenv("EXECUTION_FRESH_CLEANUP_DIRS")), &dirs); err != nil {
		t.Fatal(err)
	}
	service := NewService("fresh-cleanup", "/opt/kata/bin/cloud-hypervisor", true, 0, 4, nil, nil)
	if service.lookupActor(id) != nil || service.runningVM(id) != nil {
		t.Fatal("not a fresh worker")
	}
	if err := service.refuseGovernedReuse(id); err == nil {
		t.Fatal("fresh worker lost durable refusal")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if err := service.stopActorVM(ctx, id, &dirs); err != nil {
		t.Fatal("fresh-process cleanup", err)
	}
	if err := service.refuseGovernedReuse(id); err == nil {
		t.Fatal("retired stop owner granted dispatch")
	}
	t.Log("FRESH_PROCESS_EXACT_GUEST_CLEANUP_PASS retired binding retained until final owner completion")
}
