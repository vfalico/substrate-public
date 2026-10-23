//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/agent-substrate/substrate/internal/actorlock"
	"github.com/agent-substrate/substrate/internal/proto/ateompb"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRestoreCannotDropRetainedExecutionAuthority(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned normal runtime config required")
	}
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "config.json")
	raw, _ := json.Marshal(map[string]string{"Socket": filepath.Join(root, "unavailable.sock"), "StateRoot": state})
	if err := os.WriteFile(config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SUBSTRATE_EXECUTION_ENFORCER_CONFIG", config)
	sum := sha256.Sum256([]byte("retained-actor"))
	journal := filepath.Join(state, hex.EncodeToString(sum[:])+".json")
	if err := os.WriteFile(journal, []byte(`{"operation":"original","requirement":{"opaque":true},"target":{"generation":1},"Phase":"active"}`), 0600); err != nil {
		t.Fatal(err)
	}
	// Nil lifecycle/network fields panic if restore reaches any side effect.
	s := &AteomService{}
	_, err := s.RestoreWorkload(context.Background(), &ateompb.RestoreWorkloadRequest{ActorUid: "retained-actor"})
	if err == nil || !strings.Contains(err.Error(), "governed reuse") {
		t.Fatal("omitted requirement bypassed durable owner", err)
	}
	if _, err := os.Stat(journal); err != nil {
		t.Fatal("refusal removed cleanup ownership", err)
	}
}

func TestColdRunCannotDropRetainedExecutionAuthority(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted startup config requires root")
	}
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "config.json")
	raw, _ := json.Marshal(map[string]string{"Socket": filepath.Join(root, "unavailable.sock"), "StateRoot": state})
	if err := os.WriteFile(config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SUBSTRATE_EXECUTION_ENFORCER_CONFIG", config)
	id := "retained-cold-actor"
	sum := sha256.Sum256([]byte(id))
	record := filepath.Join(state, hex.EncodeToString(sum[:])+".json")
	if err := os.WriteFile(record, []byte(`{"Operation":"retained","Phase":"active"}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, requirement := range [][]byte{nil, []byte(`{"opaque":true}`)} {
		_, err := (&AteomService{}).RunWorkload(t.Context(), &ateompb.RunWorkloadRequest{ActorUid: id, Spec: &ateompb.WorkloadSpec{ExecutionRequirement: requirement}})
		if err == nil || !strings.Contains(err.Error(), "governed reuse") {
			t.Fatal("retained authority bypassed", err)
		}
	}
}

// Observe an actual waiter on the production Actor lock, then commit the
// competing governed journal. No launch/compute callback may be reached after
// admission. The initial preflight intentionally ran before the journal existed.
func TestRetainedAuthorityRecheckedAfterActorAdmission(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted startup config requires root")
	}
	for _, method := range []string{"run", "restore", "checkpoint"} {
		t.Run(method, func(t *testing.T) {
			root := t.TempDir()
			state := filepath.Join(root, "state")
			if err := os.Mkdir(state, 0700); err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(root, "config.json")
			raw, _ := json.Marshal(map[string]string{"Socket": filepath.Join(root, "unavailable.sock"), "StateRoot": state})
			if err := os.WriteFile(config, raw, 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("SUBSTRATE_EXECUTION_ENFORCER_CONFIG", config)
			id := "admission-" + method
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			locks := actorlock.New()
			if !locks.Lock(ctx, id) {
				t.Fatal("holder lock")
			}
			held := true
			defer func() {
				if held {
					locks.Unlock(id)
				}
			}()
			dirs := &ateompb.ActorDirs{RootDir: root, OciBundleDir: root, CheckpointDir: root, RestoreDir: root, DurableDirVolumeMountsDir: root, SystemInfoVolumeRootsDir: root, VolumesDir: root}
			service := &AteomService{locks: locks}
			done := make(chan error, 1)
			go func() {
				var err error
				switch method {
				case "run":
					_, err = service.RunWorkload(ctx, &ateompb.RunWorkloadRequest{ActorUid: id, ActorDirs: dirs})
				case "restore":
					_, err = service.RestoreWorkload(ctx, &ateompb.RestoreWorkloadRequest{ActorUid: id, ActorDirs: dirs})
				case "checkpoint":
					_, err = service.CheckpointWorkload(ctx, &ateompb.CheckpointWorkloadRequest{ActorUid: id, ActorDirs: dirs})
				}
				done <- err
			}()
			// A stack from the live test process proves preflight passed and this RPC
			// reached the held admission lock; sleeping alone would not establish order.
			deadline := time.Now().Add(2 * time.Second)
			for {
				buf := make([]byte, 1<<20)
				n := runtime.Stack(buf, true)
				if bytes.Contains(buf[:n], []byte("actorlock.(*CancelableMutex).LockContext")) {
					break
				}
				select {
				case err := <-done:
					t.Fatal("RPC did not wait for Actor admission", err)
				default:
				}
				if time.Now().After(deadline) {
					t.Fatal("Actor admission waiter not observed")
				}
				time.Sleep(time.Millisecond)
			}
			sum := sha256.Sum256([]byte(id))
			journal := filepath.Join(state, hex.EncodeToString(sum[:])+".json")
			if err := os.WriteFile(journal, []byte(`{"Operation":"competing-original","Phase":"active"}`), 0600); err != nil {
				t.Fatal(err)
			}
			locks.Unlock(id)
			held = false
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "governed reuse") {
					t.Fatal("admitted request ignored newly committed authority", err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}

// A restore carrying new mandatory authority must fail before hosting, network
// preparation, or reading snapshot paths when the worker lacks its enforcer.
func TestGovernedRestoreRequiresConfiguredBoundaryBeforeSideEffects(t *testing.T) {
	t.Setenv("SUBSTRATE_EXECUTION_ENFORCER_CONFIG", "")
	for _, scope := range []ateompb.SnapshotScope{ateompb.SnapshotScope_SNAPSHOT_SCOPE_FULL, ateompb.SnapshotScope_SNAPSHOT_SCOPE_DATA} {
		for _, delegated := range []bool{false, true} {
			s := &AteomService{actorCgroups: delegated}
			_, err := s.RestoreWorkload(t.Context(), &ateompb.RestoreWorkloadRequest{ActorUid: "new-governed-restore", Scope: scope, Spec: &ateompb.WorkloadSpec{ExecutionRequirement: []byte(`{"opaque":"mandatory"}`)}})
			if err == nil || (!strings.Contains(err.Error(), "exact delegated actor cgroup") && !strings.Contains(err.Error(), "no configured enforcer")) {
				t.Fatalf("scope=%v delegated=%v: %v", scope, delegated, err)
			}
		}
	}
}
