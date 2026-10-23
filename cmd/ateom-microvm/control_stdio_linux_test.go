//go:build linux

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-substrate/substrate/internal/executionpolicy"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func stdioConfig(t *testing.T, name string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("ordinary trusted worker config requires root")
	}
	root := t.TempDir()
	config := filepath.Join(root, "config.json")
	raw, err := json.Marshal(executionpolicy.Config{Socket: filepath.Join(root, "peer.sock"), StateRoot: filepath.Join(root, "state"), GuestPort: 1030, ControlStdioContainer: name})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SUBSTRATE_EXECUTION_ENFORCER_CONFIG", config)
}
func TestRuntimeControlSelectorBeforeExecution(t *testing.T) {
	stdioConfig(t, "harness")
	for _, tc := range []struct {
		name       string
		containers []actorContainer
		want       string
	}{
		{"missing", []actorContainer{{name: "other"}}, "not prepared"},
		{"nil-process", []actorContainer{{name: "harness", spec: &specs.Spec{}}}, "invalid"},
		{"workload-selector", []actorContainer{{name: "harness", spec: &specs.Spec{Process: &specs.Process{Env: []string{"RUNTIME_CONTROL_STDIO=0"}}}}}, "workload supplied"},
		{"duplicate", []actorContainer{{name: "harness", spec: &specs.Spec{Process: &specs.Process{}}}, {name: "harness", spec: &specs.Spec{Process: &specs.Process{}}}}, "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := (&AteomService{}).prepareControlStdio(tc.containers, []byte(`{"opaque":true}`)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatal(err)
			}
		})
	}
	workload := &specs.Spec{Process: &specs.Process{Env: []string{"PATH=/"}}}
	name, err := (&AteomService{}).prepareControlStdio([]actorContainer{{name: "harness", spec: workload}}, []byte(`{"opaque":true}`))
	if err != nil || name != "harness" || workload.Process.Env[1] != "RUNTIME_CONTROL_STDIO=1" {
		t.Fatal(name, workload, err)
	}
	// Policy-free mode must not consult unavailable mandatory configuration or
	// mutate an existing workload's ordinary transport.
	t.Setenv("SUBSTRATE_EXECUTION_ENFORCER_CONFIG", "/absent")
	if name, err = (&AteomService{}).prepareControlStdio(nil, nil); err != nil || name != "" {
		t.Fatal(name, err)
	}
}
func TestRuntimeControlNoNetworkFallback(t *testing.T) {
	s := &AteomService{actors: map[string]*hostedActor{}}
	for _, target := range []struct{ network, address string }{{"udp", "169.254.17.2:80"}, {"tcp", "127.0.0.1:80"}, {"tcp", "169.254.17.1:80"}, {"tcp", "example.com:80"}, {"tcp", "169.254.17.2:0"}, {"tcp", "169.254.17.2:80"}} {
		if conn, err := s.dialControlStdio(context.Background(), "missing-incarnation", target.network, target.address); err == nil || conn != nil {
			t.Fatal("missing exact owner/invalid route fell back", target, err)
		}
	}
	s.closeControlStdio("missing-incarnation")
}
