//go:build linux

package executionpolicy

import (
	"context"
	"encoding/json"
	"golang.org/x/sys/unix"
	"os"
	"testing"
)

// Explicit TEST peer; proves transport/config decoupling, not native enforcement.
func TestIndependentOpaquePeerFromNormalConfig(t *testing.T) {
	path := os.Getenv("EXECUTION_TEST_PEER_CONFIG")
	if path == "" {
		t.Skip("explicit independent TEST peer required")
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	req := json.RawMessage(`{"format":"test.opaque/v1","bytes":"bm90LWEtU3VpdGUtcG9saWN5AA==","capabilities":["test/opaque/v1"],"digest":"producer-owned-opaque-digest"}`)
	r := &Record{Operation: "independent-opaque", Requirement: req, Target: map[string]any{"generation": 1, "opaque": "not-Suite"}}
	ctx := t.Context()
	result, err := c.call(ctx, "assess", r, nil)
	if err != nil || string(result["supported"]) != "true" {
		t.Fatal(result, err)
	}
	fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	result, err = c.call(ctx, "activate", r, []int{fd})
	if err != nil {
		t.Fatal(err)
	}
	if err = bound(result, r, "active"); err != nil {
		t.Fatal(err)
	}
	result, err = c.call(ctx, "lookup", r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = bound(result, r, "active"); err != nil {
		t.Fatal(err)
	}
	r.Target["generation"] = 2
	if _, err = c.call(ctx, "lookup", r, nil); err == nil {
		t.Fatal("changed target admitted")
	}
	r.Target["generation"] = 1
	result, err = c.call(ctx, "retire", r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = bound(result, r, "retired"); err != nil {
		t.Fatal(err)
	}
	if _, err = c.call(ctx, "lookup", r, nil); err == nil {
		t.Fatal("retired binding admitted")
	}
	bad := *r
	bad.Requirement = json.RawMessage(`{"format":"unsupported/v1"}`)
	result, err = c.call(ctx, "assess", &bad, nil)
	if err != nil || string(result["supported"]) != "false" {
		t.Fatal(result, err)
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = c.call(cancelCtx, "activate", r, []int{fd}); err == nil {
		t.Fatal("cancelled activation accepted")
	}
	t.Log("INDEPENDENT_TEST_PEER_CONFIG_OPAQUE_TRANSPORT_PASS support activation lookup changed-target refusal retirement unsupported cancellation; no native gate claim")
}
