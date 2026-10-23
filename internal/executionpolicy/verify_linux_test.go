//go:build linux

package executionpolicy

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestVerifyFailsClosedWithoutMutatingDurableOwner(t *testing.T) {
	for _, scenario := range []string{"absent", "activating", "retiring", "different", "missing-handles"} {
		t.Run(scenario, func(t *testing.T) {
			c := &Client{Config: Config{StateRoot: t.TempDir()}}
			raw := json.RawMessage(`{"opaque":true}`)
			if scenario != "absent" {
				r := &Record{Operation: "one", Requirement: raw, Target: map[string]any{"generation": 1}, Phase: "active", CgroupPath: "/does-not-exist", NetNSPath: "/does-not-exist"}
				if scenario == "activating" || scenario == "retiring" {
					r.Phase = scenario
				}
				if err := c.save("actor", r); err != nil {
					t.Fatal(err)
				}
			}
			before, beforeErr := os.ReadFile(c.journal("actor"))
			input := raw
			if scenario == "different" {
				input = json.RawMessage(`{"opaque":false}`)
			}
			if err := c.Verify(context.Background(), "actor", input); err == nil {
				t.Fatal("unverified target admitted")
			}
			after, afterErr := os.ReadFile(c.journal("actor"))
			if !reflect.DeepEqual(before, after) || (beforeErr == nil) != (afterErr == nil) {
				t.Fatal("read-only verify altered ownership")
			}
		})
	}
}
