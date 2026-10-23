//go:build linux

package executionpolicy

import (
	"encoding/json"
	"os"
	"testing"
)

func TestCanonicalNeutralIdentity(t *testing.T) {
	raw := json.RawMessage(`{"z":9007199254740993,"a":"<literal>"}`)
	want := digest(map[string]any{"a": "<literal>", "z": json.Number("9007199254740993")})
	if got := digest(raw); got != want {
		t.Fatalf("raw object identity differs: %s != %s", got, want)
	}
	c := Client{Config: Config{StateRoot: t.TempDir()}}
	r := &Record{Operation: "original", Requirement: raw, Target: map[string]any{"inode": json.Number("9007199254740993")}, Phase: "activating"}
	if err := c.save("actor", r); err != nil {
		t.Fatal(err)
	}
	reread, err := c.Read("actor")
	if err != nil {
		t.Fatal(err)
	}
	if digest(r.Target) != digest(reread.Target) {
		t.Fatal("journal rounded kernel identity")
	}
	if err = c.save("actor", reread); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(c.journal("actor")); err != nil {
		t.Fatal(err)
	}
}
func TestExactReplyBoundToWholeAssociation(t *testing.T) {
	r := &Record{Operation: "one", Requirement: json.RawMessage(`{"bytes":"AA=="}`), Target: map[string]any{"generation": 1}}
	reply := map[string]json.RawMessage{}
	for k, v := range map[string]any{"active": true, "operation": r.Operation, "binding": digest(map[string]any{"requirement": r.Requirement, "target": r.Target}), "requirement": digest(r.Requirement), "target": digest(r.Target)} {
		reply[k], _ = json.Marshal(v)
	}
	if err := bound(reply, r, "active"); err != nil {
		t.Fatal(err)
	}
	r.Target["generation"] = 2
	if err := bound(reply, r, "active"); err == nil {
		t.Fatal("stale generation admitted")
	}
}

func TestCrashLeftTemporaryDoesNotWedgeDurableOwner(t *testing.T) {
	c := Client{Config: Config{StateRoot: t.TempDir()}}
	original := &Record{Operation: "original", Requirement: json.RawMessage(`{"opaque":true}`), Target: map[string]any{"inode": json.Number("9007199254740993")}, Phase: "activating"}
	if err := c.save("actor", original); err != nil {
		t.Fatal(err)
	}
	stale := c.journal("actor") + ".tmp"
	if err := os.WriteFile(stale, []byte("partial-crash-write"), 0600); err != nil {
		t.Fatal(err)
	}
	original.Phase = "retiring"
	if err := c.save("actor", original); err != nil {
		t.Fatal("crash leftover wedged monotonic cleanup", err)
	}
	got, err := c.Read("actor")
	if err != nil || got.Operation != "original" || got.Phase != "retiring" || digest(got.Target) != digest(original.Target) {
		t.Fatal(got, err)
	}
	if raw, err := os.ReadFile(stale); err != nil || string(raw) != "partial-crash-write" {
		t.Fatal("unowned leftover changed", err)
	}
}
