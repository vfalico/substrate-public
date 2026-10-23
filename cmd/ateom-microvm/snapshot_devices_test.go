//go:build linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSnapshotFilesystemStateMustBePortable(t *testing.T) {
	for _, tc := range []struct {
		name, id, backend string
		bases             []uint64
		want              bool
	}{
		{"complete", "_fs0", `[1,2,3]`, []uint64{4, 5}, true},
		{"absent", "_fs0", `null`, nil, false},
		{"empty", "_fs0", `[]`, []uint64{4}, false},
		{"queues absent", "_fs0", `[1]`, nil, false},
		{"wrong identity", "_fs1", `[1]`, []uint64{4}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			write := func(name string, data []byte) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			write("config.json", []byte(`{"fs":[{"id":"_fs0"}]}`))
			device, _ := json.Marshal(map[string]any{"backend_state": json.RawMessage(tc.backend), "vring_bases": tc.bases})
			snapshot, _ := json.Marshal(map[string]any{"snapshots": map[string]any{"device-manager": map[string]any{"snapshots": map[string]any{tc.id: map[string]any{"snapshot_data": map[string]string{"state": string(device)}}}}}})
			write("state.json", snapshot)
			err := requireSnapshotFilesystemState(dir)
			if (err == nil) != tc.want {
				t.Fatalf("want valid=%v, got %v", tc.want, err)
			}
		})
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"fs":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := requireSnapshotFilesystemState(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"fs":[{}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := requireSnapshotFilesystemState(dir); err == nil || !strings.Contains(err.Error(), "device identity") {
		t.Fatal(err)
	}
}
