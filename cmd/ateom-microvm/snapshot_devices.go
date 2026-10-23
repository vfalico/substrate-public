//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Full guest RAM contains live FUSE inode/handle identities. Reconstructing only
// the export path does not reconstruct the backend's identity table. Refuse an
// incomplete snapshot rather than advertise Ready or resume a latent SIGBUS.
// The format here is the generic CH snapshot contract, not an enforcer schema.
func requireSnapshotFilesystemState(dir string) error {
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return err
	}
	var cfg struct {
		Fs []struct {
			ID string `json:"id"`
		} `json:"fs"`
	}
	if err = json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("decode snapshot config: %w", err)
	}
	if len(cfg.Fs) == 0 {
		return nil
	}
	raw, err = os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		return err
	}
	type node struct {
		Snapshots map[string]json.RawMessage `json:"snapshots"`
		Data      *struct {
			State string `json:"state"`
		} `json:"snapshot_data"`
	}
	var find func(json.RawMessage, string) (*node, error)
	find = func(raw json.RawMessage, id string) (*node, error) {
		var n node
		if err := json.Unmarshal(raw, &n); err != nil {
			return nil, err
		}
		if child, ok := n.Snapshots[id]; ok {
			var found node
			if err := json.Unmarshal(child, &found); err != nil {
				return nil, err
			}
			return &found, nil
		}
		for _, child := range n.Snapshots {
			found, err := find(child, id)
			if err != nil {
				return nil, err
			}
			if found != nil {
				return found, nil
			}
		}
		return nil, nil
	}
	for _, fs := range cfg.Fs {
		if fs.ID == "" {
			return fmt.Errorf("snapshot filesystem has no exact device identity")
		}
		n, err := find(raw, fs.ID)
		if err != nil {
			return fmt.Errorf("decode snapshot filesystem %q: %w", fs.ID, err)
		}
		if n == nil || n.Data == nil {
			return fmt.Errorf("snapshot filesystem %q lacks backend device state", fs.ID)
		}
		var state struct {
			Backend json.RawMessage `json:"backend_state"`
			Bases   []uint64        `json:"vring_bases"`
		}
		if err := json.Unmarshal([]byte(n.Data.State), &state); err != nil {
			return fmt.Errorf("decode filesystem state %q: %w", fs.ID, err)
		}
		if len(state.Backend) == 0 || string(state.Backend) == "null" || string(state.Backend) == "[]" || string(state.Backend) == "\"\"" || len(state.Bases) == 0 {
			return fmt.Errorf("snapshot filesystem %q lacks backend device state and queue positions; VMM/backend state transfer required", fs.ID)
		}
	}
	return nil
}
