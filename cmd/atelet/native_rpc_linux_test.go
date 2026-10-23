//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/agent-substrate/substrate/cmd/atelet/internal/sparsefile"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/nodepath"
	"github.com/agent-substrate/substrate/internal/proto/ateletpb"
	"google.golang.org/grpc"
)

// TestNativeAteletRPC is an opt-in process harness, not a fake compute service.
// It serves the ordinary image-cache/OCI/Run/Terminate implementation over RPC
// and dials the actual microVM service supplied by the parent qualification.
func TestNativeAteletRPC(t *testing.T) {
	root := os.Getenv("EXECUTION_ATELET_NATIVE_ROOT")
	if root == "" {
		t.Skip("explicit task-owned native resources required")
	}
	nodepath.ActorsDir = filepath.Join(root, "actors")
	nodepath.StaticFilesDir = filepath.Join(root, "assets")
	if err := os.MkdirAll(nodepath.StaticFilesDir, 0700); err != nil {
		t.Fatal(err)
	}
	assets := map[string]*ateletpb.AssetFile{}
	for name, src := range map[string]string{"kata-kernel": "/opt/kata/share/kata-containers/vmlinux.container", "kata-image": "/opt/kata/share/kata-containers/kata-containers.img", "virtiofsd": "/opt/kata/libexec/virtiofsd"} {
		if override := os.Getenv("EXECUTION_NATIVE_ASSET_" + name); override != "" {
			src = override
		}
		source, err := os.Open(src)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.New()
		if _, err := io.Copy(digest, source); err != nil {
			source.Close()
			t.Fatal(err)
		}
		if err := source.Close(); err != nil {
			t.Fatal(err)
		}
		hash := hex.EncodeToString(digest.Sum(nil))
		dest := filepath.Join(nodepath.StaticFilesDir, "runsc-"+hash)
		if err := stageNativeAsset(src, dest, hash); err != nil {
			t.Fatal(err)
		}
		assets[name] = &ateletpb.AssetFile{Url: "file://" + src, Sha256: hash}
	}
	binary, err := os.ReadFile(filepath.Join(root, "guest-probe"))
	if err != nil {
		t.Fatal(err)
	}
	host := imageVolumeTestRegistry(t)
	image := host + "/native-toolchat:v1"
	pushTestImage(t, image, singleFileLayer(t, "probe", string(binary)))
	ref, err := name.ParseReference(image)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := remote.Get(ref)
	if err != nil {
		t.Fatal(err)
	}
	image = host + "/native-toolchat@" + descriptor.Digest.String()
	store := newImageVolumeStore(t)
	s := NewService(t.Context(), newAteomDialer(8), nil, nil, nil, "", store, nil, nil, nil, newSystemInfoVolumeRefresher(nil, nil))
	old := ateomSocketPath
	ateomSocketPath = func(string) string { return filepath.Join(root, "ateom-rpc.sock") }
	defer func() { ateomSocketPath = old }()
	listener, err := net.Listen("unix", filepath.Join(root, "atelet-rpc.sock"))
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	ateletpb.RegisterAteomHerderServer(server, s)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() { server.Stop(); <-done }()
	data, err := json.Marshal(struct {
		Image  string                         `json:"image"`
		Assets map[string]*ateletpb.AssetFile `json:"assets"`
	}{image, assets})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "atelet-ready.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Second)
	defer cancel()
	for {
		if _, err = os.Stat(filepath.Join(root, "atelet-stop")); err == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// stageNativeAsset handles only immutable TEST assets in this trial's state root.
// No aliases or existing cache entries are overwritten. The ordinary sparse
// file seam preserves holes; content is independently verified before success.
func stageNativeAsset(src, dest, expected string) (result error) {
	output, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, output.Close()) }()
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()
	if _, err = sparsefile.Copy(source, output); err != nil {
		return err
	}
	if err = output.Sync(); err != nil {
		return err
	}
	check, err := os.Open(dest)
	if err != nil {
		return err
	}
	digest := sha256.New()
	_, copyErr := io.Copy(digest, check)
	if err = errors.Join(copyErr, check.Close()); err != nil {
		return err
	}
	if hex.EncodeToString(digest.Sum(nil)) != expected {
		return fmt.Errorf("native asset hash changed during staging")
	}
	return nil
}
