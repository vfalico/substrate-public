//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	gcsstorage "cloud.google.com/go/storage"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/agent-substrate/substrate/cmd/atelet/internal/sparsefile"
	"github.com/agent-substrate/substrate/cmd/atelet/internal/trustbundle"
	"github.com/agent-substrate/substrate/pkg/objectstorage"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"google.golang.org/api/option"
	"io"
	certsv1 "k8s.io/api/certificates/v1"
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
	layer := singleFileLayer(t, "probe", string(binary))
	if os.Getenv("EXECUTION_NATIVE_KAGENT_A2A") == "1" {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for dest, source := range map[string]string{"probe": filepath.Join(root, "guest-probe"), "codex": os.Getenv("EXECUTION_KAGENT_CODEX"), "bin/busybox": "/bin/busybox"} {
			raw, e := os.ReadFile(source)
			if e != nil {
				t.Fatal(e)
			}
			if e = tw.WriteHeader(&tar.Header{Name: dest, Mode: 0755, Size: int64(len(raw))}); e != nil {
				t.Fatal(e)
			}
			if _, e = tw.Write(raw); e != nil {
				t.Fatal(e)
			}
		}

		if os.Getenv("EXECUTION_CURRENT_PUBLIC") == "1" {
			// Explicit task-local name fixture: no implicit DNS policy exception.
			hosts := []byte("127.0.0.1 localhost\n169.254.17.1 control.native.test model.native.test\n")
			if e := tw.WriteHeader(&tar.Header{Name: "etc/hosts", Mode: 0644, Size: int64(len(hosts))}); e != nil {
				t.Fatal(e)
			}
			if _, e := tw.Write(hosts); e != nil {
				t.Fatal(e)
			}
		}
		if e := tw.WriteHeader(&tar.Header{Name: "bin/sh", Typeflag: tar.TypeSymlink, Linkname: "busybox", Mode: 0755}); e != nil {
			t.Fatal(e)
		}
		if e := tw.Close(); e != nil {
			t.Fatal(e)
		}
		var e error
		layer, e = tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(buf.Bytes())), nil })
		if e != nil {
			t.Fatal(e)
		}
	}

	if os.Getenv("EXECUTION_CURRENT_GOLDEN") == "1" {
		img, e := mutate.AppendLayers(empty.Image, layer)
		if e != nil {
			t.Fatal(e)
		}
		cfg, e := img.ConfigFile()
		if e != nil {
			t.Fatal(e)
		}
		cfg.Config.Entrypoint = []string{"/probe"}
		cfg.Config.Env = []string{"PATH=/bin:/", "CODEX_UNSAFE_ALLOW_NO_SANDBOX=1", "RUST_LOG=warn"}
		img, e = mutate.ConfigFile(img, cfg)
		if e != nil {
			t.Fatal(e)
		}
		ref, e := name.ParseReference(image, name.Insecure)
		if e != nil {
			t.Fatal(e)
		}
		if e = remote.Write(ref, img); e != nil {
			t.Fatal(e)
		}
	} else {
		pushTestImage(t, image, layer)
	}
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

	var storage objectstorage.ObjectStorage
	refresher := newSystemInfoVolumeRefresher(nil, nil)
	if os.Getenv("EXECUTION_CURRENT_GOLDEN") == "1" {
		storage, err = objectstorage.NewGCSClient(t.Context(), option.WithoutAuthentication(), gcsstorage.WithJSONReads())
		if err != nil {
			t.Fatal(err)
		}
		cert, err := os.ReadFile(filepath.Join(root, "trust.pem"))
		if err != nil {
			t.Fatal(err)
		}
		bundles := trustbundle.NewSource(func(string) (*certsv1.ClusterTrustBundle, error) {
			return &certsv1.ClusterTrustBundle{Spec: certsv1.ClusterTrustBundleSpec{TrustBundle: string(cert)}}, nil
		}, cert)
		refresher = newSystemInfoVolumeRefresher(bundles, nil)
	}
	s := NewService(t.Context(), newAteomDialer(8), storage, storage, store, nil, nil, nil, refresher)

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
