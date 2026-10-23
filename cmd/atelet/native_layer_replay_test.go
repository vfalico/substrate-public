//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// Exercise the real fixture's layer-construction/upload branch in a subprocess.
// No VM, fake compute receipt or duplicated LayerFromOpener expression is used.
func TestNativeAteletLayerReplayNoAnonymousFile(t *testing.T) {
	root := t.TempDir()
	scratch := t.TempDir()
	for _, name := range []string{"kernel", "image", "virtiofsd", "guest-probe", "codex"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("fixture-"+name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-test.run=^TestNativeAteletRPC$", "-test.v", "-test.timeout=45s")
	cmd.Env = append(os.Environ(), "TMPDIR="+scratch, "EXECUTION_ATELET_NATIVE_ROOT="+root, "EXECUTION_NATIVE_KAGENT_A2A=1", "EXECUTION_CURRENT_PUBLIC=1", "EXECUTION_CURRENT_GOLDEN=0", "EXECUTION_KAGENT_CODEX="+filepath.Join(root, "codex"), "EXECUTION_NATIVE_ASSET_kata-kernel="+filepath.Join(root, "kernel"), "EXECUTION_NATIVE_ASSET_kata-image="+filepath.Join(root, "image"), "EXECUTION_NATIVE_ASSET_virtiofsd="+filepath.Join(root, "virtiofsd"))
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	finished := false
	defer func() {
		if !finished {
			_ = cmd.Process.Kill()
			<-done
		}
		t.Log(output.String())
	}()
	var ready struct {
		Image string `json:"image"`
	}
	until := time.Now().Add(20 * time.Second)
	for {
		raw, e := os.ReadFile(filepath.Join(root, "atelet-ready.json"))
		if e == nil {
			if e = json.Unmarshal(raw, &ready); e != nil {
				t.Fatal(e)
			}
			break
		}
		select {
		case e := <-done:
			finished = true
			t.Fatalf("fixture exited before upload: %v", e)
		default:
		}
		if time.Now().After(until) {
			t.Fatal("actual fixture upload readiness deadline")
		}
		time.Sleep(20 * time.Millisecond)
	}
	ref, err := name.ParseReference(ready.Image, name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	image, err := remote.Image(ref)
	if err != nil {
		t.Fatal(err)
	}
	layers, err := image.Layers()
	if err != nil || len(layers) != 1 {
		t.Fatalf("uploaded layers=%d err=%v", len(layers), err)
	}
	layer := layers[0]
	read := func() []byte {
		r, e := layer.Uncompressed()
		if e != nil {
			t.Fatal(e)
		}
		raw, e := io.ReadAll(r)
		if e != nil {
			t.Fatal(e)
		}
		if e = r.Close(); e != nil {
			t.Fatal(e)
		}
		return raw
	}
	raw := read()
	if !bytes.Equal(raw, read()) {
		t.Fatal("layer not replayable")
	}
	tr := tar.NewReader(bytes.NewReader(raw))
	found := map[string][]byte{}
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		body, e := io.ReadAll(tr)
		if e != nil {
			t.Fatal(e)
		}
		found[h.Name] = body
		if h.Name == "bin/sh" && (h.Typeflag != tar.TypeSymlink || h.Linkname != "busybox") {
			t.Fatal("shell link changed")
		}
	}
	for _, pair := range [][2]string{{"probe", "guest-probe"}, {"codex", "codex"}, {"bin/busybox", "/bin/busybox"}} {
		path := pair[1]
		if !filepath.IsAbs(path) {
			path = filepath.Join(root, path)
		}
		body, e := os.ReadFile(path)
		if e != nil || !bytes.Equal(body, found[pair[0]]) {
			t.Fatalf("uploaded content mismatch %s: %v", pair[0], e)
		}
	}
	if string(found["etc/hosts"]) != "127.0.0.1 localhost\n169.254.17.1 control.native.test model.native.test\n" {
		t.Fatal("hosts content changed")
	}
	// Compare uploaded compressed digest, uncompressed diffID and size to the
	// same actual TAR via an explicit named file (old reader's effective path).
	tarfile := filepath.Join(root, "reference.tar")
	if err = os.WriteFile(tarfile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	expected, err := tarball.LayerFromFile(tarfile)
	if err != nil {
		t.Fatal(err)
	}
	gotDigest, err := layer.Digest()
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := expected.Digest()
	if err != nil {
		t.Fatal(err)
	}
	gotDiff, err := layer.DiffID()
	if err != nil {
		t.Fatal(err)
	}
	wantDiff, err := expected.DiffID()
	if err != nil {
		t.Fatal(err)
	}
	gotSize, err := layer.Size()
	if err != nil {
		t.Fatal(err)
	}
	wantSize, err := expected.Size()
	if err != nil {
		t.Fatal(err)
	}
	if gotDigest != wantDigest || gotDiff != wantDiff || gotSize != wantSize {
		t.Fatalf("layer identity changed: %v/%v %v/%v %d/%d", gotDigest, wantDigest, gotDiff, wantDiff, gotSize, wantSize)
	}
	sum := sha256.Sum256(raw)
	if gotDiff.Hex != hex.EncodeToString(sum[:]) {
		t.Fatal("diffID is not actual TAR digest")
	}
	// The unmodified LayerFromReader leaves a numeric top-level tempfile here.
	entries, err := os.ReadDir(scratch)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			t.Fatalf("anonymous layer tempfile: %s", entry.Name())
		}
	}
	t.Logf("actual fixture upload usable: digest=%s diffID=%s size=%d; no anonymous layer tempfile", gotDigest, gotDiff, gotSize)
	if err = os.WriteFile(filepath.Join(root, "atelet-stop"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		finished = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("fixture stop deadline")
	}
}
