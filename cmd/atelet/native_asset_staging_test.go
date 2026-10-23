//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestNativeImmutableSparseAssetStaging(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "source")
	dst := filepath.Join(root, "dest")
	f, e := os.Create(src)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.WriteAt([]byte("head"), 0); e != nil {
		t.Fatal(e)
	}
	if _, e = f.WriteAt([]byte("tail"), 32<<20); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	in, e := os.Open(src)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.New()
	if _, e = io.Copy(h, in); e != nil {
		t.Fatal(e)
	}
	in.Close()
	digest := hex.EncodeToString(h.Sum(nil))
	if e = stageNativeAsset(src, dst, digest); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(dst)
	if e != nil {
		t.Fatal(e)
	}
	sourceInfo, _ := os.Stat(src)
	if info.Size() != sourceInfo.Size() {
		t.Fatal("logical size drift")
	}
	blocks := info.Sys().(*syscall.Stat_t).Blocks * 512
	if sourceInfo.Sys().(*syscall.Stat_t).Blocks*512 < sourceInfo.Size()/2 && blocks >= info.Size()/2 {
		t.Fatal("sparse source became dense", blocks, info.Size())
	}
	if e = stageNativeAsset(src, dst, digest); e == nil {
		t.Fatal("existing asset overwritten")
	}
	if e = stageNativeAsset(src, filepath.Join(root, "wrong-hash"), "wrong"); e == nil {
		t.Fatal("hash mismatch accepted")
	}
}
