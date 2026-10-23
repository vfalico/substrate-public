//go:build linux

package ateomnet

import (
	"context"
	"fmt"
	"github.com/agent-substrate/substrate/internal/ateomnet/netns"
	"github.com/agent-substrate/substrate/internal/nodepath"
	"golang.org/x/sys/unix"
	"os"
	"testing"
)

func TestCancelledCloseRetainsNetworkAndHolder(t *testing.T) {
	n := &SandboxNetwork{RuntimeNetNS: -1, GatewayNetNS: -1}
	s := &SandboxSession{Network: n}
	h := &SessionHolder{session: s}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := h.Close(ctx); err == nil {
		t.Fatal("cancelled close accepted")
	}
	if h.Session() != s || s.cleanupNetwork != n {
		t.Fatal("lost exact cleanup owner")
	}
	if _, err := s.Dialer()(t.Context(), "tcp", "127.0.0.1:1"); err == nil {
		t.Fatal("closing network dial accepted")
	}
	// No real handles or names were allocated; discard synthetic resource before retry.
	s.cleanupNetwork = nil
	s.Network = nil
	if err := h.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if h.Session() != nil {
		t.Fatal("holder retained proven cleanup")
	}
}

func TestNativeExactNamespaceCleanupRetryPreservesReplacement(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("explicit privileged namespace qualification required")
	}
	id := fmt.Sprintf("poc-cleanup-%d", os.Getpid())
	name := nodepath.ActorNetNSName(id)
	original, err := netns.CreateNamed(name)
	if err != nil {
		t.Fatal(err)
	}
	n := &SandboxNetwork{ActorUID: id, RuntimeNetNS: original, GatewayNetNS: original}
	defer func() {
		if n.RuntimeNetNS > 0 {
			n.RuntimeNetNS.Close()
		}
		if err := netns.RemoveNamed(name); err != nil {
			t.Error(err)
		}
	}()
	if err = netns.RemoveNamed(name); err != nil {
		t.Fatal(err)
	}
	replacement, err := netns.CreateNamed(name)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	s := &SandboxSession{Network: n}
	if err = s.Close(t.Context()); err == nil {
		t.Fatal("same-name replacement removed")
	}
	if s.cleanupNetwork != n || n.RuntimeNetNS <= 0 {
		t.Fatal("lost retained original handles")
	}
	current, err := netns.GetFromName(name)
	if err != nil {
		t.Fatal("replacement absent", err)
	}
	var expected, actual unix.Stat_t
	if err = unix.Fstat(int(replacement), &expected); err != nil {
		t.Fatal(err)
	}
	if err = unix.Fstat(int(current), &actual); err != nil {
		t.Fatal(err)
	}
	current.Close()
	if expected.Dev != actual.Dev || expected.Ino != actual.Ino {
		t.Fatal("replacement identity changed")
	}
	if err = netns.RemoveNamed(name); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(t.Context()); err != nil {
		t.Fatal("retry after replacement moved", err)
	}
	if s.cleanupNetwork != nil || s.Network != nil || n.RuntimeNetNS != -1 {
		t.Fatal("cleanup not terminal")
	}
	if err = s.Close(t.Context()); err != nil {
		t.Fatal("terminal retry", err)
	}
	t.Log("NATIVE_EXACT_NAMESPACE_REPLACEMENT_UNTOUCHED_RETRY_PASS")
}
