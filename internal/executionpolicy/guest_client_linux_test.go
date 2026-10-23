//go:build linux

package executionpolicy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TEST-ONLY independently implemented opaque stream peer. No policy parsing or
// kernel-enforcement claim. Real Unix stream + VMM CONNECT handshake exercises
// the delivered transport and root-owned normal configuration loader.
type guestTestPeer struct {
	mu                                                   sync.Mutex
	calls                                                []string
	operation                                            string
	requirement                                          json.RawMessage
	target                                               map[string]any
	dropFirst, stale, delay, failRetire, changedDescribe bool
	entered                                              chan struct{}
	release                                              chan struct{}
}

func (p *guestTestPeer) serve(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	if line != "CONNECT 1030\n" {
		return
	}
	if _, err = io.WriteString(conn, "OK 77\n"); err != nil {
		return
	}
	var size [4]byte
	if _, err = io.ReadFull(reader, size[:]); err != nil {
		return
	}
	n := binary.BigEndian.Uint32(size[:])
	if n > 4<<20 {
		return
	}
	raw := make([]byte, n)
	if _, err = io.ReadFull(reader, raw); err != nil {
		return
	}
	var q struct {
		Version, Method, Operation, Locator string
		Requirement                         json.RawMessage
		Target                              map[string]any
		Generation                          int
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&q) != nil {
		return
	}
	p.mu.Lock()
	p.calls = append(p.calls, q.Method)
	if q.Method == "describe" {
		kind := "test-boundary/v1"
		if p.changedDescribe {
			kind = "test-replacement/v1"
		}
		p.mu.Unlock()
		p.reply(conn, map[string]any{"target": map[string]any{"kind": kind, "generation": q.Generation}}, "")
		return
	}
	if p.operation == "" {
		p.operation = q.Operation
		p.requirement = append(json.RawMessage(nil), q.Requirement...)
		p.target = q.Target
	}
	if p.operation != q.Operation || digest(p.requirement) != digest(q.Requirement) || digest(p.target) != digest(q.Target) {
		p.mu.Unlock()
		p.reply(conn, nil, "association changed")
		return
	}
	drop := q.Method == "activate" && p.dropFirst
	if drop {
		p.dropFirst = false
	}
	stale := p.stale
	delay := q.Method == "activate" && p.delay
	failure := q.Method == "retire" && p.failRetire
	if failure {
		p.failRetire = false
	}
	result := map[string]any{"operation": q.Operation, "binding": digest(map[string]any{"requirement": q.Requirement, "target": q.Target}), "requirement": digest(q.Requirement), "target": digest(q.Target)}
	if q.Method == "retire" {
		result["retired"] = true
	} else {
		result["active"] = true
	}
	if stale {
		result["target"] = "stale-target"
	}
	p.mu.Unlock()
	if drop {
		return
	}
	if delay {
		close(p.entered)
		<-p.release
	}
	if failure {
		p.reply(conn, nil, "injected retirement failure")
		return
	}
	p.reply(conn, result, "")
}
func (p *guestTestPeer) reply(conn net.Conn, result map[string]any, refusal string) {
	raw, err := json.Marshal(map[string]any{"version": protocol, "ok": refusal == "", "result": result, "error": refusal})
	if err != nil {
		return
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
	if _, err = conn.Write(header[:]); err != nil {
		return
	}
	_, _ = conn.Write(raw)
}
func guestFixture(t *testing.T, p *guestTestPeer) (*Client, string) {
	t.Helper()
	dir := t.TempDir()
	socket := filepath.Join(dir, "vmm.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			wg.Add(1)
			go func() { defer wg.Done(); p.serve(c) }()
		}
	}()
	t.Cleanup(func() { l.Close(); <-done; wg.Wait() })
	config := filepath.Join(dir, "config.json")
	raw, _ := json.Marshal(Config{Socket: socket, StateRoot: filepath.Join(dir, "state"), GuestPort: 1030})
	if err = os.WriteFile(config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	// root ownership is a production trust precondition, not silently bypassed.
	if os.Geteuid() != 0 {
		t.Skip("normal protected config needs root; run bounded task-owned test with sudo")
	}
	client, err := Load(config)
	if err != nil {
		t.Fatal(err)
	}
	return client, socket
}

var guestOpaqueRequirement = []byte(`{"format":"test.non-suite/v1","bytes":"AAECAw==","digest":"opaque-producer-digest","capabilities":["test/opaque/v1"]}`)

func TestGuestLostReplyRetriesSameDurableOperation(t *testing.T) {
	peer := &guestTestPeer{dropFirst: true}
	c, socket := guestFixture(t, peer)
	if err := c.ActivateGuest(t.Context(), "actor", guestOpaqueRequirement, socket, "/sys/fs/cgroup/prepared", 1030); err == nil {
		t.Fatal("lost reply granted release")
	}
	before, err := c.guestRead("actor")
	if err != nil || before.Phase != "activating" {
		t.Fatal(before, err)
	}
	// A new client is a runtime restart; retained operation, target and owner survive.
	restarted := &Client{Config: c.Config}
	if err = restarted.ActivateGuest(t.Context(), "actor", guestOpaqueRequirement, socket, "/sys/fs/cgroup/prepared", 1030); err != nil {
		t.Fatal(err)
	}
	after, err := restarted.guestRead("actor")
	if err != nil || after.Operation != before.Operation || after.Phase != "active" {
		t.Fatal(after, err)
	}
	peer.mu.Lock()
	calls := append([]string(nil), peer.calls...)
	peer.mu.Unlock()
	if fmt.Sprint(calls) != "[describe activate activate]" {
		t.Fatal(calls)
	}
	for _, change := range []struct {
		req             []byte
		socket, locator string
		port            uint32
	}{{[]byte(`{"other":true}`), socket, "/sys/fs/cgroup/prepared", 1030}, {guestOpaqueRequirement, socket, "/sys/fs/cgroup/replacement", 1030}, {guestOpaqueRequirement, socket + "-new", "/sys/fs/cgroup/prepared", 1030}, {guestOpaqueRequirement, socket, "/sys/fs/cgroup/prepared", 1031}} {
		if err = restarted.ActivateGuest(t.Context(), "actor", change.req, change.socket, change.locator, change.port); err == nil {
			t.Fatal("changed association reused")
		}
	}
	if err = restarted.RefuseGuestReuse("actor"); err == nil {
		t.Fatal("governed reuse permitted")
	}
	if err = restarted.RetireGuest(t.Context(), "actor"); err != nil {
		t.Fatal(err)
	}
	if err = restarted.RetireGuest(t.Context(), "actor"); err != nil {
		t.Fatal(err)
	}
	if err = restarted.RefuseGuestReuse("actor"); err != nil {
		t.Fatal("completed owner blocks fresh authority", err)
	}
}
func TestGuestStaleReplyNeverActivates(t *testing.T) {
	peer := &guestTestPeer{stale: true}
	c, socket := guestFixture(t, peer)
	if err := c.ActivateGuest(t.Context(), "actor", guestOpaqueRequirement, socket, "/sys/fs/cgroup/prepared", 1030); err == nil {
		t.Fatal("stale target accepted")
	}
	r, err := c.guestRead("actor")
	if err != nil || r.Phase != "activating" {
		t.Fatal(r, err)
	}
	if err = c.LookupGuest(t.Context(), "actor", guestOpaqueRequirement); err == nil {
		t.Fatal("uncertain owner looked active")
	}
}
func TestGuestCancellationClosesReplyConnectionWithoutRelease(t *testing.T) {
	peer := &guestTestPeer{delay: true, entered: make(chan struct{}), release: make(chan struct{})}
	c, socket := guestFixture(t, peer)
	// Register after fixture cleanup so release happens before waiting for peer children.
	t.Cleanup(func() { close(peer.release) })
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- c.ActivateGuest(ctx, "actor", guestOpaqueRequirement, socket, "/sys/fs/cgroup/prepared", 1030)
	}()
	select {
	case <-peer.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("activation never reached peer")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled activation released")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not close exact owned connection")
	}
	r, err := c.guestRead("actor")
	if err != nil || r.Phase != "activating" {
		t.Fatal(r, err)
	}
}
func TestGuestRetirementFailureRetainsCleanupOwner(t *testing.T) {
	peer := &guestTestPeer{failRetire: true}
	c, socket := guestFixture(t, peer)
	if err := c.ActivateGuest(t.Context(), "actor", guestOpaqueRequirement, socket, "/sys/fs/cgroup/prepared", 1030); err != nil {
		t.Fatal(err)
	}
	if err := c.RetireGuest(t.Context(), "actor"); err == nil {
		t.Fatal("injected failure lost")
	}
	r, err := c.guestRead("actor")
	if err != nil || r.Phase != "retiring" {
		t.Fatal(r, err)
	}
	restarted := &Client{Config: c.Config}
	if err = restarted.ActivateGuest(t.Context(), "actor", guestOpaqueRequirement, socket, "/sys/fs/cgroup/prepared", 1030); err == nil {
		t.Fatal("cleanup-only owner reactivated")
	}
	if err = restarted.RefuseGuestReuse("actor"); err == nil {
		t.Fatal("cleanup-only reuse permitted")
	}
	if err = restarted.RetireGuest(t.Context(), "actor"); err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.guestRead("actor"); !os.IsNotExist(err) {
		t.Fatal("completed owner remains", err)
	}
}

func TestGuestCleanupCheckpointSurvivesNewClientAndRefusesReplacement(t *testing.T) {
	peer := &guestTestPeer{}
	client, socket := guestFixture(t, peer)
	if err := client.ActivateGuest(t.Context(), "actor", guestOpaqueRequirement, socket, "/sys/fs/cgroup/prepared", 1030, "one", "two"); err != nil {
		t.Fatal(err)
	}
	record, err := client.GuestCleanupRecord("actor")
	if err != nil || len(record.Containers) != 2 || record.Containers[1] != "two" {
		t.Fatal(record, err)
	}
	if err := client.ValidateGuestCleanup(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	if err := client.ConfirmGuestContainersStopped("actor"); err != nil {
		t.Fatal(err)
	}
	restarted := &Client{Config: client.Config}
	record, err = restarted.GuestCleanupRecord("actor")
	if err != nil || !record.ContainersStopped || record.Phase != "retiring" {
		t.Fatal(record, err)
	}
	if err := restarted.ActivateGuest(t.Context(), "actor", guestOpaqueRequirement, socket, "/sys/fs/cgroup/prepared", 1030, "one", "two"); err == nil {
		t.Fatal("stop checkpoint granted release")
	}
	peer.mu.Lock()
	peer.changedDescribe = true
	peer.mu.Unlock()
	if err := restarted.ValidateGuestCleanup(t.Context(), record); err == nil {
		t.Fatal("replacement accepted for cleanup")
	}
	peer.mu.Lock()
	for _, method := range peer.calls {
		if method == "retire" {
			t.Fatal("replacement validation retired owner")
		}
	}
	peer.changedDescribe = false
	peer.mu.Unlock()
	if err := restarted.RetireGuestKeepOwner(t.Context(), "actor"); err != nil {
		t.Fatal(err)
	}
	again := &Client{Config: client.Config}
	record, err = again.GuestCleanupRecord("actor")
	if err != nil || record.Phase != "retired" || !record.ContainersStopped {
		t.Fatal(record, err)
	}
	if err := again.RefuseGuestReuse("actor"); err == nil {
		t.Fatal("retired but unfinished compute owner reused")
	}
	if err := again.RetireGuest(t.Context(), "actor"); err != nil {
		t.Fatal(err)
	}
	if _, err := again.GuestCleanupRecord("actor"); !os.IsNotExist(err) {
		t.Fatal("finished owner retained", err)
	}
}

func TestPreCreateOwnerIsDurableImmutableAndNeverRelease(t *testing.T) {
	peer := &guestTestPeer{}
	client, socket := guestFixture(t, peer)
	if err := client.PrepareGuest(t.Context(), "actor", guestOpaqueRequirement, socket, "/sys/fs/cgroup/prepared", 1030, "one", "two"); err != nil {
		t.Fatal(err)
	}
	before, err := client.GuestCleanupRecord("actor")
	if err != nil || before.Phase != "preparing" {
		t.Fatal(before, err)
	}
	restarted := &Client{Config: client.Config}
	if err := restarted.LookupGuest(t.Context(), "actor", guestOpaqueRequirement); err == nil {
		t.Fatal("preparing owner authorized warm release")
	}
	if err := restarted.RefuseGuestReuse("actor"); err == nil {
		t.Fatal("preparing owner lost restart authority")
	}
	if err := restarted.PrepareGuest(t.Context(), "actor", guestOpaqueRequirement, socket, "/sys/fs/cgroup/prepared", 1030, "one"); err == nil {
		t.Fatal("changed inventory accepted")
	}
	if err := restarted.ActivateGuest(t.Context(), "actor", guestOpaqueRequirement, socket, "/sys/fs/cgroup/prepared", 1030, "one", "two"); err != nil {
		t.Fatal(err)
	}
	after, err := restarted.GuestCleanupRecord("actor")
	if err != nil || after.Operation != before.Operation || after.Phase != "active" {
		t.Fatal(after, err)
	}
}
func TestPartialPrepareRetirementRemainsMonotonic(t *testing.T) {
	peer := &guestTestPeer{}
	client, socket := guestFixture(t, peer)
	if err := client.PrepareGuest(t.Context(), "actor", guestOpaqueRequirement, socket, "/sys/fs/cgroup/prepared", 1030, "one", "two"); err != nil {
		t.Fatal(err)
	}
	before, _ := client.GuestCleanupRecord("actor")
	if err := client.RetireGuestKeepOwner(t.Context(), "actor"); err != nil {
		t.Fatal(err)
	}
	if err := client.ConfirmGuestContainersStopped("actor"); err != nil {
		t.Fatal(err)
	}
	restarted := &Client{Config: client.Config}
	after, err := restarted.GuestCleanupRecord("actor")
	if err != nil || after.Operation != before.Operation || after.Phase != "retired" || !after.ContainersStopped {
		t.Fatal(after, err)
	}
	if err := restarted.ActivateGuest(t.Context(), "actor", guestOpaqueRequirement, socket, "/sys/fs/cgroup/prepared", 1030, "one", "two"); err == nil {
		t.Fatal("retired preparation reactivated")
	}
}
