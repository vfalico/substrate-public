//go:build linux

package executionpolicy

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// GuestRecord owns an immutable operation in one runtime-owned VM incarnation.
// The enforcer remains opaque: no Suite schema, Guardd inventory or commands.
type GuestRecord struct {
	Operation         string          `json:"operation"`
	Requirement       json.RawMessage `json:"requirement"`
	Target            map[string]any  `json:"target"`
	Locator           string          `json:"locator"`
	Socket            string          `json:"socket"`
	Port              uint32          `json:"port"`
	Phase             string          `json:"phase"`
	Containers        []string        `json:"containers,omitempty"`
	ContainersStopped bool            `json:"containers_stopped,omitempty"`
}

func guestCall(ctx context.Context, socket string, port uint32, message any) (map[string]json.RawMessage, error) {
	if port <= 1024 {
		return nil, fmt.Errorf("explicit guest enforcer port required")
	}
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(30 * time.Second)
	if t, ok := ctx.Deadline(); ok && t.Before(deadline) {
		deadline = t
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	// Closing this exact owned connection arbitrates cancellation during a reply.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if _, err = fmt.Fprintf(conn, "CONNECT %d\n", port); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("guest CONNECT reply read: %w", err)
	}
	fields := strings.Fields(line)
	if len(fields) != 2 || fields[0] != "OK" {
		return nil, fmt.Errorf("hybrid transport refused")
	}
	if _, err = strconv.ParseUint(fields[1], 10, 32); err != nil {
		return nil, fmt.Errorf("invalid hybrid transport reply")
	}
	raw, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	if len(raw) > 1<<20 {
		return nil, fmt.Errorf("request bounds exceeded")
	}
	frame := make([]byte, 4+len(raw))
	binary.BigEndian.PutUint32(frame, uint32(len(raw)))
	copy(frame[4:], raw)
	for len(frame) > 0 {
		n, e := conn.Write(frame)
		if e != nil {
			return nil, e
		}
		if n == 0 {
			return nil, io.ErrShortWrite
		}
		frame = frame[n:]
	}
	header := make([]byte, 4)
	if _, err = io.ReadFull(reader, header); err != nil {
		return nil, fmt.Errorf("guest response header read: %w", err)
	}
	size := binary.BigEndian.Uint32(header)
	if size == 0 || size > 1<<20 {
		return nil, fmt.Errorf("reply bounds exceeded")
	}
	raw = make([]byte, size)
	if _, err = io.ReadFull(reader, raw); err != nil {
		return nil, fmt.Errorf("guest response body read: %w", err)
	}
	var reply struct {
		Version string                     `json:"version"`
		OK      bool                       `json:"ok"`
		Error   string                     `json:"error"`
		Result  map[string]json.RawMessage `json:"result"`
	}
	if err = json.Unmarshal(raw, &reply); err != nil {
		return nil, err
	}
	if reply.Version != protocol || !reply.OK {
		return nil, fmt.Errorf("enforcer refusal: %s", reply.Error)
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return reply.Result, nil
}

func (c *Client) guestRead(actor string) (*GuestRecord, error) {
	raw, err := os.ReadFile(c.journal("guest:" + actor))
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	d.DisallowUnknownFields()
	var r GuestRecord
	if err = d.Decode(&r); err != nil {
		return nil, err
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return nil, fmt.Errorf("trailing guest journal")
	}
	if r.Operation == "" || r.Phase == "" || len(r.Requirement) == 0 || r.Target == nil {
		return nil, fmt.Errorf("incomplete guest journal")
	}
	return &r, nil
}
func (c *Client) guestSave(actor string, r *GuestRecord) error {
	// Reuse the atomic write/fsync routine with a neutral typed JSON frame.
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	path := c.journal("guest:" + actor)
	file, err := os.CreateTemp(c.Config.StateRoot, "guest-*.tmp")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if _, err = file.Write(raw); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(temp, path); err != nil {
		return err
	}
	return syncDir(c.Config.StateRoot)
}
func guestMessage(method string, r *GuestRecord) map[string]any {
	return map[string]any{"version": protocol, "method": method, "operation": r.Operation, "requirement": r.Requirement, "target": r.Target, "locator": r.Locator}
}
func guestBound(result map[string]json.RawMessage, r *GuestRecord, flag string) error {
	return bound(result, &Record{Operation: r.Operation, Requirement: r.Requirement, Target: r.Target}, flag)
}

// ActivateGuest binds one whole requirement to a prepared guest-owned subtree.
// Runtime must persist its operation before dispatch and may not start any
// governed container until this returns exact authenticated activation.
func (c *Client) prepareGuest(ctx context.Context, actor string, requirement []byte, socket, locator string, port uint32, containers ...string) (*GuestRecord, error) {
	r, err := c.guestRead(actor)
	if err == nil {
		if digest(r.Requirement) != digest(json.RawMessage(requirement)) || r.Socket != socket || r.Locator != locator || r.Port != port {
			return nil, fmt.Errorf("guest operation cannot change association")
		}
		if len(containers) != len(r.Containers) {
			return nil, fmt.Errorf("guest inventory changed")
		}
		for i := range containers {
			if containers[i] != r.Containers[i] {
				return nil, fmt.Errorf("guest inventory changed")
			}
		}
		if r.Phase != "preparing" && r.Phase != "activating" && r.Phase != "active" {
			return nil, fmt.Errorf("guest owner is cleanup-only")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	} else {
		if len(requirement) == 0 || len(requirement) > 1<<20 || !json.Valid(requirement) {
			return nil, fmt.Errorf("invalid complete requirement")
		}
		// Describe is advisory identity discovery only; it never permits release.
		generation := time.Now().UnixNano()
		var result map[string]json.RawMessage
		var e error
		until := time.Now().Add(30 * time.Second)
		for {
			result, e = guestCall(ctx, socket, port, map[string]any{"version": protocol, "method": "describe", "locator": locator, "generation": generation})
			if e == nil || time.Now().After(until) {
				break
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
		if e != nil {
			return nil, e
		}
		var target map[string]any
		d := json.NewDecoder(strings.NewReader(string(result["target"])))
		d.UseNumber()
		if e = d.Decode(&target); e != nil || target == nil {
			return nil, fmt.Errorf("invalid guest identity")
		}
		r = &GuestRecord{Requirement: append([]byte(nil), requirement...), Target: target, Locator: locator, Socket: socket, Port: port, Phase: "preparing"}
		r.Containers = append([]string(nil), containers...)
		r.Operation = digest(map[string]any{"actor": actor, "target": target})
		if e = c.guestSave(actor, r); e != nil {
			return nil, e
		}
	}
	return r, nil
}

// PrepareGuest durably owns the complete intended inventory BEFORE any
// CreateContainer dispatch. This phase never grants execution or warm lookup.
func (c *Client) PrepareGuest(ctx context.Context, actor string, requirement []byte, socket, locator string, port uint32, containers ...string) error {
	_, err := c.prepareGuest(ctx, actor, requirement, socket, locator, port, containers...)
	return err
}
func (c *Client) ActivateGuest(ctx context.Context, actor string, requirement []byte, socket, locator string, port uint32, containers ...string) error {
	r, err := c.prepareGuest(ctx, actor, requirement, socket, locator, port, containers...)
	if err != nil {
		return err
	}
	// Persist the same operation's activation intent before the authenticated RPC.
	r.Phase = "activating"
	if err = c.guestSave(actor, r); err != nil {
		return err
	}

	result, err := guestCall(ctx, r.Socket, r.Port, guestMessage("activate", r))
	if err != nil {
		return err
	}
	if err = guestBound(result, r, "active"); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	r.Phase = "active"
	return c.guestSave(actor, r)
}
func (c *Client) LookupGuest(ctx context.Context, actor string, requirement []byte) error {
	r, err := c.guestRead(actor)
	if err != nil {
		return err
	}
	if r.Phase != "active" || digest(r.Requirement) != digest(json.RawMessage(requirement)) {
		return fmt.Errorf("exact active guest requirement unavailable")
	}
	result, err := guestCall(ctx, r.Socket, r.Port, guestMessage("lookup", r))
	if err != nil {
		return err
	}
	return guestBound(result, r, "active")
}

// GuestContainersStopped is cleanup-only durable authority: never activation or
// release. It is written only after exact owning Kata container removal succeeds.
func (c *Client) GuestContainersStopped(actor string) (bool, error) {
	r, err := c.guestRead(actor)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return r.ContainersStopped, nil
}
func (c *Client) ConfirmGuestContainersStopped(actor string) error {
	r, err := c.guestRead(actor)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	r.ContainersStopped = true
	if r.Phase != "retired" {
		r.Phase = "retiring"
	}
	return c.guestSave(actor, r)
}

// GuestCleanupRecord is the exact durable cleanup owner, never release authority.
// Existing malformed state is an error rather than an absent/policy-free owner.
func (c *Client) GuestCleanupRecord(actor string) (*GuestRecord, error) {
	return c.guestRead(actor)
}

// ValidateGuestCleanup refuses a replacement bootstrap before destructive calls.
// Generation and complete opaque target are checked through the same delivered
// identity-discovery transport; observational describe never grants activation.
func (c *Client) ValidateGuestCleanup(ctx context.Context, r *GuestRecord) error {
	generation, ok := r.Target["generation"]
	if !ok {
		return fmt.Errorf("guest target lacks generation")
	}
	result, err := guestCall(ctx, r.Socket, r.Port, map[string]any{"version": protocol, "method": "describe", "locator": r.Locator, "generation": generation})
	if err != nil {
		return err
	}
	var target map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(result["target"])))
	decoder.UseNumber()
	if err := decoder.Decode(&target); err != nil {
		return err
	}
	if digest(target) != digest(r.Target) {
		return fmt.Errorf("guest cleanup target incarnation changed")
	}
	return nil
}

// RetireGuestKeepOwner persists exact retired authority until the runtime has
// stopped compute. It cannot be reused to activate, restore or warm-dispatch.
func (c *Client) RetireGuestKeepOwner(ctx context.Context, actor string) error {
	return c.retireGuest(ctx, actor, true)
}
func (c *Client) RetireGuest(ctx context.Context, actor string) error {
	return c.retireGuest(ctx, actor, false)
}
func (c *Client) retireGuest(ctx context.Context, actor string, keepOwner bool) error {
	r, err := c.guestRead(actor)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if r.Phase != "retired" {
		r.Phase = "retiring"
		if err = c.guestSave(actor, r); err != nil {
			return err
		}
		result, e := guestCall(ctx, r.Socket, r.Port, guestMessage("retire", r))
		if e != nil {
			return e
		}
		if e = guestBound(result, r, "retired"); e != nil {
			return e
		}
		r.Phase = "retired"
		if err = c.guestSave(actor, r); err != nil {
			return err
		}
	}
	if keepOwner {
		return nil
	}
	if err = os.Remove(c.journal("guest:" + actor)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncDir(c.Config.StateRoot)
}

// RefuseGuestReuse checks durable ownership after a runtime restart, before
// any snapshot, replacement or warm side effect. Cleanup-only owners also refuse.
func (c *Client) RefuseGuestReuse(actor string) error {
	_, err := c.guestRead(actor)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("governed guest reuse is unsupported; original cleanup owner retained")
}
