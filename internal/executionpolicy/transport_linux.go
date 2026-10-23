//go:build linux

package executionpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"time"
)

func interfaceInfo(ns int, name string) (map[string]any, error) {
	// Pass a duplicate, never give exec ownership of the runtime-retained handle.
	dup, err := unix.Dup(ns)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(dup), "exact-netns")
	defer f.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/nsenter", "--net=/proc/self/fd/3", "--", "/usr/sbin/ip", "-j", "link", "show", "dev", name)
	cmd.ExtraFiles = []*os.File{f}
	raw, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var links []struct {
		Index   int    `json:"ifindex"`
		Name    string `json:"ifname"`
		Address string `json:"address"`
	}
	if err = json.Unmarshal(raw, &links); err != nil {
		return nil, err
	}
	if len(links) != 1 || links[0].Name != name {
		return nil, fmt.Errorf("ambiguous interface")
	}
	return map[string]any{"index": links[0].Index, "name": name, "address": links[0].Address}, nil
}
func (c *Client) call(ctx context.Context, method string, r *Record, fds []int) (map[string]json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	deadline := time.Now().Add(15 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return nil, context.DeadlineExceeded
	}
	tv := unix.NsecToTimeval(remaining.Nanoseconds())
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return nil, err
	}
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv); err != nil {
		return nil, err
	}
	if err = unix.Connect(fd, &unix.SockaddrUnix{Name: c.Config.Socket}); err != nil {
		return nil, err
	}
	peer, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return nil, err
	}
	if peer.Uid != 0 {
		return nil, fmt.Errorf("untrusted enforcer peer")
	}
	raw, err := json.Marshal(map[string]any{"version": protocol, "method": method, "operation": r.Operation, "requirement": r.Requirement, "target": r.Target})
	if err != nil {
		return nil, err
	}
	if len(raw) > 1<<20 {
		return nil, fmt.Errorf("request bounds exceeded")
	}
	n, err := retryInterrupted(ctx, deadline, func() (int, error) { return unix.SendmsgN(fd, raw, unix.UnixRights(fds...), nil, 0) })
	if err != nil {
		return nil, err
	}
	if n != len(raw) {
		return nil, fmt.Errorf("short request")
	}
	buffer := make([]byte, 1<<20)
	var flags int
	n, err = retryInterrupted(ctx, deadline, func() (int, error) {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, context.DeadlineExceeded
		}
		tv := unix.NsecToTimeval(remaining.Nanoseconds())
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
			return 0, err
		}
		count, _, gotFlags, _, recvErr := unix.Recvmsg(fd, buffer, nil, 0)
		flags = gotFlags
		return count, recvErr
	})
	if err != nil {
		return nil, err
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return nil, fmt.Errorf("truncated reply")
	}
	var reply struct {
		Version string                     `json:"version"`
		OK      bool                       `json:"ok"`
		Error   string                     `json:"error"`
		Result  map[string]json.RawMessage `json:"result"`
	}
	if err = json.Unmarshal(buffer[:n], &reply); err != nil {
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

// Retry only a kernel-interrupted syscall on the SAME socket, never reconnect
// or resend a successfully submitted operation after an uncertain reply.
func retryInterrupted(ctx context.Context, deadline time.Time, call func() (int, error)) (int, error) {
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if !time.Now().Before(deadline) {
			return 0, context.DeadlineExceeded
		}
		n, err := call()
		if !errors.Is(err, unix.EINTR) {
			return n, err
		}
	}
}
