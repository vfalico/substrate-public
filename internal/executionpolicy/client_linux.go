//go:build linux

// Package executionpolicy binds an opaque whole-execution requirement to an
// owning runtime's exact compute/network handles. It never interprets policy.
package executionpolicy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const protocol = "execution-enforcement/v1"

type Config struct {
	Socket, StateRoot     string
	GuestPort             uint32
	ControlSourcePorts    []uint16
	ControlStdioContainer string
}
type Record struct {
	Operation             string          `json:"operation"`
	Requirement           json.RawMessage `json:"requirement"`
	Target                map[string]any  `json:"target"`
	CgroupPath, NetNSPath string
	Phase                 string
}
type Client struct{ Config Config }

func Load(path string) (*Client, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	var us unix.Stat_t
	if err = unix.Fstat(fd, &us); err != nil {
		return nil, err
	}
	if us.Uid != 0 || st.Mode().Perm()&0022 != 0 || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("untrusted execution enforcer config")
	}
	d := json.NewDecoder(io.LimitReader(f, 16385))
	d.DisallowUnknownFields()
	var c Config
	if err = d.Decode(&c); err != nil {
		return nil, err
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return nil, fmt.Errorf("trailing enforcer config")
	}
	if !filepath.IsAbs(c.Socket) || !filepath.IsAbs(c.StateRoot) {
		return nil, fmt.Errorf("absolute trusted paths required")
	}
	if err = os.MkdirAll(c.StateRoot, 0700); err != nil {
		return nil, err
	}
	s, err := os.Lstat(c.StateRoot)
	if err != nil {
		return nil, err
	}
	if !s.IsDir() || s.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("untrusted execution state directory")
	}
	return &Client{Config: c}, nil
}

// Canonical object key order and exact decimal integers match the neutral wire.
// UseNumber avoids corrupting kernel inode identities when journals are reopened.
func digest(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var normalized any
	if err = d.Decode(&normalized); err != nil {
		panic(err)
	}
	var out bytes.Buffer
	e := json.NewEncoder(&out)
	e.SetEscapeHTML(false)
	if err = e.Encode(normalized); err != nil {
		panic(err)
	}
	canonical := bytes.TrimSuffix(out.Bytes(), []byte{'\n'})
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (c *Client) journal(actor string) string {
	sum := sha256.Sum256([]byte(actor))
	return filepath.Join(c.Config.StateRoot, hex.EncodeToString(sum[:])+".json")
}
func (c *Client) save(actor string, r *Record) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	p := c.journal(actor)
	f, err := os.CreateTemp(c.Config.StateRoot, filepath.Base(p)+".tmp-*")
	if err != nil {
		return err
	}
	// A crash-left temporary file is never authority and must not wedge later
	// saves. Each writer owns only its unique temp name; journal replacement is
	// still atomic and its parent directory is fsynced before returning.
	temporary := f.Name()
	defer os.Remove(temporary)
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(temporary, p); err != nil {
		return err
	}
	return syncDir(c.Config.StateRoot)
}
func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func (c *Client) Read(actor string) (*Record, error) {
	f, err := os.Open(c.journal(actor))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r Record
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	d.UseNumber()
	if err = d.Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}
func open(path string) (int, error) {
	return unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
}
func target(cg, ns int, iface, netnsPath string, generation int64) (map[string]any, error) {
	var st, nt unix.Stat_t
	var fs unix.Statfs_t
	if err := unix.Fstat(cg, &st); err != nil {
		return nil, err
	}
	if err := unix.Fstatfs(cg, &fs); err != nil {
		return nil, err
	}
	if uint64(fs.Type) != 0x63677270 {
		return nil, fmt.Errorf("not cgroup v2")
	}
	if err := unix.Fstat(ns, &nt); err != nil {
		return nil, err
	}
	info, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", cg))
	if err != nil {
		return nil, err
	}
	var mount uint64
	for _, line := range strings.Split(string(info), "\n") {
		if strings.HasPrefix(line, "mnt_id:") {
			mount, err = strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "mnt_id:")), 10, 64)
			if err != nil {
				return nil, err
			}
		}
	}
	if mount == 0 {
		return nil, fmt.Errorf("missing cgroup mount")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	link, err := interfaceInfo(ns, iface)
	if err != nil {
		return nil, err
	}
	return map[string]any{"kind": "network-interface/v1", "boot": strings.TrimSpace(string(boot)), "cgroup": map[string]any{"dev": st.Dev, "ino": st.Ino, "mount_id": mount, "cgroup_id": st.Ino}, "netns": map[string]any{"dev": nt.Dev, "ino": nt.Ino, "locator": "/run/netns/" + filepath.Base(netnsPath)}, "interface": link, "generation": generation}, nil
}
func (c *Client) Activate(ctx context.Context, actor string, requirement []byte, cgroup, namespace, iface string) error {
	if len(requirement) == 0 {
		return nil
	}
	if len(requirement) > 1<<20 || !json.Valid(requirement) {
		return fmt.Errorf("malformed complete execution requirement")
	}
	if _, err := c.Read(actor); err == nil {
		return fmt.Errorf("prior exact execution binding requires retirement")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	cg, err := open(cgroup)
	if err != nil {
		return err
	}
	defer unix.Close(cg)
	ns, err := open(namespace)
	if err != nil {
		return err
	}
	defer unix.Close(ns)
	if !strings.HasPrefix(namespace, "/run/netns/") || filepath.Base(namespace) == "." || filepath.Base(namespace) == ".." {
		return fmt.Errorf("stable runtime-owned netns locator required")
	}
	t, err := target(cg, ns, iface, namespace, time.Now().UnixNano())
	if err != nil {
		return err
	}
	r := &Record{Operation: digest(map[string]any{"actor": actor, "target": t}), Requirement: append([]byte(nil), requirement...), Target: t, CgroupPath: cgroup, NetNSPath: namespace, Phase: "activating"}
	if err = c.save(actor, r); err != nil {
		return err
	}
	result, err := c.call(ctx, "activate", r, []int{cg, ns})
	if err != nil {
		return err
	}
	if err = bound(result, r, "active"); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	r.Phase = "active"
	return c.save(actor, r)
}

// Lookup independently authenticates the original active association and live
// kernel handles. A journal alone is never current enforcement authority.
func (c *Client) Lookup(ctx context.Context, actor string, requirement []byte) error {
	r, err := c.Read(actor)
	if err != nil {
		return err
	}
	if r.Phase != "active" || digest(r.Requirement) != digest(json.RawMessage(requirement)) {
		return fmt.Errorf("exact active execution requirement unavailable")
	}
	cg, err := open(r.CgroupPath)
	if err != nil {
		return err
	}
	defer unix.Close(cg)
	ns, err := open(r.NetNSPath)
	if err != nil {
		return err
	}
	defer unix.Close(ns)
	result, err := c.call(ctx, "lookup", r, []int{cg, ns})
	if err != nil {
		return err
	}
	return bound(result, r, "active")
}

func (c *Client) Retire(ctx context.Context, actor string) error {
	r, err := c.Read(actor)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if r.Phase != "retired" {
		r.Phase = "retiring"
		if err = c.save(actor, r); err != nil {
			return err
		}
		cg, cgErr := open(r.CgroupPath)
		var fds []int
		if cgErr == nil {
			defer unix.Close(cg)
			ns, nsErr := open(r.NetNSPath)
			if nsErr != nil {
				return nsErr
			}
			defer unix.Close(ns)
			fds = []int{cg, ns}
		} else if !errors.Is(cgErr, os.ErrNotExist) {
			return cgErr
		}
		result, err := c.call(ctx, "retire", r, fds)
		if err != nil {
			return err
		}
		if err = bound(result, r, "retired"); err != nil {
			return err
		}
		r.Phase = "retired"
		if err = c.save(actor, r); err != nil {
			return err
		}
	}
	if err = os.Remove(c.journal(actor)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(c.Config.StateRoot)
}
func bound(result map[string]json.RawMessage, r *Record, flag string) error {
	var ok bool
	if json.Unmarshal(result[flag], &ok) != nil || !ok {
		return fmt.Errorf("enforcer did not prove %s", flag)
	}
	for k, v := range map[string]string{"operation": r.Operation, "binding": digest(map[string]any{"requirement": r.Requirement, "target": r.Target}), "requirement": digest(r.Requirement), "target": digest(r.Target)} {
		var got string
		if json.Unmarshal(result[k], &got) != nil || got != v {
			return fmt.Errorf("exact enforcer %s mismatch", k)
		}
	}
	return nil
}
