//go:build linux

package executionpolicy

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Explicit native qualification. The controlling reproducer owns daemon, netns,
// cgroup and deadlines; the test uses the same normal client as ateom.
func TestNativeConfiguredInterfaceBinding(t *testing.T) {
	config := os.Getenv("EXECUTION_NATIVE_CONFIG")
	if config == "" {
		t.Skip("explicit native qualification required")
	}
	c, err := Load(config)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(os.Getenv("EXECUTION_NATIVE_REQUIREMENT"))
	if err != nil {
		t.Fatal(err)
	}
	cg, ns, iface := os.Getenv("EXECUTION_NATIVE_CGROUP"), os.Getenv("EXECUTION_NATIVE_NETNS"), os.Getenv("EXECUTION_NATIVE_INTERFACE")
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	if err = c.Activate(ctx, "native", raw, cg, ns, iface); err != nil {
		t.Fatal(err)
	}
	record, err := c.Read("native")
	if err != nil {
		t.Fatal(err)
	}
	if record.Phase != "active" {
		t.Fatal("not active", record.Phase)
	}
	if err = c.Activate(ctx, "native", raw, cg, ns, iface); err == nil {
		t.Fatal("live journal reused")
	}
	// This static script is task-owned packet generation, not runtime input.
	cmd := exec.CommandContext(ctx, "/usr/sbin/ip", "netns", "exec", filepath.Base(os.Getenv("EXECUTION_NATIVE_ACTOR_NS")), "/usr/bin/python3", "-c", `import socket,json
result={}
for kind,port in [(socket.SOCK_STREAM,28292),(socket.SOCK_STREAM,28293),(socket.SOCK_STREAM,53),(socket.SOCK_DGRAM,53)]:
 s=socket.socket(socket.AF_INET,kind);s.settimeout(.4)
 try:s.connect(('169.254.17.1',port));s.send(b'wire-native');result[str(kind)+':'+str(port)]='sent'
 except OSError as e:result[str(kind)+':'+str(port)]=str(e)
 finally:s.close()
print(json.dumps(result))`)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err, string(out))
	}
	t.Log("NATIVE_CLIENT", strings.TrimSpace(string(out)))
	var attempts map[string]string
	if err = json.Unmarshal(out, &attempts); err != nil {
		t.Fatal(err)
	}
	if attempts["1:28292"] != "sent" || attempts["1:28293"] == "sent" || attempts["1:53"] == "sent" {
		t.Fatal(attempts)
	}
	// Fresh normal client reopens exact durable identity before retirement.
	c, err = Load(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Retire(ctx, "native"); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Read("native"); !os.IsNotExist(err) {
		t.Fatal("retired journal remains", err)
	}
	t.Log("NATIVE_CONFIGURED_CLIENT_RETIRE_PASS")
}
