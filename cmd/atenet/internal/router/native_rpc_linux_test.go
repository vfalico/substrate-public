//go:build linux

package router

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/cmd/atenet/internal/router/extproc"
	"github.com/agent-substrate/substrate/cmd/atenet/internal/router/ingress"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Real ingress handler, ext_proc, xDS and Envoy dataplane; the native parent
// supplies actual Control/ActorWorkflow, atelet and mTLS atunnel/microVM.
func TestNativeRouterRPC(t *testing.T) {
	root := os.Getenv("EXECUTION_ROUTER_NATIVE_ROOT")
	if root == "" {
		t.Skip("explicit task-owned native resources required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 130*time.Second)
	defer cancel()
	transport := insecure.NewCredentials()
	if os.Getenv("EXECUTION_NATIVE_KAGENT") == "1" {
		trusted, err := credentials.NewClientTLSFromFile(filepath.Join(root, "trust.pem"), "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		transport = trusted
	}
	conn, err := grpc.NewClient("unix://"+filepath.Join(root, "control-rpc.sock"), grpc.WithTransportCredentials(transport))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	handler := ingress.New(ateapipb.NewControlClient(conn), ingress.ParkedRequestConfig{}, nil)
	histogram, err := extproc.NewRouteDurationHistogram()
	if err != nil {
		t.Fatal(err)
	}
	processor := extproc.NewServer(0, histogram, extproc.Handlers{extproc.DirectionIngress: handler})
	server := processor.NewGRPCServer()
	extListen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	extDone := make(chan error, 1)
	go func() { extDone <- server.Serve(extListen) }()
	defer func() { server.Stop(); <-extDone }()
	xdsListen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// Reserve ingress until Envoy starts; no host or cluster configuration changes.
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserved.Addr().(*net.TCPAddr).Port
	reserved.Close()
	// A dedicated unused numeric UID gets its own inotify-instance allowance;
	// no host sysctls or existing process limits are changed.
	private, err := os.MkdirTemp("/tmp", "poc-envoy-native-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(private)
	if err = os.Chown(private, 60807, 60807); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"bundle.pem", "trust.pem"} {
		raw, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatal(err)
		}
		dest := filepath.Join(private, file)
		if err = os.WriteFile(dest, raw, 0400); err != nil {
			t.Fatal(err)
		}
		if err = os.Chown(dest, 60807, 60807); err != nil {
			t.Fatal(err)
		}
	}
	xds := NewXdsServer(xdsListen.Addr().(*net.TCPAddr).Port)
	xds.SetConfig(port, extListen.Addr().(*net.TCPAddr).Port, "127.0.0.1")
	xds.SetUpstreamTls(filepath.Join(private, "bundle.pem"), filepath.Join(private, "trust.pem"), "spiffe://task.local/")
	xdsCtx, xdsCancel := context.WithCancel(ctx)
	xdsDone := make(chan error, 1)
	go func() { xdsDone <- xds.Serve(xdsCtx, xdsListen) }()
	defer func() {
		xdsCancel()
		if err := <-xdsDone; err != nil {
			t.Error(err)
		}
	}()
	bootstrap := map[string]any{}
	bootstrap["node"] = map[string]any{"id": NodeID, "cluster": "task-owned-native"}
	grpcService := map[string]any{"envoy_grpc": map[string]any{"cluster_name": "xds"}}
	ads := map[string]any{"api_type": "GRPC", "transport_api_version": "V3", "grpc_services": []any{grpcService}}
	discovery := map[string]any{"ads": map[string]any{}, "resource_api_version": "V3"}
	bootstrap["dynamic_resources"] = map[string]any{"ads_config": ads, "cds_config": discovery, "lds_config": discovery}
	socket := map[string]any{"address": "127.0.0.1", "port_value": xdsListen.Addr().(*net.TCPAddr).Port}
	endpoint := map[string]any{"endpoint": map[string]any{"address": map[string]any{"socket_address": socket}}}
	assignment := map[string]any{"cluster_name": "xds", "endpoints": []any{map[string]any{"lb_endpoints": []any{endpoint}}}}
	cluster := map[string]any{"name": "xds", "type": "STATIC", "connect_timeout": "2s", "http2_protocol_options": map[string]any{}, "load_assignment": assignment}
	bootstrap["static_resources"] = map[string]any{"clusters": []any{cluster}}

	raw, err := json.Marshal(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(private, "envoy-bootstrap.json")
	if err = os.WriteFile(config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(config, 60807, 60807); err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(root, "envoy.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	processCtx, processCancel := context.WithCancel(ctx)
	defer processCancel()
	command := exec.CommandContext(processCtx, "/usr/local/bin/envoy", "-c", config, "--disable-hot-restart", "--concurrency", "2", "--log-level", "warning")
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 60807, Gid: 60807}}
	command.Stdout = log
	command.Stderr = log
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	defer func() { processCancel(); <-done }()
	address := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	for {
		c, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		select {
		case err := <-done:
			done <- err
			t.Fatalf("Envoy exited before readiness: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	if err = os.WriteFile(filepath.Join(root, "router-ready"), []byte(address), 0600); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err = os.Stat(filepath.Join(root, "router-stop")); err == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// TestNativeTunnelRelay is a transparent byte relay in a task-owned namespace.
// It returns no fabricated protocol replies and does not terminate mTLS.
func TestNativeTunnelRelay(t *testing.T) {
	if os.Getenv("EXECUTION_NATIVE_RELAY") != "1" {
		t.Skip("explicit namespace relay required")
	}
	listener, err := net.Listen("tcp", "10.207.8.2:443")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { <-ctx.Done(); listener.Close() }()
	defer wg.Wait()
	for {
		in, err := listener.Accept()
		if err != nil {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer in.Close()
			out, err := net.DialTimeout("tcp", "10.207.8.1:29443", 2*time.Second)
			if err != nil {
				return
			}
			defer out.Close()
			closed := make(chan struct{})
			go func() {
				select {
				case <-ctx.Done():
					in.Close()
					out.Close()
				case <-closed:
				}
			}()
			defer close(closed)
			done := make(chan struct{})
			go func() { io.Copy(out, in); out.Close(); close(done) }()
			io.Copy(in, out)
			in.Close()
			<-done
		}()
	}
}
