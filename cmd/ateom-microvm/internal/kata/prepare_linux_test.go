//go:build linux

package kata

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/cmd/ateom-microvm/internal/third_party/kata/agentpb"
	"github.com/containerd/ttrpc"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/protobuf/types/known/emptypb"
)

// The fake is a protocol-order discriminator, NOT guest execution evidence.
func TestPrepareRootfsContainerDoesNotStart(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted", true: "create-error"}[fail], func(t *testing.T) {
			sock := filepath.Join(t.TempDir(), "agent.sock")
			listener, err := net.Listen("unix", sock)
			if err != nil {
				t.Fatal(err)
			}
			server, err := ttrpc.NewServer()
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var calls []string
			server.Register("grpc.AgentService", map[string]ttrpc.Method{
				"CreateContainer": func(_ context.Context, unmarshal func(interface{}) error) (interface{}, error) {
					var req agentpb.CreateContainerRequest
					if err := unmarshal(&req); err != nil {
						return nil, err
					}
					mu.Lock()
					calls = append(calls, "create:"+req.ContainerId)
					mu.Unlock()
					if req.OCI.Root.Path != GuestSharedRootfs("probe") || req.OCI.Linux.CgroupsPath != "/ateomchv/probe" {
						return nil, errors.New("rootfs/cgroup identity lost")
					}
					if fail {
						return nil, errors.New("create refused")
					}
					return &emptypb.Empty{}, nil
				},
				"StartContainer": func(_ context.Context, unmarshal func(interface{}) error) (interface{}, error) {
					var req agentpb.StartContainerRequest
					if err := unmarshal(&req); err != nil {
						return nil, err
					}
					mu.Lock()
					calls = append(calls, "start:"+req.ContainerId)
					mu.Unlock()
					return &emptypb.Empty{}, nil
				},
			})
			go func() {
				if err := server.Serve(context.Background(), listener); err != nil {
					t.Logf("fake server stopped: %v", err)
				}
			}()
			t.Cleanup(func() {
				if err := server.Close(); err != nil {
					t.Log(err)
				}
			})
			conn, err := net.Dial("unix", sock)
			if err != nil {
				t.Fatal(err)
			}
			client := &AgentClient{conn: conn, client: ttrpc.NewClient(conn)}
			t.Cleanup(func() {
				if err := client.Close(); err != nil {
					t.Log(err)
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			spec := &specs.Spec{Root: &specs.Root{Path: "/unused"}, Linux: &specs.Linux{}}
			err = client.PrepareRootfsContainer(ctx, "probe", spec)
			if (err != nil) != fail {
				t.Fatalf("Prepare error=%v fail=%v", err, fail)
			}
			mu.Lock()
			got := append([]string(nil), calls...)
			mu.Unlock()
			if !reflect.DeepEqual(got, []string{"create:probe"}) {
				t.Fatalf("preparation dispatched execution: %v", got)
			}
			if !fail {
				if err := client.StartContainer(ctx, "probe"); err != nil {
					t.Fatal(err)
				}
				mu.Lock()
				got = append([]string(nil), calls...)
				mu.Unlock()
				if !reflect.DeepEqual(got, []string{"create:probe", "start:probe"}) {
					t.Fatal(got)
				}
			}
		})
	}
}
