package controlapi

import (
	"context"
	"github.com/agent-substrate/substrate/internal/ateinterceptors"
	"github.com/agent-substrate/substrate/internal/resources"
	atev1alpha1 "github.com/agent-substrate/substrate/pkg/api/v1alpha1"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Independent package boundary: admit the exact compiler-produced template via
// ordinary RPC validation/defaulting/persistence, not a reconstructed fixture.
func TestCurrentKaimahiCompiledTemplateAdmission(t *testing.T) {
	p := os.Getenv("KMX_CODEX_ADMISSION_CAPTURE")
	if p == "" {
		t.Skip("explicit compiler-produced capture required")
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	template := &ateapipb.ActorTemplate{}
	if err = protojson.Unmarshal(raw, template); err != nil {
		t.Fatal(err)
	}
	persistence := newTestPersistence(t)
	ctx := context.Background()
	ns := template.GetMetadata().GetAtespace()
	if _, err = persistence.CreateAtespace(ctx, &ateapipb.Atespace{Metadata: &ateapipb.ResourceMetadata{Name: ns}}); err != nil {
		t.Fatal(err)
	}
	config := template.GetSandboxConfig()
	s := &RPCService{impl: newServiceImpl(persistence, nil), sandboxConfigLister: sandboxConfigListerFor(t, []*atev1alpha1.SandboxConfig{{ObjectMeta: metav1.ObjectMeta{Name: config.GetConfigName()}, Spec: atev1alpha1.SandboxConfigSpec{SandboxClass: atev1alpha1.SandboxClassMicroVM, Assets: testAssets()}}})}
	admitted, err := s.CreateActorTemplate(ctx, &ateapipb.CreateActorTemplateRequest{ActorTemplate: proto.CloneOf(template)})
	if err != nil {
		t.Fatal("exact compiler output refused by owning compute API", err)
	}
	retained, err := persistence.GetActorTemplate(ctx, resources.ActorTemplateRef{Atespace: ns, Name: admitted.GetMetadata().GetName()})
	if err != nil || retained.GetMetadata().GetUid() == "" {
		t.Fatal(retained, err)
	}
	if !proto.Equal(template.GetContainers()[0], retained.GetContainers()[0]) {
		t.Fatal("container mutated across native admission")
	}
	t.Log("CURRENT_RENDERED_COMPILED_TEMPLATE_NATIVE_API_ADMISSION_PASS no golden snapshot or Ready claimed")
}

// TestCurrentKaimahiTemplateControl serves real template RPCs backed by the
// native PostgreSQL store. It cannot create a golden snapshot or invent Ready.
func TestCurrentKaimahiTemplateControl(t *testing.T) {
	root := os.Getenv("KMX_TEMPLATE_CONTROL_ROOT")
	if root == "" {
		t.Skip("explicit private test socket required")
	}
	persistence := newTestPersistence(t)
	s := &RPCService{impl: newServiceImpl(persistence, nil), sandboxConfigLister: sandboxConfigListerFor(t, []*atev1alpha1.SandboxConfig{{ObjectMeta: metav1.ObjectMeta{Name: "microvm"}, Spec: atev1alpha1.SandboxConfigSpec{SandboxClass: atev1alpha1.SandboxClassMicroVM, Assets: testAssets()}}})}
	listener, err := net.Listen("unix", filepath.Join(root, "template-control.sock"))
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.ChainUnaryInterceptor(ateinterceptors.ServerUnaryInterceptor, ateinterceptors.RejectUnknownFieldsUnaryInterceptor))
	ateapipb.RegisterControlServer(server, s)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() { server.Stop(); listener.Close(); <-done }()
	if err = os.WriteFile(filepath.Join(root, "ready"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(100 * time.Second)
	defer deadline.Stop()
	for {
		if _, err = os.Stat(filepath.Join(root, "stop")); err == nil {
			return
		}
		select {
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-deadline.C:
			t.Fatal("bounded template control deadline")
		case <-time.After(50 * time.Millisecond):
		}
	}
}
