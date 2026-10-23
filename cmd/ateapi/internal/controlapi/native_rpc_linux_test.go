//go:build linux

package controlapi

import (
	"cloud.google.com/go/storage"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/agent-substrate/substrate/internal/objectstore"
	"google.golang.org/api/option"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store/storetest"
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/workercache"
	"github.com/agent-substrate/substrate/internal/ateinterceptors"
	"github.com/agent-substrate/substrate/internal/atelet"
	"github.com/agent-substrate/substrate/internal/proto/ateletpb"
	"github.com/agent-substrate/substrate/pkg/api/v1alpha1"
	listersv1alpha1 "github.com/agent-substrate/substrate/pkg/client/listers/api/v1alpha1"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

// TestNativeControlRPC serves the ordinary Control implementation, scheduler,
// PostgreSQL persistence and ActorWorkflow, dialing the real task-owned atelet.
// Only node discovery and sandbox asset configuration are supplied by the test.
// This does not deploy or alter a Kubernetes cluster.
func TestNativeControlRPC(t *testing.T) {
	root := os.Getenv("EXECUTION_CONTROL_NATIVE_ROOT")
	if root == "" {
		t.Skip("explicit native task resources required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Second)
	defer cancel()
	st, cleanup := storetest.SetupTestStore(t)
	defer cleanup()
	storetest.MustCreateAtespace(t, ctx, st, "native")
	data, err := os.ReadFile(filepath.Join(root, "atelet-ready.json"))
	if err != nil {
		t.Fatal(err)
	}
	var info struct {
		Image  string                         `json:"image"`
		Assets map[string]*ateletpb.AssetFile `json:"assets"`
	}
	if err = json.Unmarshal(data, &info); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "native-control-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Env []*ateapipb.EnvVar `json:"env"`
	}
	if err = json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	assets := map[string]v1alpha1.AssetFile{}
	for name, file := range info.Assets {
		assets[name] = v1alpha1.AssetFile{URL: file.Url, SHA256: file.Sha256}
	}
	index := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	if err = index.Add(&v1alpha1.SandboxConfig{ObjectMeta: metav1.ObjectMeta{Name: "native-microvm"}, Spec: v1alpha1.SandboxConfigSpec{SandboxClass: v1alpha1.SandboxClassMicroVM, Assets: map[string]map[string]v1alpha1.AssetFile{"amd64": assets}}}); err != nil {
		t.Fatal(err)
	}

	if os.Getenv("EXECUTION_CURRENT_GOLDEN") == "1" {
		if err = index.Add(&v1alpha1.SandboxConfig{ObjectMeta: metav1.ObjectMeta{Name: "microvm"}, Spec: v1alpha1.SandboxConfigSpec{SandboxClass: v1alpha1.SandboxClassMicroVM, Assets: map[string]map[string]v1alpha1.AssetFile{"amd64": assets}}}); err != nil {
			t.Fatal(err)
		}
	}
	configs := listersv1alpha1.NewSandboxConfigLister(index)
	template := &ateapipb.ActorTemplate{Metadata: &ateapipb.ResourceMetadata{Atespace: "native", Name: "toolchat"}, SandboxConfig: &ateapipb.SandboxConfig{SandboxClass: ateapipb.SandboxClass_SANDBOX_CLASS_MICROVM, ConfigName: "native-microvm"}, Containers: []*ateapipb.Container{{Name: "probe", Image: info.Image, Command: []string{"/probe"}, WakeupProbe: &ateapipb.ContainerWakeupProbe{HttpGet: &ateapipb.HTTPGetAction{Path: "/readyz", Port: 8081}, TimeoutSeconds: 20}, Env: config.Env, Resources: &ateapipb.Resources{Limits: []*ateapipb.Limits{{Name: "cpu", Quantity: "1"}, {Name: "memory", Quantity: "1Gi"}}}}}}
	if os.Getenv("EXECUTION_NATIVE_KAGENT_A2A") == "1" {
		projection := &ateapipb.ActorMetadataDataSource{Items: []*ateapipb.ActorMetadataItem{
			{Field: ateapipb.ActorMetadataField_ACTOR_METADATA_FIELD_NAME, Path: "name"},
			{Field: ateapipb.ActorMetadataField_ACTOR_METADATA_FIELD_ATESPACE, Path: "atespace"},
			{Field: ateapipb.ActorMetadataField_ACTOR_METADATA_FIELD_UID, Path: "uid"},
		}}
		source := &ateapipb.SystemInfoVolumeSource{DataSources: []*ateapipb.SystemInfoDataSource{{ActorMetadata: projection}}}
		template.Volumes = []*ateapipb.Volume{
			{Name: "data", DurableDir: &ateapipb.DurableDirVolumeSource{}},
			{Name: "identity", SystemInfo: source},
		}
		template.Containers[0].VolumeMounts = []*ateapipb.VolumeMount{{Name: "data", MountPath: "/data"}, {Name: "identity", MountPath: "/run/kagent/identity"}}
	}
	if os.Getenv("EXECUTION_CURRENT_GOLDEN") != "1" {
		_, err = st.CreateActorTemplate(ctx, template)
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = st.CreateWorker(ctx, &ateapipb.Worker{Metadata: &ateapipb.ResourceMetadata{Name: "native-worker"}, Labels: map[string]string{"kagent.dev/worker-pool-name": "default", "kagent.dev/worker-pool-namespace": "test"}, WorkerNamespace: "native", WorkerPool: "native", WorkerPod: "native-worker", WorkerPodUid: "11111111-1111-4111-8111-111111111111", NodeName: "native-node", Ips: []string{os.Getenv("EXECUTION_NATIVE_WORKER_IP")}, SandboxClass: "microvm", Status: &ateapipb.WorkerStatus{State: ateapipb.WorkerState_WORKER_STATE_ACTIVE, Capacity: &ateapipb.WorkerResources{Actors: 2}}})
	if err != nil {
		t.Fatal(err)
	}
	workers := workercache.New(st, time.Second)
	if err = workers.Start(ctx); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "native", Name: "atelet", UID: "22222222-2222-4222-8222-222222222222"}, Spec: corev1.PodSpec{NodeName: "native-node"}, Status: corev1.PodStatus{PodIP: "127.0.0.1", PodIPs: []corev1.PodIP{{IP: "127.0.0.1"}}, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	// A bounded TCP bridge exposes the ordinary atelet RPC on its declared port;
	// there are no canned Run/Terminate replies and no bypass of its image path.
	listen, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(atelet.DefaultPort)))
	if err != nil {
		t.Fatal(err)
	}
	bridgeDone := make(chan struct{})
	go func() {
		defer close(bridgeDone)
		for {
			in, err := listen.Accept()
			if err != nil {
				return
			}
			go func() {
				defer in.Close()
				out, err := net.DialTimeout("unix", filepath.Join(root, "atelet-rpc.sock"), 2*time.Second)
				if err != nil {
					return
				}
				defer out.Close()
				done := make(chan struct{})
				go func() { io.Copy(out, in); out.Close(); close(done) }()
				io.Copy(in, out)
				in.Close()
				<-done
			}()
		}
	}()
	defer func() { listen.Close(); <-bridgeDone }()
	dialer := NewAteletDialer(newTestAteletIndexer(t, pod), "", "", "", WithDialCredentials(func(string) (credentials.TransportCredentials, error) { return insecure.NewCredentials(), nil }))

	var objects objectstore.Store
	if os.Getenv("EXECUTION_CURRENT_GOLDEN") == "1" {
		client, e := storage.NewClient(ctx, option.WithoutAuthentication())
		if e != nil {
			t.Fatal(e)
		}
		defer client.Close()
		objects = objectstore.NewGCS(client)
	}
	service := NewRPCService(st, workers, configs, nil, nil, dialer, nil, "", 120*time.Second, nil, objects, "", nil, nil)
	if os.Getenv("EXECUTION_CURRENT_GOLDEN") == "1" {
		NewActorTemplateReconciler(st, service, 100*time.Millisecond).Start(ctx)
	}

	listener, err := net.Listen("unix", filepath.Join(root, "control-rpc.sock"))
	if err != nil {
		t.Fatal(err)
	}
	// Fixture receiver readiness is separate from guest readiness: don't return
	// the initial Resume to the public client until its native test endpoint exists.
	fixtureReady := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		result, err := handler(ctx, req)
		if err != nil {
			return result, err
		}
		if info.FullMethod == "/ateapi.Control/ResumeActor" && os.Getenv("EXECUTION_NATIVE_KAIMAHI") == "1" {
			deadline := time.NewTimer(10 * time.Second)
			defer deadline.Stop()
			for {
				if _, e := os.Stat(filepath.Join(root, "native-receiver-ready")); e == nil {
					break
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-deadline.C:
					return nil, fmt.Errorf("native receiver not ready")
				case <-time.After(5 * time.Millisecond):
				}
			}
		}
		return result, nil
	}
	options := []grpc.ServerOption{}
	if os.Getenv("EXECUTION_NATIVE_KAGENT") == "1" {
		cert, err := tls.LoadX509KeyPair(filepath.Join(root, "bundle.pem"), filepath.Join(root, "bundle.pem"))
		if err != nil {
			t.Fatal(err)
		}
		options = append(options, grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})))
	}
	options = append(options, grpc.ChainUnaryInterceptor(ateinterceptors.ServerUnaryInterceptor, ateinterceptors.RejectUnknownFieldsUnaryInterceptor, fixtureReady))
	server := grpc.NewServer(options...)
	ateapipb.RegisterControlServer(server, service)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() { server.Stop(); <-done }()
	if err = os.WriteFile(filepath.Join(root, "control-ready"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err = os.Stat(filepath.Join(root, "control-stop")); err == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}
