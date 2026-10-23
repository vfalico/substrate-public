//go:build linux

package controlapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
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
	if err = index.Add(&v1alpha1.SandboxConfig{ObjectMeta: metav1.ObjectMeta{Name: "native-microvm"}, Spec: v1alpha1.SandboxConfigSpec{SandboxClass: v1alpha1.SandboxClassMicroVM, DefaultVersion: "native-v1", Versions: []v1alpha1.SandboxVersionConfig{{Name: "native-v1", Assets: map[string]map[string]v1alpha1.AssetFile{"amd64": assets}}}}}); err != nil {
		t.Fatal(err)
	}
	configs := listersv1alpha1.NewSandboxConfigLister(index)
	_, err = st.CreateActorTemplate(ctx, &ateapipb.ActorTemplate{Metadata: &ateapipb.ResourceMetadata{Atespace: "native", Name: "toolchat"}, SandboxConfig: &ateapipb.SandboxConfig{SandboxClass: ateapipb.SandboxClass_SANDBOX_CLASS_MICROVM, ConfigName: "native-microvm"}, Containers: []*ateapipb.Container{{Name: "probe", Image: info.Image, Command: []string{"/probe"}, WakeupProbe: &ateapipb.ContainerWakeupProbe{HttpGet: &ateapipb.HTTPGetAction{Path: "/readyz", Port: 8081}, TimeoutSeconds: 20}, Env: config.Env, Resources: &ateapipb.Resources{Limits: []*ateapipb.Limits{{Name: "cpu", Quantity: "1"}, {Name: "memory", Quantity: "1Gi"}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.CreateWorker(ctx, &ateapipb.Worker{Metadata: &ateapipb.ResourceMetadata{Name: "native-worker"}, WorkerNamespace: "native", WorkerPool: "native", WorkerPod: "native-worker", WorkerPodUid: "11111111-1111-4111-8111-111111111111", NodeName: "native-node", Ips: []string{os.Getenv("EXECUTION_NATIVE_WORKER_IP")}, SandboxClass: "microvm", Status: &ateapipb.WorkerStatus{State: ateapipb.WorkerState_WORKER_STATE_ACTIVE, Capacity: &ateapipb.WorkerResources{Actors: 2}}})
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
	service := NewRPCService(st, workers, configs, nil, nil, dialer, nil, "", nil, nil, "", nil, nil)
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
		if info.FullMethod == "/ateapi.Control/CreateActor" && os.Getenv("EXECUTION_PUBLIC_NATIVE_SCENARIO") == "lost-create" {
			request, ok := req.(*ateapipb.CreateActorRequest)
			if !ok {
				return nil, fmt.Errorf("unexpected create request %T", req)
			}
			if request.GetOperationId() != "" && !request.GetLookupOnly() && !request.GetRetireOperation() {
				actor, ok := result.(*ateapipb.Actor)
				if !ok {
					return nil, fmt.Errorf("unexpected create response %T", result)
				}
				if actor.GetStatus().GetState() != ateapipb.ActorState_ACTOR_STATE_SUSPENDED {
					return nil, fmt.Errorf("created native Actor not suspended")
				}
				raw, e := json.Marshal(map[string]string{"name": actor.GetMetadata().GetName(), "uid": actor.GetMetadata().GetUid(), "operation_id": request.GetOperationId(), "fault": "lost committed suspended Create reply"})
				if e != nil {
					return nil, e
				}
				if e = os.WriteFile(filepath.Join(root, "injected-lost-create.json"), raw, 0600); e != nil {
					return nil, e
				}
				t.Logf("INJECTED_LOST_REAL_SUSPENDED_CREATE_REPLY name=%s uid=%s operation=%s", actor.GetMetadata().GetName(), actor.GetMetadata().GetUid(), request.GetOperationId())
				return nil, status.Error(codes.Unavailable, "injected lost committed suspended Create reply")
			}
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
		if info.FullMethod == "/ateapi.Control/ResumeActor" && os.Getenv("EXECUTION_PUBLIC_NATIVE_SCENARIO") == "lost-resume" {
			// Deliberate transport fault AFTER ordinary owning workflow, activation,
			// real native boot and receiver readiness. Never changes returned state.
			response, ok := result.(*ateapipb.ResumeActorResponse)
			if !ok {
				return nil, fmt.Errorf("unexpected native resume response %T", result)
			}
			actor := response.GetActor()
			raw, e := json.Marshal(map[string]string{"name": actor.GetMetadata().GetName(), "uid": actor.GetMetadata().GetUid(), "fault": "lost successful native Resume reply"})
			if e != nil {
				return nil, e
			}
			if e = os.WriteFile(filepath.Join(root, "injected-lost-resume.json"), raw, 0600); e != nil {
				return nil, e
			}
			t.Logf("INJECTED_LOST_REAL_NATIVE_RESUME_REPLY name=%s uid=%s", actor.GetMetadata().GetName(), actor.GetMetadata().GetUid())
			return nil, status.Error(codes.Unavailable, "injected lost successful native Resume reply")
		}
		return result, nil
	}
	server := grpc.NewServer(grpc.ChainUnaryInterceptor(ateinterceptors.ServerUnaryInterceptor, ateinterceptors.RejectUnknownFieldsUnaryInterceptor, fixtureReady))
	ateapipb.RegisterControlServer(server, service)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() { server.Stop(); <-done }()

	// Optional ordinary-daemon qualification transport. The same real Control
	// implementation and workflow are served with verified TLS and an explicit
	// fixture bearer, not a canned RPC endpoint or policy exemption.
	if os.Getenv("EXECUTION_CONTROL_PUBLIC_TLS") == "1" {
		key, e := rsa.GenerateKey(rand.Reader, 2048)
		if e != nil {
			t.Fatal(e)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(807), Subject: pkix.Name{CommonName: "control.native.test"}, DNSNames: []string{"control.native.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		pair, e := tls.X509KeyPair(certPEM, keyPEM)
		if e != nil {
			t.Fatal(e)
		}
		tokenRaw := make([]byte, 32)
		if _, e = rand.Read(tokenRaw); e != nil {
			t.Fatal(e)
		}
		token := fmt.Sprintf("%x", tokenRaw)
		caPath := filepath.Join(root, "control-fixture-ca.pem")
		tokenPath := filepath.Join(root, "control-fixture-token")
		if e = os.WriteFile(caPath, certPEM, 0600); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(tokenPath, []byte(token), 0600); e != nil {
			t.Fatal(e)
		}
		authenticate := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			md, _ := metadata.FromIncomingContext(ctx)
			values := md.Get("authorization")
			if len(values) != 1 || values[0] != "Bearer "+token {
				return nil, status.Error(codes.Unauthenticated, "fixture Control token required")
			}
			return handler(ctx, req)
		}
		tcp, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		secure := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}})), grpc.ChainUnaryInterceptor(authenticate, ateinterceptors.ServerUnaryInterceptor, ateinterceptors.RejectUnknownFieldsUnaryInterceptor, fixtureReady))
		ateapipb.RegisterControlServer(secure, service)
		secureDone := make(chan error, 1)
		go func() { secureDone <- secure.Serve(tcp) }()
		defer func() { secure.Stop(); <-secureDone }()
		raw, e := json.Marshal(map[string]string{"address": tcp.Addr().String(), "serverName": "control.native.test", "caFile": caPath, "tokenFile": tokenPath})
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(root, "control-tls-ready.json"), raw, 0600); e != nil {
			t.Fatal(e)
		}
		t.Log("NATIVE_CONTROL_TLS_TOKEN_LISTENER_READY", tcp.Addr().String())
	}
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
