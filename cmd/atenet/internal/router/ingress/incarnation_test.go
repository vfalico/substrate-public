package ingress

import (
	"context"
	"github.com/agent-substrate/substrate/cmd/atenet/internal/router/extproc"
	"github.com/agent-substrate/substrate/internal/atenet"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
	"testing"
)

func TestExpectedIncarnationRoutesOnlyExactUID(t *testing.T) {
	client := &mockClient{resumeFn: func(context.Context, *ateapipb.ResumeActorRequest, ...grpc.CallOption) (*ateapipb.ResumeActorResponse, error) {
		return &ateapipb.ResumeActorResponse{Actor: &ateapipb.Actor{Metadata: &ateapipb.ResourceMetadata{Uid: "new-uid"}, Status: &ateapipb.ActorStatus{State: ateapipb.ActorState_ACTOR_STATE_RUNNING, WorkerAssignment: &ateapipb.WorkerAssignment{WorkerPodIps: []string{"10.0.0.52"}}}}}, nil
	}}
	resumes := 0
	original := client.resumeFn
	client.getFn = func(ctx context.Context, _ *ateapipb.GetActorRequest, opts ...grpc.CallOption) (*ateapipb.Actor, error) {
		r, e := original(ctx, nil, opts...)
		return r.GetActor(), e
	}
	client.resumeFn = func(ctx context.Context, r *ateapipb.ResumeActorRequest, opts ...grpc.CallOption) (*ateapipb.ResumeActorResponse, error) {
		resumes++
		return original(ctx, r, opts...)
	}
	for _, tc := range []struct {
		name, uid string
		ok        bool
	}{
		{"legacy", "", true}, {"exact", "new-uid", true}, {"replaced", "old-uid", false}, {"comma", "new-uid,old-uid", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := resumes
			md := requestMetadata("actor", "team-a")
			if tc.uid != "" {
				md.Headers[atenet.TargetActorUIDHeader] = tc.uid
			}
			result, err := New(client, ParkedRequestConfig{}, nil).HandleRequestHeaders(context.Background(), md)
			if tc.uid != "" && resumes != before {
				t.Fatal("pinned route resumed compute")
			}
			if (err == nil) != tc.ok {
				t.Fatal(err)
			}
			if tc.ok && tc.uid != "" {
				found := false
				for _, header := range result.Response.Response.HeaderMutation.SetHeaders {
					if header.Header.Key == atenet.TargetActorUIDHeader && string(header.Header.RawValue) == tc.uid {
						found = true
					}
				}
				if !found {
					t.Fatal("UID precondition lost at worker hop")
				}
			}
		})
	}
}
func TestExpectedIncarnationUsesOuterConnectAuthority(t *testing.T) {
	client := &mockClient{resumeFn: func(context.Context, *ateapipb.ResumeActorRequest, ...grpc.CallOption) (*ateapipb.ResumeActorResponse, error) {
		return &ateapipb.ResumeActorResponse{Actor: &ateapipb.Actor{Metadata: &ateapipb.ResourceMetadata{Uid: "new-uid"}, Status: &ateapipb.ActorStatus{State: ateapipb.ActorState_ACTOR_STATE_RUNNING, WorkerAssignment: &ateapipb.WorkerAssignment{WorkerPodIps: []string{"10.0.0.52"}}}}}, nil
	}}
	client.getFn = func(ctx context.Context, _ *ateapipb.GetActorRequest, opts ...grpc.CallOption) (*ateapipb.Actor, error) {
		r, e := client.resumeFn(ctx, nil, opts...)
		return r.GetActor(), e
	}
	attrs, _ := structpb.NewStruct(map[string]any{extproc.TargetActorFilterStateAttribute: "team-a/actor", extproc.ConnectAuthorityFilterStateAttribute: "actor:80", extproc.TargetActorUIDFilterStateAttribute: "old-uid"})
	md := extproc.NewRequestMetadata([]*corev3.HeaderValue{{Key: atenet.TargetActorUIDHeader, Value: "new-uid"}}, map[string]*structpb.Struct{"ingress": attrs})
	if _, err := New(client, ParkedRequestConfig{}, nil).HandleRequestHeaders(context.Background(), md); err == nil {
		t.Fatal("inner header replaced outer UID")
	}
}
