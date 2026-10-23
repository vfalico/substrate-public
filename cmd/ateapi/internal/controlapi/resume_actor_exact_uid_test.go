package controlapi

import (
	"context"
	"testing"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/internal/apierror"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
)

// Explicit store double: panic on any unimplemented side effect. The second
// read models replacement between the advisory running check and Actor lease.
type exactResumeStore struct {
	store.Interface
	actors                []*ateapipb.Actor
	reads, leases, closes int
}

func (s *exactResumeStore) GetActor(context.Context, resources.ActorRef) (*ateapipb.Actor, error) {
	i := s.reads
	s.reads++
	if i >= len(s.actors) {
		i = len(s.actors) - 1
	}
	return proto.Clone(s.actors[i]).(*ateapipb.Actor), nil
}
func (s *exactResumeStore) AcquireLease(ctx context.Context, _ string) (*store.Lease, error) {
	s.leases++
	return store.NewLease(ctx, func() { s.closes++ }), nil
}
func exactResumeActor(uid string, state ateapipb.ActorState) *ateapipb.Actor {
	return &ateapipb.Actor{Metadata: &ateapipb.ResourceMetadata{Atespace: "native", Name: "reused", Uid: uid}, Status: &ateapipb.ActorStatus{State: state}}
}
func TestResumeActorExactUIDBeforeSideEffects(t *testing.T) {
	for _, scenario := range []string{"running-replacement", "suspended-replacement", "replacement-under-lease-running", "replacement-under-lease-suspended", "exact-running", "legacy-running"} {
		t.Run(scenario, func(t *testing.T) {
			expected := "original"
			st := &exactResumeStore{}
			wantCode := codes.Aborted
			wantLeases := 0
			switch scenario {
			case "running-replacement":
				st.actors = []*ateapipb.Actor{exactResumeActor("replacement", ateapipb.ActorState_ACTOR_STATE_RUNNING)}
			case "suspended-replacement":
				st.actors = []*ateapipb.Actor{exactResumeActor("replacement", ateapipb.ActorState_ACTOR_STATE_SUSPENDED)}
			case "replacement-under-lease-running":
				st.actors = []*ateapipb.Actor{exactResumeActor("original", ateapipb.ActorState_ACTOR_STATE_SUSPENDED), exactResumeActor("replacement", ateapipb.ActorState_ACTOR_STATE_RUNNING)}
				wantLeases = 1
			case "replacement-under-lease-suspended":
				st.actors = []*ateapipb.Actor{exactResumeActor("original", ateapipb.ActorState_ACTOR_STATE_SUSPENDED), exactResumeActor("replacement", ateapipb.ActorState_ACTOR_STATE_SUSPENDED)}
				wantLeases = 1
			case "exact-running":
				st.actors = []*ateapipb.Actor{exactResumeActor("original", ateapipb.ActorState_ACTOR_STATE_RUNNING)}
				wantCode = codes.OK
			case "legacy-running":
				st.actors = []*ateapipb.Actor{exactResumeActor("replacement", ateapipb.ActorState_ACTOR_STATE_RUNNING)}
				expected = ""
				wantCode = codes.OK
			}
			w := &ActorWorkflow{store: st}
			actor, resumed, err := w.ResumeActorExact(context.Background(), resources.ActorRef{Atespace: "native", Name: "reused"}, expected)
			if apierror.Code(err) != wantCode {
				t.Fatalf("wrong code: %v", err)
			}
			if resumed {
				t.Fatal("unexpected dispatch")
			}
			if wantCode == codes.Aborted && actor != nil {
				t.Fatal("replacement returned as authority")
			}
			if wantCode == codes.OK && actor == nil {
				t.Fatal("lost observational fast path")
			}
			if st.leases != wantLeases || st.closes != wantLeases {
				t.Fatalf("lease lifecycle %d/%d want%d", st.leases, st.closes, wantLeases)
			}
		})
	}
}
