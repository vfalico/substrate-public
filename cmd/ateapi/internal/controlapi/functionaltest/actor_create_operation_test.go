package functionaltest

import (
	"testing"

	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Real public gRPC, PostgreSQL and envtest; fake worker never resumes. This
// proves suspended creation/identity replay, not native enforcement activation.
func TestCreateActorOperationPublicReplayNeverAdoptsReplacement(t *testing.T) {
	ns := namespaceForTest("ns-create-operation")
	tc := setupTest(t, ns)
	defer tc.cleanup()
	createTemplate(t, tc, ns)
	request := &ateapipb.CreateActorRequest{OperationId: uuid.NewString(), Actor: &ateapipb.Actor{Metadata: &ateapipb.ResourceMetadata{Atespace: testAtespace, Name: "owned"}, ActorTemplate: &ateapipb.ObjectRef{Atespace: testAtespace, Name: "tmpl1"}, ExecutionRequirement: []byte(`{"opaque":"unchanged"}`)}}
	lookup := proto.CloneOf(request)
	lookup.LookupOnly = true
	if _, e := tc.client.CreateActor(t.Context(), lookup); status.Code(e) != codes.NotFound {
		t.Fatalf("uncommitted lookup must not create: %v", e)
	}
	// Exact source remains frozen; gRPC serializes independent request instances.
	first, err := tc.client.CreateActor(t.Context(), proto.CloneOf(request))
	if err != nil {
		t.Fatal(err)
	}
	if first.GetMetadata().GetUid() == "" || first.GetStatus().GetState() != ateapipb.ActorState_ACTOR_STATE_SUSPENDED {
		t.Fatal("not server-owned suspended compute", first)
	}
	recovered, e := tc.client.CreateActor(t.Context(), lookup)
	if e != nil || !proto.Equal(recovered, first) {
		t.Fatalf("lookup lost original: %v %v", recovered, e)
	}
	again, err := tc.client.CreateActor(t.Context(), proto.CloneOf(request))
	if err != nil || !proto.Equal(again, first) {
		t.Fatalf("replay changed original: %v %v", again, err)
	}
	changed := proto.CloneOf(request)
	changed.Actor.ExecutionRequirement = []byte(`{"opaque":"changed"}`)
	if _, err = tc.client.CreateActor(t.Context(), changed); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("changed input accepted: %v", err)
	}
	if _, err = tc.client.DeleteActor(t.Context(), &ateapipb.DeleteActorRequest{Actor: &ateapipb.ObjectRef{Atespace: testAtespace, Name: "owned"}, Options: &ateapipb.DeleteOptions{Uid: first.GetMetadata().GetUid()}}); err != nil {
		t.Fatal(err)
	}
	// Target deletion cannot erase the create operation or let retry recreate.
	again, err = tc.client.CreateActor(t.Context(), proto.CloneOf(request))
	if err != nil || !proto.Equal(again, first) {
		t.Fatalf("post-delete replay=%v %v", again, err)
	}
	if _, err = tc.client.GetActor(t.Context(), &ateapipb.GetActorRequest{Actor: &ateapipb.ObjectRef{Atespace: testAtespace, Name: "owned"}}); status.Code(err) != codes.NotFound {
		t.Fatalf("replay recreated compute: %v", err)
	}
	replacementReq := proto.CloneOf(request)
	replacementReq.OperationId = ""
	replacement, err := tc.client.CreateActor(t.Context(), replacementReq)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.GetMetadata().GetUid() == first.GetMetadata().GetUid() {
		t.Fatal("not a real replacement")
	}
	again, err = tc.client.CreateActor(t.Context(), proto.CloneOf(request))
	if err != nil || !proto.Equal(again, first) {
		t.Fatalf("replacement adopted: %v %v", again, err)
	}
	invalid := proto.CloneOf(request)
	invalid.OperationId = "not-a-uuid"
	if _, err = tc.client.CreateActor(t.Context(), invalid); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid operation accepted: %v", err)
	}
}

func TestCreateActorOperationPublicRetirementPreventsDelayedCreate(t *testing.T) {
	ns := namespaceForTest("ns-cancel-operation")
	tc := setupTest(t, ns)
	defer tc.cleanup()
	createTemplate(t, tc, ns)
	req := &ateapipb.CreateActorRequest{OperationId: uuid.NewString(), Actor: &ateapipb.Actor{Metadata: &ateapipb.ResourceMetadata{Atespace: testAtespace, Name: "held"}, ActorTemplate: &ateapipb.ObjectRef{Atespace: testAtespace, Name: "tmpl1"}}}
	cancel := proto.CloneOf(req)
	cancel.RetireOperation = true
	reply, e := tc.client.CreateActor(t.Context(), cancel)
	if e != nil || reply.GetMetadata().GetUid() != "" {
		t.Fatal("retirement did not cancel", reply, e)
	}
	if _, e = tc.client.CreateActor(t.Context(), proto.CloneOf(req)); status.Code(e) != codes.FailedPrecondition {
		t.Fatal("delayed create passed cancellation", e)
	}
	reply, e = tc.client.CreateActor(t.Context(), cancel)
	if e != nil || reply.GetMetadata().GetUid() != "" {
		t.Fatal("retirement not monotonic", reply, e)
	}
	if _, e = tc.client.GetActor(t.Context(), &ateapipb.GetActorRequest{Actor: &ateapipb.ObjectRef{Atespace: testAtespace, Name: "held"}}); status.Code(e) != codes.NotFound {
		t.Fatal("cancel created compute", e)
	}
}

func TestCommittedCreateOperationPublicRetirementRevokesAdmission(t *testing.T) {
	ns := namespaceForTest("ns-retire-committed")
	tc := setupTest(t, ns)
	defer tc.cleanup()
	createTemplate(t, tc, ns)
	req := &ateapipb.CreateActorRequest{OperationId: uuid.NewString(), Actor: &ateapipb.Actor{Metadata: &ateapipb.ResourceMetadata{Atespace: testAtespace, Name: "held"}, ActorTemplate: &ateapipb.ObjectRef{Atespace: testAtespace, Name: "tmpl1"}}}
	first, e := tc.client.CreateActor(t.Context(), proto.CloneOf(req))
	if e != nil {
		t.Fatal(e)
	}
	retire := proto.CloneOf(req)
	retire.RetireOperation = true
	for i := 0; i < 2; i++ {
		old, e := tc.client.CreateActor(t.Context(), proto.CloneOf(retire))
		if e != nil || old.GetMetadata().GetUid() != first.GetMetadata().GetUid() {
			t.Fatal("retirement lost original", old, e)
		}
		if _, e = tc.client.ResumeActor(t.Context(), &ateapipb.ResumeActorRequest{Actor: &ateapipb.ObjectRef{Atespace: testAtespace, Name: "held"}, ActorUid: first.GetMetadata().GetUid()}); status.Code(e) != codes.FailedPrecondition {
			t.Fatal("retirement allowed delayed resume", e)
		}
		if _, e = tc.client.CreateActor(t.Context(), proto.CloneOf(req)); status.Code(e) != codes.FailedPrecondition {
			t.Fatal("retired original admitted", e)
		}
		lookup := proto.CloneOf(req)
		lookup.LookupOnly = true
		if _, e = tc.client.CreateActor(t.Context(), lookup); status.Code(e) != codes.FailedPrecondition {
			t.Fatal("retired original lookup admitted", e)
		}
	}
}
