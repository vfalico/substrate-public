package atepg

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func TestCreateActorOperationOriginalAuthoritySurvivesDeletionAndReplacement(t *testing.T) {
	p := setupPostgresPersistence(t)
	ctx := context.Background()
	createTestAtespace(t, p, "owner-space")
	actor := &ateapipb.Actor{Metadata: &ateapipb.ResourceMetadata{Atespace: "owner-space", Name: "owned"}, ActorTemplate: &ateapipb.ObjectRef{Atespace: "default", Name: "template"}, Status: &ateapipb.ActorStatus{State: ateapipb.ActorState_ACTOR_STATE_SUSPENDED}, ExecutionRequirement: []byte(`{"opaque":true}`)}
	frozen := proto.CloneOf(actor)
	hash := sha256.Sum256([]byte("normalized request"))
	op := uuid.NewString()
	first, err := p.CreateActorOperation(ctx, actor, op, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	if first.GetMetadata().GetUid() == "" || !proto.Equal(actor, frozen) {
		t.Fatal("missing original UID or input mutation")
	}
	// Two independently scheduled overlapping retries must observe ONE original
	// create response; no policy composition, current status or activation implied.
	var wg sync.WaitGroup
	results := make(chan *ateapipb.Actor, 12)
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, e := p.CreateActorOperation(ctx, proto.CloneOf(actor), op, hash[:])
			if e != nil {
				errs <- e
				return
			}
			results <- a
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	for a := range results {
		if !proto.Equal(a, first) {
			t.Error("retry changed original authority")
		}
	}
	changed := hash
	changed[0] ^= 1
	if _, e := p.CreateActorOperation(ctx, actor, op, changed[:]); !errors.Is(e, store.ErrFailedPrecondition) {
		t.Fatalf("changed hash replay=%v", e)
	}
	other := proto.CloneOf(actor)
	other.Metadata.Name = "unrelated"
	if _, e := p.CreateActorOperation(ctx, other, op, hash[:]); !errors.Is(e, store.ErrFailedPrecondition) {
		t.Fatalf("changed target replay=%v", e)
	}
	ref := resources.ActorRefFromActor(first)
	if _, err = p.DeleteActor(ctx, ref, store.DeletePreconditions{UID: first.GetMetadata().GetUid(), Version: first.GetMetadata().GetVersion()}); err != nil {
		t.Fatal(err)
	}
	// Post-target-deletion retry returns ORIGINAL identity, never recreates.
	replay, err := p.CreateActorOperation(ctx, actor, op, hash[:])
	if err != nil || !proto.Equal(replay, first) {
		t.Fatalf("post-delete retry=%v %v", replay, err)
	}
	if _, e := p.GetActor(ctx, ref); !errors.Is(e, store.ErrNotFound) {
		t.Fatalf("replay recreated compute: %v", e)
	}
	replacement, err := p.CreateActor(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.GetMetadata().GetUid() == first.GetMetadata().GetUid() {
		t.Fatal("fixture did not replace UID")
	}
	replay, err = p.CreateActorOperation(ctx, actor, op, hash[:])
	if err != nil || !proto.Equal(replay, first) {
		t.Fatalf("replacement stole old authority: %v %v", replay, err)
	}
	current, err := p.GetActor(ctx, ref)
	if err != nil || !proto.Equal(current, replacement) {
		t.Fatal("replacement modified", err)
	}
	// A new operation cannot adopt this occupied name, and its rolled-back row
	// must not prevent unrelated later use of that same operation token.
	op2 := uuid.NewString()
	if _, e := p.CreateActorOperation(ctx, actor, op2, hash[:]); !errors.Is(e, store.ErrAlreadyExists) {
		t.Fatalf("new operation adopted occupied name: %v", e)
	}
	if _, e := p.CreateActorOperation(ctx, other, op2, hash[:]); e != nil {
		t.Fatal("failed create stranded operation", e)
	}
}

func TestCreateActorOperationRefusesInvalidOrUnsuspendedInput(t *testing.T) {
	p := setupPostgresPersistence(t)
	createTestAtespace(t, p, "owner-space")
	actor := &ateapipb.Actor{Metadata: &ateapipb.ResourceMetadata{Atespace: "owner-space", Name: "held"}, Status: &ateapipb.ActorStatus{State: ateapipb.ActorState_ACTOR_STATE_SUSPENDED}}
	hash := sha256.Sum256([]byte("original"))
	for _, c := range []struct {
		id      string
		hash    []byte
		running bool
	}{{"bad", hash[:], false}, {uuid.NewString(), nil, false}, {uuid.NewString(), hash[:], true}} {
		a := proto.CloneOf(actor)
		if c.running {
			a.Status.State = ateapipb.ActorState_ACTOR_STATE_RUNNING
		}
		if _, e := p.CreateActorOperation(t.Context(), a, c.id, c.hash); !errors.Is(e, store.ErrFailedPrecondition) {
			t.Fatalf("unsafe input accepted: %v", e)
		}
	}
}
