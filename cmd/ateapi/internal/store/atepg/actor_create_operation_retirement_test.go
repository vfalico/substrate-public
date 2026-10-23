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
)

func TestCreateActorOperationRetirementWinsBeforeDelayedCreate(t *testing.T) {
	p := setupPostgresPersistence(t)
	createTestAtespace(t, p, "cancel-space")
	actor := &ateapipb.Actor{Metadata: &ateapipb.ResourceMetadata{Atespace: "cancel-space", Name: "held"}, Status: &ateapipb.ActorStatus{State: ateapipb.ActorState_ACTOR_STATE_SUSPENDED}}
	hash := sha256.Sum256([]byte("original"))
	op := uuid.NewString()
	original, e := p.RetireActorCreateOperation(t.Context(), "cancel-space", "held", op, hash[:])
	if e != nil || original != nil {
		t.Fatal("cancel failed", original, e)
	}
	for i := 0; i < 3; i++ {
		if _, e = p.CreateActorOperation(t.Context(), actor, op, hash[:]); !errors.Is(e, store.ErrFailedPrecondition) {
			t.Fatalf("delayed create passed tombstone: %v", e)
		}
		original, e = p.RetireActorCreateOperation(t.Context(), "cancel-space", "held", op, hash[:])
		if e != nil || original != nil {
			t.Fatal("retirement not monotonic", original, e)
		}
	}
	if _, e = p.GetActor(t.Context(), resources.ActorRef{Atespace: "cancel-space", Name: "held"}); !errors.Is(e, store.ErrNotFound) {
		t.Fatal("cancel created target", e)
	}
}

func TestCreateActorOperationConcurrentRetirementCannotLoseCompute(t *testing.T) {
	p := setupPostgresPersistence(t)
	createTestAtespace(t, p, "cancel-space")
	hash := sha256.Sum256([]byte("original"))
	for i := 0; i < 12; i++ {
		name := "held-" + uuid.NewString()
		op := uuid.NewString()
		actor := &ateapipb.Actor{Metadata: &ateapipb.ResourceMetadata{Atespace: "cancel-space", Name: name}, Status: &ateapipb.ActorStatus{State: ateapipb.ActorState_ACTOR_STATE_SUSPENDED}}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		var created, retired *ateapipb.Actor
		var ce, re error
		go func() {
			defer wg.Done()
			<-start
			created, ce = p.CreateActorOperation(context.Background(), actor, op, hash[:])
		}()
		go func() {
			defer wg.Done()
			<-start
			retired, re = p.RetireActorCreateOperation(context.Background(), "cancel-space", name, op, hash[:])
		}()
		close(start)
		wg.Wait()
		if re != nil {
			t.Fatal(re)
		}
		if retired == nil {
			if !errors.Is(ce, store.ErrFailedPrecondition) {
				t.Fatalf("cancel won but create committed: %v %v", created, ce)
			}
			if _, e := p.GetActor(t.Context(), resources.ActorRef{Atespace: "cancel-space", Name: name}); !errors.Is(e, store.ErrNotFound) {
				t.Fatal("cancel lost compute", e)
			}
		} else {
			if ce != nil || created.GetMetadata().GetUid() != retired.GetMetadata().GetUid() {
				t.Fatalf("cleanup lost original UID: created=%v retired=%v err=%v", created, retired, ce)
			}
		}
	}
}

func TestCommittedCreateOperationRetirementIrrevocablyRefusesRetry(t *testing.T) {
	p := setupPostgresPersistence(t)
	createTestAtespace(t, p, "cancel-space")
	actor := &ateapipb.Actor{Metadata: &ateapipb.ResourceMetadata{Atespace: "cancel-space", Name: "held"}, Status: &ateapipb.ActorStatus{State: ateapipb.ActorState_ACTOR_STATE_SUSPENDED}}
	hash := sha256.Sum256([]byte("original"))
	op := uuid.NewString()
	first, e := p.CreateActorOperation(t.Context(), actor, op, hash[:])
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 3; i++ {
		retired, e := p.RetireActorCreateOperation(t.Context(), "cancel-space", "held", op, hash[:])
		if e != nil || retired.GetMetadata().GetUid() != first.GetMetadata().GetUid() {
			t.Fatal("lost cleanup identity", retired, e)
		}
		if _, e = p.CreateActorOperation(t.Context(), actor, op, hash[:]); !errors.Is(e, store.ErrFailedPrecondition) {
			t.Fatal("retired operation allowed creating replay", e)
		}
		if _, e = p.LookupActorCreateOperation(t.Context(), "cancel-space", "held", op, hash[:]); !errors.Is(e, store.ErrFailedPrecondition) {
			t.Fatal("retired operation allowed admission lookup", e)
		}
	}
}
