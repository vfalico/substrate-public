package controlapi

import (
	"context"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"testing"
)

func TestVerifyActorExecutionRejectsIncompleteIdentityBeforeLookup(t *testing.T) {
	s := &RPCService{}
	for _, r := range []*ateapipb.VerifyActorExecutionRequest{nil, {}, {Actor: &ateapipb.ObjectRef{Name: "owned", Atespace: "native"}}, {Actor: &ateapipb.ObjectRef{Name: "owned", Atespace: "native"}, ActorUid: "exact"}, {Actor: &ateapipb.ObjectRef{Name: "owned"}, ActorUid: "exact", ExecutionRequirement: []byte("opaque")}} {
		if _, err := s.VerifyActorExecution(context.Background(), r); err == nil {
			t.Fatal("incomplete exact request admitted")
		}
	}
}
