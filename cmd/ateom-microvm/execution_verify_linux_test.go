//go:build linux

package main

import (
	"context"
	"github.com/agent-substrate/substrate/internal/actorlock"
	"github.com/agent-substrate/substrate/internal/proto/ateompb"
	"testing"
)

func TestVerifyExecutionCannotTrustMissingNativeActor(t *testing.T) {
	s := &AteomService{locks: actorlock.New()}
	for _, r := range []*ateompb.VerifyExecutionRequest{{}, {ActorUid: "exact", Atespace: "native", ActorName: "owned", ExecutionRequirement: []byte(`{"opaque":true}`)}} {
		if _, err := s.VerifyExecution(context.Background(), r); err == nil {
			t.Fatal("absent exact native actor admitted")
		}
	}
}
