//go:build linux

package main

import (
	"context"
	"fmt"
	"github.com/agent-substrate/substrate/internal/proto/ateompb"
)

// VerifyExecution holds the native lifecycle lock through exact handle readback.
func (s *AteomService) VerifyExecution(ctx context.Context, r *ateompb.VerifyExecutionRequest) (*ateompb.VerifyExecutionResponse, error) {
	if r.GetActorUid() == "" || r.GetAtespace() == "" || r.GetActorName() == "" || len(r.GetExecutionRequirement()) == 0 {
		return nil, fmt.Errorf("complete exact actor execution identity required")
	}
	if !s.locks.Lock(ctx, r.GetActorUid()) {
		return nil, ctx.Err()
	}
	defer s.locks.Unlock(r.GetActorUid())
	hosted := s.lookupActor(r.GetActorUid())
	vm := s.runningVM(r.GetActorUid())
	if hosted == nil || hosted.attribution.Ref.Atespace != r.GetAtespace() || hosted.attribution.Ref.Name != r.GetActorName() || vm == nil || vm.chCmd == nil || vm.chCmd.Process == nil {
		return nil, fmt.Errorf("exact live native Actor unavailable")
	}
	c, err := s.executionClient()
	if err != nil {
		return nil, err
	}
	if c.Config.GuestPort != 0 {
		err = c.LookupGuest(ctx, r.GetActorUid(), r.GetExecutionRequirement())
	} else {
		err = c.Verify(ctx, r.GetActorUid(), r.GetExecutionRequirement())
	}
	if err != nil {
		return nil, err
	}
	return &ateompb.VerifyExecutionResponse{Active: true}, nil
}
