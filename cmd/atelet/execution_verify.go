package main

import (
	"context"
	"fmt"
	"github.com/agent-substrate/substrate/internal/proto/ateletpb"
	"github.com/agent-substrate/substrate/internal/proto/ateompb"
)

func (s *AteomHerder) VerifyExecution(ctx context.Context, r *ateletpb.VerifyExecutionRequest) (*ateletpb.VerifyExecutionResponse, error) {
	if r.GetWorkerPodUid() == "" || r.GetActorUid() == "" || r.GetAtespace() == "" || r.GetActorName() == "" || len(r.GetExecutionRequirement()) == 0 {
		return nil, fmt.Errorf("complete exact actor execution identity required")
	}
	client, err := s.dialAteom(ctx, r.GetWorkerPodUid())
	if err != nil {
		return nil, err
	}
	response, err := client.VerifyExecution(ctx, &ateompb.VerifyExecutionRequest{Atespace: r.GetAtespace(), ActorName: r.GetActorName(), ActorUid: r.GetActorUid(), ExecutionRequirement: r.GetExecutionRequirement()})
	if err != nil {
		return nil, err
	}
	if !response.GetActive() {
		return nil, fmt.Errorf("owning compute did not prove current enforcement")
	}
	return &ateletpb.VerifyExecutionResponse{Active: true}, nil
}
