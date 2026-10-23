package controlapi

import (
	"bytes"
	"context"
	"fmt"
	"github.com/agent-substrate/substrate/internal/proto/ateletpb"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
)

// Exact current read under the same distributed Actor lease as delete/resume.
func (s *RPCService) VerifyActorExecution(ctx context.Context, r *ateapipb.VerifyActorExecutionRequest) (*ateapipb.VerifyActorExecutionResponse, error) {
	if r.GetActor().GetAtespace() == "" || r.GetActor().GetName() == "" || r.GetActorUid() == "" || len(r.GetExecutionRequirement()) == 0 {
		return nil, fmt.Errorf("complete exact Actor requirement identity required")
	}
	ref := resources.ActorRefFromObjectRef(r.GetActor())
	leaseCtx, lease, err := s.actorWorkflow.acquireActorLease(ctx, ref)
	if err != nil {
		return nil, err
	}
	defer lease.Close()
	actor, err := s.impl.GetActor(leaseCtx, ref)
	if err != nil {
		return nil, err
	}
	if actor.GetMetadata().GetUid() != r.GetActorUid() || actor.GetStatus().GetState() != ateapipb.ActorState_ACTOR_STATE_RUNNING || !bytes.Equal(actor.GetExecutionRequirement(), r.GetExecutionRequirement()) {
		return nil, fmt.Errorf("exact running Actor requirement differs")
	}
	assignment := actor.GetStatus().GetWorkerAssignment()
	if assignment.GetNodeName() == "" || assignment.GetWorkerPodUid() == "" {
		return nil, fmt.Errorf("current native worker assignment missing")
	}
	conn, err := s.dialer.DialForAteletOnNode(assignment.GetNodeName())
	if err != nil {
		return nil, err
	}
	proof, err := ateletpb.NewAteomHerderClient(conn).VerifyExecution(leaseCtx, &ateletpb.VerifyExecutionRequest{WorkerPodUid: assignment.GetWorkerPodUid(), Atespace: ref.Atespace, ActorName: ref.Name, ActorUid: r.GetActorUid(), ExecutionRequirement: r.GetExecutionRequirement()})
	if err != nil {
		return nil, err
	}
	if !proof.GetActive() {
		return nil, fmt.Errorf("native compute did not prove current enforcement")
	}
	return &ateapipb.VerifyActorExecutionResponse{Active: true}, nil
}
