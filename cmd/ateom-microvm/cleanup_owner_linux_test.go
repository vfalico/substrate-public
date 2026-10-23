//go:build linux

package main

import (
	"context"
	"github.com/agent-substrate/substrate/internal/ateomnet"
	"github.com/agent-substrate/substrate/internal/resources"
	"testing"
)

func TestFailedLocalCleanupRetainsExactHostedOwner(t *testing.T) {
	t.Setenv("SUBSTRATE_EXECUTION_ENFORCER_CONFIG", "")
	network := &ateomnet.SandboxSession{}
	h := &hostedActor{network: network}
	s := &AteomService{actors: map[string]*hostedActor{"original": h}, maxActors: 1}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.unhostActor(ctx, "original"); err == nil {
		t.Fatal("cancelled local cleanup accepted")
	}
	if s.actors["original"] != h || !h.cleanupPending {
		t.Fatal("lost exact cleanup owner")
	}
	if err := s.refuseGovernedReuse("original"); err == nil {
		t.Fatal("pending local cleanup replaced")
	}
	if _, _, err := s.admitActor(resources.ActorAttribution{UID: "original"}, false); err == nil {
		t.Fatal("admission replaced cleanup owner")
	}
	if _, _, err := s.admitActor(resources.ActorAttribution{UID: "other"}, false); err == nil {
		t.Fatal("cleanup owner lost capacity reservation")
	}
	if err := s.lookupExecution(t.Context(), "original"); err == nil {
		t.Fatal("warm traffic accepted while cleanup pending")
	}
	if err := s.unhostActor(t.Context(), "original"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.actors["original"]; ok {
		t.Fatal("proven cleanup retained owner")
	}
	if err := s.unhostActor(t.Context(), "original"); err != nil {
		t.Fatal("idempotent exact cleanup", err)
	}
}
