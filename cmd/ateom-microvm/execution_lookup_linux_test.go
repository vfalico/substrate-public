//go:build linux

package main

import (
	"context"
	"testing"
)

func TestWarmMandatoryLookupCannotDowngradeOnMissingLocator(t *testing.T) {
	t.Setenv("SUBSTRATE_EXECUTION_ENFORCER_CONFIG", "")
	s := &AteomService{actors: map[string]*hostedActor{"mandatory": {executionRequirement: []byte(`{"opaque":true}`)}, "policy-free": {}}}
	if err := s.lookupExecution(context.Background(), "mandatory"); err == nil {
		t.Fatal("mandatory actor downgraded without locator")
	}
	if err := s.lookupExecution(context.Background(), "absent"); err == nil {
		t.Fatal("absent actor admitted")
	}
	if err := s.lookupExecution(context.Background(), "policy-free"); err != nil {
		t.Fatal(err)
	}
}

func TestRetainedMandatoryLocatorLossCannotRetireOrReplace(t *testing.T) {
	t.Setenv("SUBSTRATE_EXECUTION_ENFORCER_CONFIG", "")
	h := &hostedActor{executionRequirement: []byte(`{"opaque":true}`)}
	s := &AteomService{actors: map[string]*hostedActor{"mandatory": h, "policy-free": {}}}
	if err := s.retireExecution(t.Context(), "mandatory"); err == nil {
		t.Fatal("retirement lost retained requirement")
	}
	if err := s.unhostActor(t.Context(), "mandatory"); err == nil {
		t.Fatal("unhost removed retained owner")
	}
	if s.actors["mandatory"] != h {
		t.Fatal("mandatory hosted owner mutated")
	}
	if err := s.refuseGovernedReuse("mandatory"); err == nil {
		t.Fatal("replacement bypassed retained owner")
	}
	if err := s.retireExecution(t.Context(), "policy-free"); err != nil {
		t.Fatal(err)
	}
	if err := s.refuseGovernedReuse("policy-free"); err != nil {
		t.Fatal(err)
	}
}
