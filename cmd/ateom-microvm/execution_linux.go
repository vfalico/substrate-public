//go:build linux

package main

import (
	"context"
	"fmt"
	"github.com/agent-substrate/substrate/internal/ateomcgroup"
	"github.com/agent-substrate/substrate/internal/executionpolicy"
	"github.com/agent-substrate/substrate/internal/nodepath"
	"os"
	"path/filepath"
)

// A trusted worker startup locator, never admitted from workload/policy bytes.
// Loading before side effects makes malformed config a hard launch failure.
func (s *AteomService) executionClient() (*executionpolicy.Client, error) {
	p := os.Getenv("SUBSTRATE_EXECUTION_ENFORCER_CONFIG")
	if p == "" {
		return nil, fmt.Errorf("mandatory execution requirement has no configured enforcer")
	}
	return executionpolicy.Load(p)
}
func (s *AteomService) checkExecutionConfig(requirement []byte) error {
	if len(requirement) == 0 {
		return nil
	}
	if !s.actorCgroups {
		return fmt.Errorf("mandatory execution requirement needs exact delegated actor cgroup")
	}
	_, err := s.executionClient()
	return err
}
func (s *AteomService) activateExecution(ctx context.Context, id string, requirement []byte, iface string) error {
	if len(requirement) == 0 {
		return nil
	}
	c, err := s.executionClient()
	if err != nil {
		return err
	}
	if err := c.Activate(ctx, id, requirement, filepath.Join(ateomcgroup.Root, id), nodepath.ActorNetNSPath(id), iface); err != nil {
		return err
	}
	s.actorsMu.Lock()
	if h := s.actors[id]; h != nil {
		h.executionRequirement = append([]byte(nil), requirement...)
	}
	s.actorsMu.Unlock()
	return nil
}
func (s *AteomService) retireExecution(ctx context.Context, id string) error {
	// The immutable hosted requirement cannot be erased by removing a locator.
	if s.hostedMandatoryExecution(id) && os.Getenv("SUBSTRATE_EXECUTION_ENFORCER_CONFIG") == "" {
		return fmt.Errorf("mandatory retained execution retirement has no configured enforcer")
	}
	// Policy-free workers need no running service. Configured workers reconcile
	// original journal ownership before deleting targets, even after restart.
	if os.Getenv("SUBSTRATE_EXECUTION_ENFORCER_CONFIG") == "" {
		return nil
	}
	c, err := s.executionClient()
	if err != nil {
		return err
	}
	if c.Config.GuestPort != 0 {
		return c.RetireGuest(ctx, id)
	}
	return c.Retire(ctx, id)
}

// Current version explicitly refuses snapshot/warm reuse of a governed binding.
// A missing configured locator is not evidence that stored policy disappeared.
func (s *AteomService) refuseGovernedReuse(id string) error {
	s.actorsMu.RLock()
	h := s.actors[id]
	pending := h != nil && h.cleanupPending
	s.actorsMu.RUnlock()
	if pending {
		return fmt.Errorf("actor cleanup pending; replacement refused")
	}
	if s.hostedMandatoryExecution(id) {
		return fmt.Errorf("governed reuse is not supported; retained hosted owner unchanged")
	}
	if os.Getenv("SUBSTRATE_EXECUTION_ENFORCER_CONFIG") == "" {
		return nil
	}
	c, err := s.executionClient()
	if err != nil {
		return err
	}
	if c.Config.GuestPort != 0 {
		return c.RefuseGuestReuse(id)
	}
	_, err = c.Read(id)
	if err == nil {
		return fmt.Errorf("governed reuse is not supported; no compute changed")
	}
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// The admitted hosted frame retains mandatory authority even if the locator is
// removed. No config or journal disappearance can downgrade it to policy-free.
func (s *AteomService) lookupExecution(ctx context.Context, id string) error {
	s.actorsMu.RLock()
	h := s.actors[id]
	var requirement []byte
	pending := h != nil && h.cleanupPending
	if h != nil {
		requirement = append([]byte(nil), h.executionRequirement...)
	}
	s.actorsMu.RUnlock()
	if h == nil {
		return fmt.Errorf("exact hosted actor unavailable")
	}
	if pending {
		return fmt.Errorf("exact hosted actor cleanup pending")
	}
	if len(requirement) == 0 {
		return nil
	}
	c, err := s.executionClient()
	if err != nil {
		return err
	}
	if c.Config.GuestPort != 0 {
		return c.LookupGuest(ctx, id, requirement)
	}
	return c.Lookup(ctx, id, requirement)
}

func (s *AteomService) hostedMandatoryExecution(id string) bool {
	s.actorsMu.RLock()
	defer s.actorsMu.RUnlock()
	h := s.actors[id]
	return h != nil && len(h.executionRequirement) > 0
}
