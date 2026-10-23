//go:build linux

package main

import (
	"context"
	"github.com/agent-substrate/substrate/cmd/ateom-microvm/internal/ch"
	"github.com/agent-substrate/substrate/internal/ateomnet/netns"
	"os/exec"
)

// The VMM must own the same network namespace as its fd-backed TAP. CH queries
// interface MTU via a fresh socket even when the TAP arrives by SCM_RIGHTS.
// Do locks and restores the launching OS thread; the child retains the target
// namespace while SysProcAttr still atomically assigns its owning cgroup.
func (s *AteomService) launchActorVMM(ctx context.Context, id string, o ch.LaunchVMMOptions) (cmd *exec.Cmd, client *ch.Client, err error) {
	err = netns.Do(ctx, s.sandboxNetNS(id), func(ctx context.Context) error {
		var launchErr error
		cmd, client, launchErr = ch.LaunchVMM(ctx, o)
		return launchErr
	})
	return
}
