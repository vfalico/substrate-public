//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
)

// A successful retirement is exact authenticated proof of a stable empty scope,
// not an inference from a failed removal RPC. Caller retains guest and owner
// on any uncertain retirement/confirmation. No workload starts in this helper.
func retirePreparedGuest(ctx context.Context, ids []string, remove func(context.Context, string) error, retire func() error, confirm func() error) error {
	var removalErrors []error
	for _, id := range ids {
		if err := remove(ctx, id); err != nil {
			removalErrors = append(removalErrors, fmt.Errorf("remove intended %q: %w", id, err))
		}
	}
	if err := retire(); err != nil {
		return errors.Join(append(removalErrors, fmt.Errorf("exact empty retirement required: %w", err))...)
	}
	if len(removalErrors) > 0 {
		slog.WarnContext(ctx, "prepared removal replies uncertain; exact empty retirement confirmed", "uncertain_removals", len(removalErrors))
	}
	return confirm()
}
