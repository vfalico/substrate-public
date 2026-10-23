//go:build linux

package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestPartialPreparedCleanupRequiresExactEmptyRetirement(t *testing.T) {
	for _, fail := range []bool{false, true} {
		calls := []string{}
		confirmed := false
		err := retirePreparedGuest(t.Context(), []string{"uncertain", "prepared", "never-created"}, func(_ context.Context, id string) error {
			calls = append(calls, id)
			if id != "prepared" {
				return errors.New("arbitrary RPC error, not parsed")
			}
			return nil
		}, func() error {
			calls = append(calls, "retire")
			if fail {
				return errors.New("scope still populated")
			}
			return nil
		}, func() error { confirmed = true; return nil })
		if !reflect.DeepEqual(calls, []string{"uncertain", "prepared", "never-created", "retire"}) {
			t.Fatal(calls)
		}
		if fail && (err == nil || confirmed) {
			t.Fatal("uncertain retirement discarded owner", err, confirmed)
		}
		if !fail && (err != nil || !confirmed) {
			t.Fatal("authenticated empty retirement refused", err, confirmed)
		}
	}
}
func TestPartialPreparedCleanupConfirmationFailureIsNotSuccess(t *testing.T) {
	if err := retirePreparedGuest(t.Context(), []string{"prepared"}, func(context.Context, string) error { return nil }, func() error { return nil }, func() error { return errors.New("durability fault") }); err == nil {
		t.Fatal("missing stop checkpoint accepted")
	}
}
