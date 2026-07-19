package store

import (
	"context"
	"testing"
	"time"

	"byos/internal/auththrottle"
)

func TestAdminAuthThrottleRepositoryLadderResetAndGlobalGuard(t *testing.T) {
	database, err := Open(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewAdminAuthThrottleRepository(database.DB)
	policy := auththrottle.DefaultPolicy()
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	var source [32]byte
	source[0] = 1

	for failure := 1; failure <= 5; failure++ {
		transitions, err := repository.RecordFailure(context.Background(), source, now, policy)
		if err != nil {
			t.Fatal(err)
		}
		if failure < 3 && len(transitions) != 0 {
			t.Fatalf("failure %d transitions = %#v", failure, transitions)
		}
		if failure >= 3 && len(transitions) == 0 {
			t.Fatalf("failure %d did not create a penalty", failure)
		}
	}
	status, err := repository.Check(t.Context(), source, now, policy)
	if err != nil {
		t.Fatal(err)
	}
	if !status.BlockedUntil.Equal(now.Add(policy.LockAfterFive)) {
		t.Fatalf("blocked until = %v", status.BlockedUntil)
	}
	transition, changed, err := repository.ResetSource(t.Context(), source)
	if err != nil || !changed || transition.PriorFailureCount != 5 {
		t.Fatalf("reset = %#v changed=%v err=%v", transition, changed, err)
	}
	status, err = repository.Check(t.Context(), source, now, policy)
	if err != nil || !status.BlockedUntil.IsZero() {
		t.Fatalf("post-reset status = %#v err=%v", status, err)
	}

	for index := range policy.GlobalSourceLockLimit {
		var distinct [32]byte
		distinct[0] = byte(index + 2)
		for range 5 {
			if _, err := repository.RecordFailure(t.Context(), distinct, now, policy); err != nil {
				t.Fatal(err)
			}
		}
	}
	var fresh [32]byte
	fresh[0] = 250
	status, err = repository.Check(t.Context(), fresh, now, policy)
	if err != nil {
		t.Fatal(err)
	}
	if !status.BlockedUntil.Equal(now.Add(policy.GlobalBlockDuration)) {
		t.Fatalf("global blocked until = %v", status.BlockedUntil)
	}
	status, err = repository.Check(t.Context(), fresh, now.Add(policy.GlobalBlockDuration), policy)
	if err != nil || !status.BlockedUntil.IsZero() {
		t.Fatalf("expired global status = %#v err=%v", status, err)
	}
}
