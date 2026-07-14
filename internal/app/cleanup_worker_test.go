package app

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeCleaner struct {
	mu      sync.Mutex
	cutoffs []time.Time
	err     error
	count   int64
}

func (f *fakeCleaner) Cleanup(_ context.Context, cutoff time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cutoffs = append(f.cutoffs, cutoff)
	return f.count, f.err
}

type fakePromoter struct {
	mu     sync.Mutex
	values []time.Time
}

func (f *fakePromoter) PromoteExpired(_ context.Context, at time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.values = append(f.values, at)
	return 0, nil
}
func TestCleanupWorkerUsesExpiryAndRetentionCutoffs(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	responses := &fakeCleaner{}
	oauth := &fakeCleaner{}
	admin := &fakeCleaner{}
	usage := &fakeCleaner{}
	attempts := &fakeCleaner{}
	cooldowns := &fakePromoter{}
	worker := NewCleanupWorker(responses, oauth, admin, usage, attempts, cooldowns, 30*24*time.Hour, 24*time.Hour)
	worker.now = func() time.Time { return now }
	if err := worker.runOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, cleaner := range []*fakeCleaner{responses, oauth, admin} {
		if len(cleaner.cutoffs) != 1 || !cleaner.cutoffs[0].Equal(now) {
			t.Fatalf("cutoffs=%v", cleaner.cutoffs)
		}
	}
	if len(usage.cutoffs) != 1 || !usage.cutoffs[0].Equal(now.Add(-30*24*time.Hour)) {
		t.Fatalf("usage cutoff=%v", usage.cutoffs)
	}
	if len(attempts.cutoffs) != 1 || !attempts.cutoffs[0].Equal(now.Add(-24*time.Hour)) {
		t.Fatalf("attempt cutoff=%v", attempts.cutoffs)
	}
	if len(cooldowns.values) != 1 || !cooldowns.values[0].Equal(now) {
		t.Fatalf("cooldown=%v", cooldowns.values)
	}
	if err := worker.runOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
}
func TestCleanupWorkerCancellationAndErrors(t *testing.T) {
	sentinel := errors.New("cleanup failed")
	worker := NewCleanupWorker(&fakeCleaner{err: sentinel}, nil, nil, nil, nil, nil, time.Hour, time.Hour)
	if err := worker.runOnce(t.Context()); !errors.Is(err, sentinel) {
		t.Fatalf("error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	worker = NewCleanupWorker(nil, nil, nil, nil, nil, nil, time.Hour, time.Hour)
	if err := worker.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}

func TestCleanupWorkerCapsBatchesPerRun(t *testing.T) {
	cleaner := &fakeCleaner{count: 500}
	worker := NewCleanupWorker(cleaner, nil, nil, nil, nil, nil, time.Hour, time.Hour)
	worker.maxBatches = 3
	if err := worker.runOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(cleaner.cutoffs) != 3 {
		t.Fatalf("batches=%d", len(cleaner.cutoffs))
	}
}

type cancelingCleaner struct {
	cancel context.CancelFunc
	calls  int
}

func (c *cancelingCleaner) Cleanup(context.Context, time.Time) (int64, error) {
	c.calls++
	if c.calls == 1 {
		c.cancel()
	}
	return 500, nil
}
func TestCleanupWorkerStopsBetweenBatchesOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cleaner := &cancelingCleaner{cancel: cancel}
	worker := NewCleanupWorker(cleaner, nil, nil, nil, nil, nil, time.Hour, time.Hour)
	err := worker.runOnce(ctx)
	if !errors.Is(err, context.Canceled) || cleaner.calls != 1 {
		t.Fatalf("err=%v calls=%d", err, cleaner.calls)
	}
}
