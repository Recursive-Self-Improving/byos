package app

import (
	"context"
	"errors"
	"time"
)

type expiryCleaner interface {
	Cleanup(context.Context, time.Time) (int64, error)
}
type cooldownPromoter interface {
	PromoteExpired(context.Context, time.Time) (int64, error)
}
type CleanupWorker struct {
	responses, oauth, admin, usage, attempts   expiryCleaner
	cooldowns                                  cooldownPromoter
	interval, usageRetention, attemptRetention time.Duration
	now                                        func() time.Time
	timeout                                    time.Duration
	maxBatches                                 int
}

func NewCleanupWorker(responses, oauth, admin, usage, attempts expiryCleaner, cooldowns cooldownPromoter, usageRetention, attemptRetention time.Duration) *CleanupWorker {
	if usageRetention <= 0 {
		usageRetention = 30 * 24 * time.Hour
	}
	if attemptRetention <= 0 {
		attemptRetention = 24 * time.Hour
	}
	return &CleanupWorker{responses: responses, oauth: oauth, admin: admin, usage: usage, attempts: attempts, cooldowns: cooldowns, interval: time.Hour, usageRetention: usageRetention, attemptRetention: attemptRetention, timeout: 30 * time.Second, maxBatches: 20, now: func() time.Time { return time.Now().UTC() }}
}
func (w *CleanupWorker) Run(ctx context.Context) error {
	if err := w.runOnce(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := w.runOnce(ctx); err != nil {
				return err
			}
		}
	}
}
func (w *CleanupWorker) runOnce(ctx context.Context) error {
	runCtx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	now := w.now()
	var errs []error
	errs = append(errs, w.drainExpiry(runCtx, w.responses, now), w.drainExpiry(runCtx, w.oauth, now), w.drainExpiry(runCtx, w.admin, now), w.drainExpiry(runCtx, w.usage, now.Add(-w.usageRetention)), w.drainExpiry(runCtx, w.attempts, now.Add(-w.attemptRetention)), w.drainCooldowns(runCtx, now))
	return errors.Join(errs...)
}
func (w *CleanupWorker) drainExpiry(ctx context.Context, cleaner expiryCleaner, cutoff time.Time) error {
	if cleaner == nil {
		return nil
	}
	for range w.maxBatches {
		if err := ctx.Err(); err != nil {
			return err
		}
		count, err := cleaner.Cleanup(ctx, cutoff)
		if err != nil {
			return err
		}
		if count == 0 {
			return nil
		}
	}
	return nil
}
func (w *CleanupWorker) drainCooldowns(ctx context.Context, now time.Time) error {
	if w.cooldowns == nil {
		return nil
	}
	for range w.maxBatches {
		if err := ctx.Err(); err != nil {
			return err
		}
		count, err := w.cooldowns.PromoteExpired(ctx, now)
		if err != nil {
			return err
		}
		if count == 0 {
			return nil
		}
	}
	return nil
}
