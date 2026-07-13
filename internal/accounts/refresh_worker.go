package accounts

import (
	"context"
	"time"

	oauthxai "supergrok-api/internal/oauth/xai"
	"supergrok-api/internal/store"
)

type RefreshWorker struct {
	accounts *store.AccountRepository
	refresh  *oauthxai.RefreshService
	interval time.Duration
	now      func() time.Time
}

func NewRefreshWorker(accounts *store.AccountRepository, refresh *oauthxai.RefreshService) *RefreshWorker {
	return &RefreshWorker{accounts: accounts, refresh: refresh, interval: time.Minute, now: func() time.Time { return time.Now().UTC() }}
}
func (w *RefreshWorker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		if err := w.refreshDue(ctx); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func (w *RefreshWorker) refreshDue(ctx context.Context) error {
	accounts, err := w.accounts.List(ctx)
	if err != nil {
		return err
	}
	for _, account := range accounts {
		if account.Enabled && oauthxai.NeedsRefresh(account, w.now()) {
			_, _ = w.refresh.Refresh(ctx, account.ID)
		}
	}
	return nil
}
