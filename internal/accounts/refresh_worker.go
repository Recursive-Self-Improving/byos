package accounts

import (
	"context"
	"time"

	"byos/internal/provider"
	"byos/internal/store"
)

type RefreshHook interface {
	Refresh(context.Context, string) error
}

type RefreshWorker struct {
	accounts *store.AccountRepository
	registry provider.CredentialRefreshRegistry
	interval time.Duration
	now      func() time.Time
	hooks    []RefreshHook
}

func NewRefreshWorker(accounts *store.AccountRepository, registry provider.CredentialRefreshRegistry, hooks ...RefreshHook) *RefreshWorker {
	return &RefreshWorker{accounts: accounts, registry: registry, hooks: append([]RefreshHook(nil), hooks...), interval: time.Minute, now: func() time.Time { return time.Now().UTC() }}
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
		if !account.Enabled || w.registry == nil {
			continue
		}
		refresher, ok := w.registry.CredentialRefresher(account.Provider, string(account.Provider))
		if !ok || refresher == nil {
			continue
		}
		due, err := refresher.NeedsRefresh(ctx, account.ID, w.now())
		if err != nil || !due {
			continue
		}
		if err := refresher.Refresh(ctx, account.ID); err == nil {
			for _, hook := range w.hooks {
				_ = hook.Refresh(ctx, account.ID)
			}
		}
	}
	return nil
}
