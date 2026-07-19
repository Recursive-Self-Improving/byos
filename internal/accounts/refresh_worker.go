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
	accounts  *store.AccountRepository
	registry  provider.CredentialRefreshRegistry
	usability provider.CredentialUsabilityRegistry
	interval  time.Duration
	now       func() time.Time
	hooks     []RefreshHook
}

// NewRefreshWorker constructs a refresh worker from an explicit credential
// refresh registry and an explicit, purpose-specific credential usability
// registry. The usability registry is a required, compile-time-checked
// dependency: it is the only way the worker resolves CredentialUsability for
// providers (e.g. Devin) that have no explicit refresher, so a fake or
// decorator cannot silently omit usability projection by failing an
// undeclared type assertion. It is distinct from CapabilityRegistry so
// providers whose runtime registration is lifecycle-only still project
// usability without registering placeholder generation capabilities. Both
// dependencies must be non-nil.
func NewRefreshWorker(accounts *store.AccountRepository, registry provider.CredentialRefreshRegistry, usability provider.CredentialUsabilityRegistry, hooks ...RefreshHook) *RefreshWorker {
	return &RefreshWorker{accounts: accounts, registry: registry, usability: usability, hooks: append([]RefreshHook(nil), hooks...), interval: time.Minute, now: func() time.Time { return time.Now().UTC() }}
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
		if ok && refresher != nil {
			due, err := refresher.NeedsRefresh(ctx, account.ID, w.now())
			if err != nil || !due {
				continue
			}
			if err := refresher.Refresh(ctx, account.ID); err == nil {
				for _, hook := range w.hooks {
					_ = hook.Refresh(ctx, account.ID)
				}
			}
			continue
		}
		// Providers without an explicit refresher (e.g. Devin) cannot be
		// refreshed here. Project their usability through the provider's
		// CredentialUsability so expired/missing credentials durably become
		// relogin-required without returning a token or performing refresh or
		// network calls. Hooks fire only after an actual successful refresh,
		// which never occurs for these providers.
		usability, ok := w.resolveUsability(account.Provider)
		if !ok || usability == nil {
			continue
		}
		_, _ = usability.CredentialUsable(ctx, account.ID)
	}
	return nil
}

func (w *RefreshWorker) resolveUsability(kind provider.Kind) (provider.CredentialUsability, bool) {
	if w.usability == nil {
		return nil, false
	}
	return w.usability.CredentialUsability(kind)
}
