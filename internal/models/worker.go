package models

import (
	"context"
	"errors"
	"sync"
	"time"

	"byos/internal/provider"
	"byos/internal/store"
	"golang.org/x/sync/singleflight"
)

type Account struct {
	ID       string
	Provider provider.Kind
	Enabled  bool
}

type AccountProvider interface {
	ModelAccounts(context.Context) ([]Account, error)
}

type DiscoveryApplier interface {
	ApplyDiscovery(context.Context, string, []provider.DiscoveredModel, error) ([]Model, error)
}

type StoreAccountProvider struct {
	repository interface {
		List(context.Context) ([]store.Account, error)
	}
}

func NewStoreAccountProvider(repository interface {
	List(context.Context) ([]store.Account, error)
}) *StoreAccountProvider {
	return &StoreAccountProvider{repository: repository}
}
func (p *StoreAccountProvider) ModelAccounts(ctx context.Context) ([]Account, error) {
	values, err := p.repository.List(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]Account, 0, len(values))
	for _, value := range values {
		result = append(result, Account{ID: value.ID, Provider: value.Provider, Enabled: value.Enabled})
	}
	return result, nil
}

type Worker struct {
	accounts AccountProvider
	registry provider.CapabilityRegistry
	applier  DiscoveryApplier
	interval time.Duration
	timeout  time.Duration
	group    singleflight.Group
	limiter  chan struct{}
	mu       sync.RWMutex
	status   map[string]RefreshStatus
}

func NewWorker(accounts AccountProvider, registry provider.CapabilityRegistry, applier DiscoveryApplier, interval, timeout time.Duration, concurrency ...int) *Worker {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	limit := 4
	if len(concurrency) > 0 && concurrency[0] > 0 {
		limit = concurrency[0]
	}
	return &Worker{accounts: accounts, registry: registry, applier: applier, interval: interval, timeout: timeout, limiter: make(chan struct{}, limit), status: make(map[string]RefreshStatus)}
}

func (w *Worker) RefreshAccount(ctx context.Context, account Account) error {
	if !account.Enabled {
		return nil
	}
	if w.registry == nil || w.applier == nil {
		return nil
	}
	capabilities, ok := w.registry.Capabilities(account.Provider, string(account.Provider))
	if !ok || capabilities.ModelDiscoverer == nil || capabilities.Credentials == nil {
		return nil
	}
	channel := w.group.DoChan(account.ID, func() (any, error) {
		select {
		case w.limiter <- struct{}{}:
			defer func() { <-w.limiter }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		attempt := time.Now().UTC()
		w.setStatus(account.ID, func(status *RefreshStatus) {
			status.AccountID = account.ID
			status.LastAttempt = attempt
			status.Refreshing = true
		})
		refreshCtx, refreshCancel := context.WithTimeout(ctx, w.timeout)
		credential, err := capabilities.Credentials.Credential(refreshCtx, account.ID)
		var discovered []provider.DiscoveredModel
		if err == nil {
			discovered, err = capabilities.ModelDiscoverer.Discover(refreshCtx, credential)
		}
		refreshCancel()
		persistenceCtx, persistenceCancel := context.WithTimeout(ctx, w.timeout)
		defer persistenceCancel()
		_, err = w.applier.ApplyDiscovery(persistenceCtx, account.ID, discovered, err)
		w.setStatus(account.ID, func(status *RefreshStatus) {
			status.Refreshing = false
			status.Stale = err != nil
			if err != nil {
				status.LastError = err.Error()
			} else {
				status.LastError = ""
				status.LastSuccess = time.Now().UTC()
			}
		})
		return nil, err
	})
	select {
	case <-ctx.Done():
		return ctx.Err()
	case result := <-channel:
		return result.Err
	}
}

func (w *Worker) Status(accountID string) RefreshStatus {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.status[accountID]
}

func (w *Worker) Run(ctx context.Context) error {
	if err := w.refreshAll(ctx); err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			_ = w.refreshAll(ctx)
		}
	}
}

func (w *Worker) refreshAll(ctx context.Context) error {
	accounts, err := w.accounts.ModelAccounts(ctx)
	if err != nil {
		return err
	}
	var joined error
	for _, account := range accounts {
		if !account.Enabled {
			continue
		}
		if err := w.RefreshAccount(ctx, account); err != nil && !errors.Is(err, context.Canceled) {
			joined = errors.Join(joined, err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return joined
}

func (w *Worker) setStatus(accountID string, update func(*RefreshStatus)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	status := w.status[accountID]
	update(&status)
	w.status[accountID] = status
}
