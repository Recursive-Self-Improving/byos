package accounts

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sync/singleflight"

	"byos/internal/provider"
	"byos/internal/store"
)

var ErrAccountLifecycleUnavailable = errors.New("account lifecycle unavailable")
var ErrCredentialRefreshUnavailable = errors.New("credential refresh unavailable")

type CapabilityRefresher interface {
	Refresh(context.Context, string) error
}

type UsageRefresher interface {
	Refresh(context.Context, string) error
}

type Service struct {
	accounts        *store.AccountRepository
	registry        provider.CapabilityRegistry
	capabilities    CapabilityRefresher
	usage           UsageRefresher
	now             func() time.Time
	completions     singleflight.Group
	onFlightEntered func() // test seam; nil in production
}

func NewService(accounts *store.AccountRepository, registry provider.CapabilityRegistry, capabilities CapabilityRefresher, usage UsageRefresher) *Service {
	return &Service{accounts: accounts, registry: registry, capabilities: capabilities, usage: usage, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) lifecycle(kind provider.Kind) (provider.AccountLifecycle, error) {
	policyKey := string(kind)
	if s.registry == nil {
		return nil, fmt.Errorf("%w: provider=%s policy=%s", ErrAccountLifecycleUnavailable, kind, policyKey)
	}
	capabilities, ok := s.registry.Capabilities(kind, policyKey)
	if !ok || capabilities.Lifecycle == nil {
		return nil, fmt.Errorf("%w: provider=%s policy=%s", ErrAccountLifecycleUnavailable, kind, policyKey)
	}
	return capabilities.Lifecycle, nil
}

func (s *Service) optionalCapabilities(account store.Account) provider.Capabilities {
	if s.registry == nil {
		return provider.Capabilities{}
	}
	capabilities, _ := s.registry.Capabilities(account.Provider, string(account.Provider))
	return capabilities
}

func (s *Service) StartLogin(ctx context.Context, kind provider.Kind) (provider.Authorization, error) {
	lifecycle, err := s.lifecycle(kind)
	if err != nil {
		return provider.Authorization{}, err
	}
	authorization, err := lifecycle.Start(ctx)
	if err != nil {
		return provider.Authorization{}, err
	}
	if authorization.Ref.Provider != kind {
		return provider.Authorization{}, fmt.Errorf("account lifecycle returned provider %q, want %q", authorization.Ref.Provider, kind)
	}
	return authorization, nil
}

func (s *Service) LoginStatus(ctx context.Context, kind provider.Kind, sessionID provider.SessionID) (provider.AuthorizationSession, error) {
	lifecycle, err := s.lifecycle(kind)
	if err != nil {
		return provider.AuthorizationSession{}, err
	}
	session, err := lifecycle.Status(ctx, provider.AuthorizationRef{Provider: kind, SessionID: sessionID})
	if err != nil {
		return provider.AuthorizationSession{}, err
	}
	if session.Ref.Provider != kind {
		return provider.AuthorizationSession{}, fmt.Errorf("account lifecycle returned provider %q, want %q", session.Ref.Provider, kind)
	}
	return session, nil
}

// CompleteLogin completes an authorization flow. For xAI the ref carries the
// public SessionID used by the internal polling completion path; for Devin the
// ref carries the raw callback state. Neither path invokes management Status;
// the lifecycle Complete implementation is the sole authority for completion
// and already handles the already-completed case internally.
//
// xAI completion is SessionID-scoped and idempotent. singleflight dedupes
// concurrent calls for the same session so the lifecycle and optional
// model/usage hooks run exactly once per in-flight completion. Sequential
// replays are not memoized: they re-enter the lifecycle, which reports the
// already-completed AccountID from persisted OAuth session linkage, and the
// account is reloaded from the repository so a deleted or rotated account is
// never served stale. No decrypted account is retained in a long-lived map.
func (s *Service) CompleteLogin(ctx context.Context, kind provider.Kind, ref provider.AuthorizationRef, completion provider.AuthorizationCompletion) (store.Account, error) {
	if ref.Provider != kind {
		return store.Account{}, fmt.Errorf("account lifecycle returned provider %q, want %q", ref.Provider, kind)
	}
	if kind != provider.XAI {
		return s.completeLogin(ctx, kind, ref, completion)
	}
	key := string(kind) + "\x00" + string(ref.SessionID)
	result := s.completions.DoChan(key, func() (any, error) {
		return s.completeLogin(ctx, kind, ref, completion)
	})
	if s.onFlightEntered != nil {
		s.onFlightEntered()
	}
	select {
	case <-ctx.Done():
		return store.Account{}, ctx.Err()
	case completed := <-result:
		if completed.Err != nil {
			return store.Account{}, completed.Err
		}
		return completed.Val.(store.Account), nil
	}
}

func (s *Service) completeLogin(ctx context.Context, kind provider.Kind, ref provider.AuthorizationRef, completion provider.AuthorizationCompletion) (store.Account, error) {
	lifecycle, err := s.lifecycle(kind)
	if err != nil {
		return store.Account{}, err
	}
	result, err := lifecycle.Complete(ctx, ref, completion)
	if err != nil {
		return store.Account{}, err
	}
	if result.Provider != kind {
		return store.Account{}, fmt.Errorf("account lifecycle returned provider %q, want %q", result.Provider, kind)
	}
	if result.AccountID == "" {
		return store.Account{}, errors.New("account lifecycle returned an empty account id")
	}
	account, err := s.account(ctx, kind, result.AccountID)
	if err != nil {
		return store.Account{}, err
	}
	capabilities := s.optionalCapabilities(account)
	if capabilities.ModelDiscoverer != nil && s.capabilities != nil {
		_ = s.capabilities.Refresh(ctx, account.ID)
	}
	if capabilities.UsageFetcher != nil && s.usage != nil {
		_ = s.usage.Refresh(ctx, account.ID)
	}
	return account, nil
}

func (s *Service) account(ctx context.Context, kind provider.Kind, accountID string) (store.Account, error) {
	account, err := s.accounts.Get(ctx, accountID)
	if err != nil {
		return store.Account{}, err
	}
	if account.Provider != kind {
		return store.Account{}, fmt.Errorf("account %q belongs to provider %q, want %q", account.ID, account.Provider, kind)
	}
	return account, nil
}

func (s *Service) CancelLogin(ctx context.Context, kind provider.Kind, sessionID provider.SessionID) error {
	lifecycle, err := s.lifecycle(kind)
	if err != nil {
		return err
	}
	return lifecycle.Cancel(ctx, provider.AuthorizationRef{Provider: kind, SessionID: sessionID})
}

func (s *Service) ResumeLogins(ctx context.Context, kind provider.Kind) ([]provider.AuthorizationSession, error) {
	lifecycle, err := s.lifecycle(kind)
	if err != nil {
		return nil, err
	}
	sessions, err := lifecycle.Resume(ctx)
	if err != nil {
		return nil, err
	}
	for _, session := range sessions {
		if session.Ref.Provider != kind {
			return nil, fmt.Errorf("account lifecycle returned provider %q, want %q", session.Ref.Provider, kind)
		}
	}
	return sessions, nil
}

func (s *Service) Get(ctx context.Context, id string) (store.Account, error) {
	return s.accounts.Get(ctx, id)
}

func (s *Service) List(ctx context.Context) ([]store.Account, error) { return s.accounts.List(ctx) }

func (s *Service) Update(ctx context.Context, id, label string, enabled bool) error {
	return s.accounts.Update(ctx, id, label, enabled)
}

func (s *Service) Delete(ctx context.Context, id string) error { return s.accounts.Delete(ctx, id) }

func (s *Service) Refresh(ctx context.Context, id string) (store.Account, error) {
	account, err := s.accounts.Get(ctx, id)
	if err != nil {
		return store.Account{}, err
	}
	registry, ok := s.registry.(provider.CredentialRefreshRegistry)
	if !ok {
		return store.Account{}, fmt.Errorf("%w: provider=%s policy=%s", ErrCredentialRefreshUnavailable, account.Provider, account.Provider)
	}
	refresher, ok := registry.CredentialRefresher(account.Provider, string(account.Provider))
	if !ok || refresher == nil {
		return store.Account{}, fmt.Errorf("%w: provider=%s policy=%s", ErrCredentialRefreshUnavailable, account.Provider, account.Provider)
	}
	if err := refresher.Refresh(ctx, account.ID); err != nil {
		return store.Account{}, err
	}
	account, err = s.accounts.Get(ctx, id)
	if err != nil {
		return store.Account{}, err
	}
	capabilities := s.optionalCapabilities(account)
	if capabilities.ModelDiscoverer != nil && s.capabilities != nil {
		_ = s.capabilities.Refresh(ctx, id)
	}
	if capabilities.UsageFetcher != nil && s.usage != nil {
		_ = s.usage.Refresh(ctx, id)
	}
	return account, nil
}
