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

const xaiPolicyKey = "xai"

var ErrAccountLifecycleUnavailable = errors.New("account lifecycle unavailable")
var ErrCredentialRefreshUnavailable = errors.New("credential refresh unavailable")

type CapabilityRefresher interface {
	Refresh(context.Context, string) error
}

type UsageRefresher interface {
	Refresh(context.Context, string) error
}

type Service struct {
	accounts     *store.AccountRepository
	registry     provider.CapabilityRegistry
	capabilities CapabilityRefresher
	usage        UsageRefresher
	now          func() time.Time
	completions  singleflight.Group
}

func NewService(accounts *store.AccountRepository, registry provider.CapabilityRegistry, capabilities CapabilityRefresher, usage UsageRefresher) *Service {
	return &Service{accounts: accounts, registry: registry, capabilities: capabilities, usage: usage, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) lifecycle() (provider.AccountLifecycle, error) {
	if s.registry == nil {
		return nil, fmt.Errorf("%w: provider=%s policy=%s", ErrAccountLifecycleUnavailable, provider.XAI, xaiPolicyKey)
	}
	capabilities, ok := s.registry.Capabilities(provider.XAI, xaiPolicyKey)
	if !ok || capabilities.Lifecycle == nil {
		return nil, fmt.Errorf("%w: provider=%s policy=%s", ErrAccountLifecycleUnavailable, provider.XAI, xaiPolicyKey)
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

func (s *Service) StartLogin(ctx context.Context) (provider.Authorization, error) {
	lifecycle, err := s.lifecycle()
	if err != nil {
		return provider.Authorization{}, err
	}
	authorization, err := lifecycle.Start(ctx)
	if err != nil {
		return provider.Authorization{}, err
	}
	if authorization.Ref.Provider != provider.XAI {
		return provider.Authorization{}, fmt.Errorf("account lifecycle returned provider %q, want %q", authorization.Ref.Provider, provider.XAI)
	}
	return authorization, nil
}

func (s *Service) LoginStatus(ctx context.Context, state string) (provider.AuthorizationSession, error) {
	lifecycle, err := s.lifecycle()
	if err != nil {
		return provider.AuthorizationSession{}, err
	}
	session, err := lifecycle.Status(ctx, provider.AuthorizationRef{Provider: provider.XAI, State: state})
	if err != nil {
		return provider.AuthorizationSession{}, err
	}
	if session.Ref.Provider != provider.XAI {
		return provider.AuthorizationSession{}, fmt.Errorf("account lifecycle returned provider %q, want %q", session.Ref.Provider, provider.XAI)
	}
	return session, nil
}

func (s *Service) CompleteLogin(ctx context.Context, state string) (store.Account, error) {
	result := s.completions.DoChan(state, func() (any, error) {
		return s.completeLogin(ctx, state)
	})
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

func (s *Service) completeLogin(ctx context.Context, state string) (store.Account, error) {
	lifecycle, err := s.lifecycle()
	if err != nil {
		return store.Account{}, err
	}
	ref := provider.AuthorizationRef{Provider: provider.XAI, State: state}
	session, err := lifecycle.Status(ctx, ref)
	if err != nil {
		return store.Account{}, err
	}
	if session.Status == provider.AuthorizationCompleted {
		if session.Ref.Provider != provider.XAI {
			return store.Account{}, fmt.Errorf("account lifecycle returned provider %q, want %q", session.Ref.Provider, provider.XAI)
		}
		if session.AccountID == "" {
			return store.Account{}, errors.New("completed account lifecycle returned an empty account id")
		}
		return s.account(ctx, session.AccountID)
	}
	result, err := lifecycle.Complete(ctx, ref)
	if err != nil {
		return store.Account{}, err
	}
	if result.Provider != provider.XAI {
		return store.Account{}, fmt.Errorf("account lifecycle returned provider %q, want %q", result.Provider, provider.XAI)
	}
	if result.AccountID == "" {
		return store.Account{}, errors.New("account lifecycle returned an empty account id")
	}
	account, err := s.account(ctx, result.AccountID)
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

func (s *Service) account(ctx context.Context, accountID string) (store.Account, error) {
	account, err := s.accounts.Get(ctx, accountID)
	if err != nil {
		return store.Account{}, err
	}
	if account.Provider != provider.XAI {
		return store.Account{}, fmt.Errorf("account %q belongs to provider %q, want %q", account.ID, account.Provider, provider.XAI)
	}
	return account, nil
}

func (s *Service) CancelLogin(ctx context.Context, state string) error {
	lifecycle, err := s.lifecycle()
	if err != nil {
		return err
	}
	return lifecycle.Cancel(ctx, provider.AuthorizationRef{Provider: provider.XAI, State: state})
}

func (s *Service) ResumeLogins(ctx context.Context) ([]provider.AuthorizationSession, error) {
	lifecycle, err := s.lifecycle()
	if err != nil {
		return nil, err
	}
	sessions, err := lifecycle.Resume(ctx)
	if err != nil {
		return nil, err
	}
	for _, session := range sessions {
		if session.Ref.Provider != provider.XAI {
			return nil, fmt.Errorf("account lifecycle returned provider %q, want %q", session.Ref.Provider, provider.XAI)
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
