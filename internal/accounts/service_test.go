package accounts

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	appcrypto "byos/internal/crypto"
	"byos/internal/provider"
	"byos/internal/store"
)

type fakeLifecycle struct {
	start       provider.Authorization
	status      provider.AuthorizationSession
	result      provider.AccountResult
	resume      []provider.AuthorizationSession
	err         error
	completeErr error
	calls       atomic.Int32
	completed   atomic.Bool
	started     chan struct{}
	release     chan struct{}
}

func (f *fakeLifecycle) Start(context.Context) (provider.Authorization, error) { return f.start, f.err }
func (f *fakeLifecycle) Status(context.Context, provider.AuthorizationRef) (provider.AuthorizationSession, error) {
	if f.completed.Load() {
		return provider.AuthorizationSession{
			Authorization: provider.Authorization{Ref: provider.AuthorizationRef{Provider: f.result.Provider, State: "state"}},
			Status:        provider.AuthorizationCompleted, AccountID: f.result.AccountID,
		}, f.err
	}
	return f.status, f.err
}
func (f *fakeLifecycle) Complete(ctx context.Context, _ provider.AuthorizationRef) (provider.AccountResult, error) {
	f.calls.Add(1)
	if f.started != nil {
		close(f.started)
	}
	if f.release != nil {
		select {
		case <-ctx.Done():
			return provider.AccountResult{}, ctx.Err()
		case <-f.release:
		}
	}
	if f.completeErr == nil {
		f.completed.Store(true)
	}
	return f.result, f.completeErr
}
func (f *fakeLifecycle) Cancel(context.Context, provider.AuthorizationRef) error { return f.err }
func (f *fakeLifecycle) Resume(context.Context) ([]provider.AuthorizationSession, error) {
	return f.resume, f.err
}

type fakeLifecycleRegistry struct {
	provider     provider.Kind
	policyKey    string
	capabilities provider.Capabilities
}

func (f fakeLifecycleRegistry) Capabilities(kind provider.Kind, policyKey string) (provider.Capabilities, bool) {
	wantProvider, wantPolicy := f.provider, f.policyKey
	if wantProvider == "" {
		wantProvider = provider.XAI
	}
	if wantPolicy == "" {
		wantPolicy = string(wantProvider)
	}
	if kind != wantProvider || policyKey != wantPolicy {
		return provider.Capabilities{}, false
	}
	if f.capabilities.Policy == nil && f.capabilities.Generation == nil && f.capabilities.Credentials == nil && f.capabilities.CredentialRefresher == nil && f.capabilities.Lifecycle == nil && f.capabilities.ModelDiscoverer == nil && f.capabilities.UsageFetcher == nil {
		return provider.Capabilities{}, false
	}
	return f.capabilities, true
}

var _ provider.CapabilityRegistry = fakeLifecycleRegistry{}

func (f fakeLifecycleRegistry) CredentialRefresher(kind provider.Kind, policyKey string) (provider.CredentialRefresher, bool) {
	capabilities, ok := f.Capabilities(kind, policyKey)
	return capabilities.CredentialRefresher, ok && capabilities.CredentialRefresher != nil
}

var _ provider.CredentialRefreshRegistry = fakeLifecycleRegistry{}

type countingHook struct{ calls atomic.Int32 }

func (h *countingHook) Refresh(context.Context, string) error {
	h.calls.Add(1)
	return nil
}

type countingCredentialRefresher struct {
	needsCalls atomic.Int32
	calls      atomic.Int32
	needs      bool
	err        error
}

func (r *countingCredentialRefresher) NeedsRefresh(context.Context, string, time.Time) (bool, error) {
	r.needsCalls.Add(1)
	return r.needs, r.err
}

func (r *countingCredentialRefresher) Refresh(context.Context, string) error {
	r.calls.Add(1)
	return r.err
}

type optionalDiscoverer struct{}

func (optionalDiscoverer) Discover(context.Context, provider.Credential) ([]provider.DiscoveredModel, error) {
	return nil, nil
}

type optionalUsageFetcher struct{}

func (optionalUsageFetcher) FetchUsage(context.Context, provider.Credential) (provider.UsageSnapshot, error) {
	return provider.UsageSnapshot{}, nil
}

func lifecycleRegistry(lifecycle provider.AccountLifecycle) provider.CapabilityRegistry {
	return fakeLifecycleRegistry{capabilities: provider.Capabilities{Lifecycle: lifecycle, ModelDiscoverer: optionalDiscoverer{}, UsageFetcher: optionalUsageFetcher{}}}
}

func accountRepository(t *testing.T) (*store.AccountRepository, func()) {
	t.Helper()
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{23}, 32))
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	return store.NewAccountRepository(database.DB, keys), func() { _ = database.Close() }
}

func TestCompleteLoginSingleflightAndCompletedFastPathRunHooksOnce(t *testing.T) {
	ctx := context.Background()
	repo, closeRepo := accountRepository(t)
	defer closeRepo()
	expires := time.Now().Add(time.Hour)
	account, err := repo.UpsertLogin(ctx, store.Account{Provider: provider.XAI, Status: "ready", ExpiresAt: &expires, Credentials: store.AccountCredentials{Issuer: "https://auth.x.ai", Subject: "private-subject", AccessToken: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle := &fakeLifecycle{result: provider.AccountResult{Provider: provider.XAI, AccountID: account.ID}, started: make(chan struct{}), release: make(chan struct{})}
	capabilities, usage := &countingHook{}, &countingHook{}
	service := NewService(repo, lifecycleRegistry(lifecycle), capabilities, usage)

	results := make(chan store.Account, 2)
	errs := make(chan error, 2)
	go func() { value, err := service.CompleteLogin(ctx, "state"); results <- value; errs <- err }()
	<-lifecycle.started
	go func() { value, err := service.CompleteLogin(ctx, "state"); results <- value; errs <- err }()
	close(lifecycle.release)
	first, second := <-results, <-results
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	third, err := service.CompleteLogin(ctx, "state")
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != account.ID || second.ID != account.ID || third.ID != account.ID {
		t.Fatalf("accounts=%q/%q/%q", first.ID, second.ID, third.ID)
	}
	if lifecycle.calls.Load() != 1 || capabilities.calls.Load() != 1 || usage.calls.Load() != 1 {
		t.Fatalf("lifecycle=%d capabilities=%d usage=%d", lifecycle.calls.Load(), capabilities.calls.Load(), usage.calls.Load())
	}
}

func TestCompleteLoginCancellationRemainsLifecycleOwned(t *testing.T) {
	lifecycle := &fakeLifecycle{completeErr: context.Canceled}
	service := NewService(nil, lifecycleRegistry(lifecycle), nil, nil)
	if _, err := service.CompleteLogin(context.Background(), "state"); !errors.Is(err, context.Canceled) {
		t.Fatalf("completion error=%v", err)
	}
}

func TestLifecycleUnavailableFailsBeforeProviderCall(t *testing.T) {
	service := NewService(nil, fakeLifecycleRegistry{}, nil, nil)
	if _, err := service.StartLogin(context.Background()); !errors.Is(err, ErrAccountLifecycleUnavailable) {
		t.Fatalf("start error=%v", err)
	}
	if _, err := service.CompleteLogin(context.Background(), "state"); !errors.Is(err, ErrAccountLifecycleUnavailable) {
		t.Fatalf("complete error=%v", err)
	}
}

func TestLifecycleRejectsWrongProviderResultsBeforeRepositoryAccess(t *testing.T) {
	lifecycle := &fakeLifecycle{
		start:  provider.Authorization{Ref: provider.AuthorizationRef{Provider: provider.Devin, State: "state"}},
		result: provider.AccountResult{Provider: provider.Devin, AccountID: "account"},
		resume: []provider.AuthorizationSession{{Authorization: provider.Authorization{Ref: provider.AuthorizationRef{Provider: provider.Devin, State: "state"}}}},
	}
	service := NewService(nil, lifecycleRegistry(lifecycle), nil, nil)
	if _, err := service.StartLogin(context.Background()); err == nil {
		t.Fatal("wrong-provider start succeeded")
	}
	if _, err := service.CompleteLogin(context.Background(), "state"); err == nil {
		t.Fatal("wrong-provider completion reached repository")
	}
	if _, err := service.ResumeLogins(context.Background()); err == nil {
		t.Fatal("wrong-provider resume succeeded")
	}
}

func TestRefreshDispatchesThroughExactProviderCapability(t *testing.T) {
	ctx := context.Background()
	repo, closeRepo := accountRepository(t)
	defer closeRepo()
	account, err := repo.UpsertLogin(ctx, store.Account{Provider: provider.Devin, Enabled: true, Credentials: store.AccountCredentials{OpaqueToken: "devin-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	refresher := &countingCredentialRefresher{}
	registry := fakeLifecycleRegistry{provider: provider.Devin, policyKey: string(provider.Devin), capabilities: provider.Capabilities{CredentialRefresher: refresher}}
	service := NewService(repo, registry, nil, nil)
	refreshed, err := service.Refresh(ctx, account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.ID != account.ID || refresher.calls.Load() != 1 || refresher.needsCalls.Load() != 0 {
		t.Fatalf("account=%q refresh=%d needs=%d", refreshed.ID, refresher.calls.Load(), refresher.needsCalls.Load())
	}
}

func TestRefreshFailsSafelyWhenCapabilityIsMissing(t *testing.T) {
	ctx := context.Background()
	repo, closeRepo := accountRepository(t)
	defer closeRepo()
	account, err := repo.UpsertLogin(ctx, store.Account{Provider: provider.Devin, Enabled: true, Credentials: store.AccountCredentials{OpaqueToken: "devin-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(repo, fakeLifecycleRegistry{}, nil, nil)
	if _, err := service.Refresh(ctx, account.ID); !errors.Is(err, ErrCredentialRefreshUnavailable) {
		t.Fatalf("refresh error=%v", err)
	}
}

func TestCompleteLoginSkipsAbsentOptionalHooks(t *testing.T) {
	ctx := context.Background()
	repo, closeRepo := accountRepository(t)
	defer closeRepo()
	account, err := repo.UpsertLogin(ctx, store.Account{Provider: provider.XAI, Enabled: true, Credentials: store.AccountCredentials{Issuer: "https://auth.x.ai", Subject: "subject", AccessToken: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle := &fakeLifecycle{result: provider.AccountResult{Provider: provider.XAI, AccountID: account.ID}}
	registry := fakeLifecycleRegistry{capabilities: provider.Capabilities{Lifecycle: lifecycle}}
	models, usage := &countingHook{}, &countingHook{}
	service := NewService(repo, registry, models, usage)
	if _, err := service.CompleteLogin(ctx, "state"); err != nil {
		t.Fatal(err)
	}
	if models.calls.Load() != 0 || usage.calls.Load() != 0 {
		t.Fatalf("optional hooks models=%d usage=%d", models.calls.Load(), usage.calls.Load())
	}
}
