package accounts

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	appcrypto "byos/internal/crypto"
	oauthdevin "byos/internal/oauth/devin"
	"byos/internal/provider"
	"byos/internal/store"
)

type refreshHookFunc func(context.Context, string) error

func (f refreshHookFunc) Refresh(ctx context.Context, id string) error { return f(ctx, id) }

type workerCredentialRefresher struct {
	due          map[string]bool
	needsErrors  map[string]error
	refreshError map[string]error
	needsCalls   map[string]int
	refreshCalls map[string]int
}

func (r *workerCredentialRefresher) NeedsRefresh(_ context.Context, id string, _ time.Time) (bool, error) {
	r.needsCalls[id]++
	return r.due[id], r.needsErrors[id]
}

func (r *workerCredentialRefresher) Refresh(_ context.Context, id string) error {
	r.refreshCalls[id]++
	return r.refreshError[id]
}

// workerRefreshRegistry is a fake CredentialRefreshRegistry. It also
// implements CredentialUsabilityRegistry by resolving no usability, so it can
// be supplied as the worker's explicit usability dependency for tests that
// only exercise the explicit-refresher dispatch path.
type workerRefreshRegistry struct {
	provider provider.Kind
	policy   string
	refresh  provider.CredentialRefresher
}

func (r workerRefreshRegistry) CredentialRefresher(kind provider.Kind, policy string) (provider.CredentialRefresher, bool) {
	if kind != r.provider || policy != r.policy || r.refresh == nil {
		return nil, false
	}
	return r.refresh, true
}

func (r workerRefreshRegistry) CredentialUsability(provider.Kind) (provider.CredentialUsability, bool) {
	return nil, false
}

func TestRefreshWorkerDispatchesExactCapabilityAndHooksOnlySuccess(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	repo := store.NewAccountRepository(database.DB, keys)
	expires := time.Now().UTC().Add(time.Minute)
	add := func(kind provider.Kind, subject string, enabled bool) store.Account {
		t.Helper()
		credentials := store.AccountCredentials{OpaqueToken: "opaque-" + subject}
		if kind == provider.XAI {
			credentials = store.AccountCredentials{Issuer: "issuer", Subject: subject, AccessToken: "access-" + subject, RefreshToken: "refresh-" + subject, TokenEndpoint: "https://auth.x.ai/token"}
		}
		account, err := repo.UpsertLogin(ctx, store.Account{Provider: kind, ExpiresAt: &expires, Credentials: credentials})
		if err != nil {
			t.Fatal(err)
		}
		if !enabled {
			if err := repo.Update(ctx, account.ID, account.Label, false); err != nil {
				t.Fatal(err)
			}
		}
		return account
	}
	success := add(provider.XAI, "success", true)
	fresh := add(provider.XAI, "fresh", true)
	needsFailed := add(provider.XAI, "needs-failed", true)
	refreshFailed := add(provider.XAI, "refresh-failed", true)
	disabled := add(provider.XAI, "disabled", false)
	devin := add(provider.Devin, "devin", true)
	refresher := &workerCredentialRefresher{
		due:          map[string]bool{success.ID: true, refreshFailed.ID: true},
		needsErrors:  map[string]error{needsFailed.ID: errors.New("needs failed")},
		refreshError: map[string]error{refreshFailed.ID: errors.New("refresh failed")},
		needsCalls:   make(map[string]int), refreshCalls: make(map[string]int),
	}
	registry := workerRefreshRegistry{provider: provider.XAI, policy: "xai", refresh: refresher}
	var hookCalls atomic.Int32
	worker := NewRefreshWorker(repo, registry, registry, refreshHookFunc(func(_ context.Context, id string) error {
		if id != success.ID {
			t.Fatalf("hook account id = %q, want %q", id, success.ID)
		}
		hookCalls.Add(1)
		return errors.New("hook failure is isolated")
	}))
	if err := worker.refreshDue(ctx); err != nil {
		t.Fatal(err)
	}
	if refresher.refreshCalls[success.ID] != 1 || refresher.refreshCalls[refreshFailed.ID] != 1 {
		t.Fatalf("refresh calls = %#v", refresher.refreshCalls)
	}
	if refresher.needsCalls[fresh.ID] != 1 || refresher.needsCalls[needsFailed.ID] != 1 {
		t.Fatalf("needs calls = %#v", refresher.needsCalls)
	}
	if refresher.needsCalls[disabled.ID] != 0 || refresher.needsCalls[devin.ID] != 0 {
		t.Fatalf("unsupported/disabled accounts reached capability: %#v", refresher.needsCalls)
	}
	if hookCalls.Load() != 1 {
		t.Fatalf("hook calls = %d", hookCalls.Load())
	}
}

// workerRefreshAndUsabilityRegistry is a fake registry that implements both
// CredentialRefreshRegistry and CredentialUsabilityRegistry so the refresh
// worker can exercise mixed-provider dispatch: xAI gets an explicit refresher,
// Devin gets only a CredentialUsability projection through its real credential
// manager.
type workerRefreshAndUsabilityRegistry struct {
	workerRefreshRegistry
	usability map[provider.Kind]provider.CredentialUsability
}

func (r workerRefreshAndUsabilityRegistry) CredentialUsability(kind provider.Kind) (provider.CredentialUsability, bool) {
	usability, ok := r.usability[kind]
	return usability, ok
}

func TestRefreshWorkerProjectsDevinUsabilityWithoutRefreshOrCredentialOrHooks(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	repo := store.NewAccountRepository(database.DB, keys)
	now := time.Now().UTC()
	expires := now.Add(time.Minute)
	expired := now.Add(-time.Minute)
	xaiAccount, err := repo.UpsertLogin(ctx, store.Account{Provider: provider.XAI, ExpiresAt: &expires, Credentials: store.AccountCredentials{Issuer: "issuer", Subject: "xai", AccessToken: "access", RefreshToken: "refresh", TokenEndpoint: "https://auth.x.ai/token"}})
	if err != nil {
		t.Fatal(err)
	}
	devinValid, err := repo.UpsertLogin(ctx, store.Account{Provider: provider.Devin, ExpiresAt: &expires, Credentials: store.AccountCredentials{OpaqueToken: "devin-valid"}})
	if err != nil {
		t.Fatal(err)
	}
	devinExpired, err := repo.UpsertLogin(ctx, store.Account{Provider: provider.Devin, ExpiresAt: &expired, Credentials: store.AccountCredentials{OpaqueToken: "devin-expired"}})
	if err != nil {
		t.Fatal(err)
	}
	devinMissing, err := repo.UpsertLogin(ctx, store.Account{Provider: provider.Devin, ExpiresAt: &expires, Credentials: store.AccountCredentials{OpaqueToken: " "}})
	if err != nil {
		t.Fatal(err)
	}
	refresher := &workerCredentialRefresher{
		due:        map[string]bool{xaiAccount.ID: true},
		needsCalls: make(map[string]int), refreshCalls: make(map[string]int),
	}
	// Real Devin credential manager: CredentialUsable durably transitions
	// expired/missing credentials to relogin_required via MarkReloginRequired,
	// exactly as production routing sees. No fake usability stub.
	devinManager := oauthdevin.NewProviderCredentialManager(repo)
	registry := workerRefreshAndUsabilityRegistry{
		workerRefreshRegistry: workerRefreshRegistry{provider: provider.XAI, policy: "xai", refresh: refresher},
		usability: map[provider.Kind]provider.CredentialUsability{
			provider.Devin: devinManager,
		},
	}
	var hookCalls atomic.Int32
	worker := NewRefreshWorker(repo, registry, registry, refreshHookFunc(func(_ context.Context, id string) error {
		if id != xaiAccount.ID {
			t.Fatalf("hook fired for non-xAI account %q", id)
		}
		hookCalls.Add(1)
		return nil
	}))
	if err := worker.refreshDue(ctx); err != nil {
		t.Fatal(err)
	}

	// xAI refresh and hook behavior remains exact: one refresh, one hook, and
	// Devin accounts never reach the xAI refresher.
	if refresher.refreshCalls[xaiAccount.ID] != 1 {
		t.Fatalf("xAI refresh calls = %#v", refresher.refreshCalls)
	}
	if refresher.needsCalls[devinValid.ID] != 0 || refresher.needsCalls[devinExpired.ID] != 0 || refresher.needsCalls[devinMissing.ID] != 0 {
		t.Fatalf("Devin accounts reached xAI refresher: %#v", refresher.needsCalls)
	}
	if hookCalls.Load() != 1 {
		t.Fatalf("hook calls = %d; Devin must not trigger hooks", hookCalls.Load())
	}

	// Reload accounts and assert durable Devin transitions: expired and
	// missing credentials become disabled with relogin_required, while valid
	// Devin remains ready/enabled. This proves the persistence-level
	// transition, not merely a method return value.
	reload := func(id string) store.Account {
		t.Helper()
		got, err := repo.Get(ctx, id)
		if err != nil {
			t.Fatalf("reload %s: %v", id, err)
		}
		return got
	}
	validAfter := reload(devinValid.ID)
	if !validAfter.Enabled || validAfter.Status != "ready" {
		t.Fatalf("valid Devin after refresh = %+v; want enabled/ready", validAfter)
	}
	for _, id := range []string{devinExpired.ID, devinMissing.ID} {
		got := reload(id)
		if got.Enabled || got.Status != "relogin_required" || got.LastError != "authentication expired; reconnect required" {
			t.Fatalf("Devin %s after refresh = %+v; want disabled relogin_required", id, got)
		}
	}

	// A second refresh pass is a valid no-op: already-disabled Devin accounts
	// are skipped (not enabled), valid Devin stays ready, and no extra xAI
	// refresh or hooks fire. Devin still never reaches xAI refresh.
	beforeRefresh := refresher.refreshCalls[xaiAccount.ID]
	beforeHooks := hookCalls.Load()
	if err := worker.refreshDue(ctx); err != nil {
		t.Fatal(err)
	}
	if refresher.refreshCalls[xaiAccount.ID] != beforeRefresh+1 {
		t.Fatalf("second pass xAI refresh calls = %#v", refresher.refreshCalls)
	}
	if hookCalls.Load() != beforeHooks+1 {
		t.Fatalf("second pass hook calls = %d", hookCalls.Load())
	}
	if refresher.needsCalls[devinValid.ID] != 0 || refresher.needsCalls[devinExpired.ID] != 0 || refresher.needsCalls[devinMissing.ID] != 0 {
		t.Fatalf("second pass Devin reached xAI refresher: %#v", refresher.needsCalls)
	}
	validAfter2 := reload(devinValid.ID)
	if !validAfter2.Enabled || validAfter2.Status != "ready" {
		t.Fatalf("valid Devin after second pass = %+v; want enabled/ready", validAfter2)
	}
}
