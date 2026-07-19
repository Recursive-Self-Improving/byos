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
	var hookCalls atomic.Int32
	worker := NewRefreshWorker(repo, workerRefreshRegistry{provider: provider.XAI, policy: "xai", refresh: refresher}, refreshHookFunc(func(_ context.Context, id string) error {
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
