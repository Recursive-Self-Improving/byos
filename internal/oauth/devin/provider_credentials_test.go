package devin

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	appcrypto "byos/internal/crypto"
	"byos/internal/provider"
	"byos/internal/store"
)

func newDevinCredentialFixture(t *testing.T, now time.Time, account store.Account) (*store.AccountRepository, *ProviderCredentialManager, store.Account) {
	t.Helper()
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	repository := store.NewAccountRepository(database.DB, keys)
	created, err := repository.UpsertLogin(ctx, account)
	if err != nil {
		t.Fatal(err)
	}
	if !account.Enabled {
		if err := repository.Update(ctx, created.ID, created.Label, false); err != nil {
			t.Fatal(err)
		}
		created, err = repository.Get(ctx, created.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	manager := NewProviderCredentialManager(repository)
	manager.now = func() time.Time { return now }
	return repository, manager, created
}

func devinCredentialAccount(token string, expiry time.Time) store.Account {
	return store.Account{
		Provider: provider.Devin, Label: "Devin", Enabled: true, Status: "ready",
		Credentials: store.AccountCredentials{OpaqueToken: token, OpaqueTokenExpiresAt: &expiry}, ExpiresAt: &expiry,
	}
}

func TestProviderCredentialManagerUsabilityAndCredential(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	const token = "opaque-token-only-secret"
	tests := []struct {
		name       string
		account    store.Account
		usable     bool
		transition bool
	}{
		{name: "valid", account: devinCredentialAccount(token, now.Add(time.Second)), usable: true},
		{name: "expired", account: devinCredentialAccount(token, now.Add(-time.Second)), transition: true},
		{name: "equality is expired", account: devinCredentialAccount(token, now), transition: true},
		{name: "disabled", account: func() store.Account {
			a := devinCredentialAccount(token, now.Add(time.Hour))
			a.Enabled = false
			return a
		}()},
		{name: "non-ready status", account: func() store.Account {
			a := devinCredentialAccount(token, now.Add(time.Hour))
			a.Status = "relogin_required"
			return a
		}()},
		{name: "empty opaque token", account: devinCredentialAccount(" ", now.Add(time.Hour)), transition: true},
		{name: "missing expiry", account: func() store.Account {
			a := devinCredentialAccount(token, now.Add(time.Hour))
			a.ExpiresAt = nil
			return a
		}(), transition: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository, manager, account := newDevinCredentialFixture(t, now, test.account)
			usable, err := manager.CredentialUsable(context.Background(), account.ID)
			if err != nil || usable != test.usable {
				t.Fatalf("CredentialUsable() = %v, %v; want %v", usable, err, test.usable)
			}
			credential, err := manager.Credential(context.Background(), account.ID)
			if test.usable {
				if err != nil || credential != (provider.Credential{Value: token}) {
					t.Fatalf("Credential() = %#v, %v", credential, err)
				}
				return
			}
			if err == nil || credential != (provider.Credential{}) {
				t.Fatalf("Credential() = %#v, %v; want empty credential and error", credential, err)
			}
			if strings.Contains(err.Error(), token) {
				t.Fatalf("Credential error exposed token: %v", err)
			}
			persisted, persistErr := repository.Get(context.Background(), account.ID)
			if persistErr != nil {
				t.Fatal(persistErr)
			}
			if test.transition {
				if persisted.Enabled || persisted.Status != "relogin_required" || persisted.LastError != "authentication expired; reconnect required" {
					t.Fatalf("persisted account = %+v; want disabled relogin_required", persisted)
				}
			} else if persisted.Enabled != account.Enabled || persisted.Status != account.Status || persisted.LastError != account.LastError {
				t.Fatalf("account unexpectedly mutated: before=%+v after=%+v", account, persisted)
			}
		})
	}
}

func TestProviderCredentialManagerExpiredCredentialAcquisitionPersistsTransition(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	const secret = "expired-acquisition-secret"
	repository, manager, account := newDevinCredentialFixture(t, now, devinCredentialAccount(secret, now))

	credential, err := manager.Credential(context.Background(), account.ID)
	if err == nil || credential != (provider.Credential{}) || strings.Contains(err.Error(), secret) {
		t.Fatalf("Credential() = %#v, %v; want sanitized unavailable error", credential, err)
	}
	persisted, err := repository.Get(context.Background(), account.ID)
	if err != nil || persisted.Enabled || persisted.Status != "relogin_required" || persisted.LastError != "authentication expired; reconnect required" {
		t.Fatalf("persisted account = %+v, %v", persisted, err)
	}
	usable, err := manager.CredentialUsable(context.Background(), account.ID)
	if err != nil || usable {
		t.Fatalf("CredentialUsable() after transition = %v, %v", usable, err)
	}
}

func TestProviderCredentialManagerExpiredTransitionIsConcurrentAndIdempotent(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	const secret = "concurrent-expired-secret"
	repository, manager, account := newDevinCredentialFixture(t, now, devinCredentialAccount(secret, now.Add(-time.Second)))

	const callers = 24
	start := make(chan struct{})
	results := make(chan error, callers)
	for index := range callers {
		go func() {
			<-start
			if index%2 == 0 {
				usable, err := manager.CredentialUsable(context.Background(), account.ID)
				if err != nil {
					results <- err
					return
				}
				if usable {
					results <- errors.New("expired credential reported usable")
					return
				}
				results <- nil
				return
			}
			credential, err := manager.Credential(context.Background(), account.ID)
			if err == nil || credential != (provider.Credential{}) || strings.Contains(err.Error(), secret) {
				results <- errors.New("expired credential acquisition was not safely rejected")
				return
			}
			results <- nil
		}()
	}
	close(start)
	for range callers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}

	persisted, err := repository.Get(context.Background(), account.ID)
	if err != nil || persisted.Enabled || persisted.Status != "relogin_required" || persisted.LastError != "authentication expired; reconnect required" {
		t.Fatalf("persisted account = %+v, %v", persisted, err)
	}
}

func TestProviderCredentialManagerRejectsProviderMismatchWithoutSecrets(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	secret := "xai-secret-mismatch-sentinel"
	expiry := now.Add(time.Hour)
	account := store.Account{Provider: provider.XAI, Label: "xAI", Enabled: true, Status: "ready", Credentials: store.AccountCredentials{Issuer: "issuer", Subject: "subject", AccessToken: secret}, ExpiresAt: &expiry}
	repository, manager, created := newDevinCredentialFixture(t, now, account)

	for _, call := range []func() error{
		func() error { _, err := manager.CredentialUsable(context.Background(), created.ID); return err },
		func() error { _, err := manager.Credential(context.Background(), created.ID); return err },
		func() error {
			return manager.AuthenticationFailed(context.Background(), created.ID, &provider.UpstreamError{Provider: provider.Devin, Status: http.StatusUnauthorized})
		},
	} {
		err := call()
		if !errors.Is(err, provider.ErrProviderMismatch) || strings.Contains(err.Error(), secret) {
			t.Fatalf("mismatch error = %v", err)
		}
	}
	after, err := repository.Get(context.Background(), created.ID)
	if err != nil || !after.Enabled || after.Status != "ready" || after.Credentials.AccessToken != secret {
		t.Fatalf("mismatch mutated account: %+v, %v", after, err)
	}
}

func TestProviderCredentialManagerAuthenticationFailureTransitions(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			repository, manager, account := newDevinCredentialFixture(t, now, devinCredentialAccount("auth-secret-sentinel", now.Add(time.Hour)))
			for range 2 {
				err := manager.AuthenticationFailed(context.Background(), account.ID, &provider.UpstreamError{Provider: provider.Devin, Status: status})
				var upstream *provider.UpstreamError
				if !errors.As(err, &upstream) {
					t.Fatalf("AuthenticationFailed() error = %T %v", err, err)
				}
				classification := upstream.Classification
				if upstream.Provider != provider.Devin || upstream.Status != status || classification.Class != provider.ClassUnauthorized || !classification.RetryNext || !classification.DisableAccount || !classification.ReloginRequired || classification.CooldownScope != provider.CooldownAccount {
					t.Fatalf("classification = %+v, upstream = %+v", classification, upstream)
				}
				if strings.Contains(err.Error(), "auth-secret-sentinel") {
					t.Fatalf("authentication error exposed token: %v", err)
				}
			}
			marked, err := repository.Get(context.Background(), account.ID)
			if err != nil || marked.Enabled || marked.Status != "relogin_required" || marked.LastError != "authentication expired; reconnect required" {
				t.Fatalf("marked account = %+v, %v", marked, err)
			}
		})
	}
}

func TestProviderCredentialManagerAuthenticationFailureOtherStatusNoOp(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	repository, manager, account := newDevinCredentialFixture(t, now, devinCredentialAccount("no-op-secret", now.Add(time.Hour)))
	for _, upstream := range []*provider.UpstreamError{
		{Provider: provider.Devin, Status: http.StatusTooManyRequests},
		{Provider: provider.Devin, Status: http.StatusInternalServerError},
		{Provider: provider.XAI, Status: http.StatusTooManyRequests},
		{Provider: provider.XAI, Status: http.StatusInternalServerError},
	} {
		if err := manager.AuthenticationFailed(context.Background(), account.ID, upstream); err != nil {
			t.Fatalf("status %d returned %v", upstream.Status, err)
		}
	}
	beforeMismatch, err := repository.Get(context.Background(), account.ID)
	if err != nil {
		t.Fatal(err)
	}
	mismatchErr := manager.AuthenticationFailed(context.Background(), account.ID, &provider.UpstreamError{Provider: provider.XAI, Status: http.StatusUnauthorized})
	if !errors.Is(mismatchErr, provider.ErrProviderMismatch) || strings.Contains(mismatchErr.Error(), "no-op-secret") {
		t.Fatalf("upstream mismatch error = %v", mismatchErr)
	}
	after, err := repository.Get(context.Background(), account.ID)
	if err != nil || !after.Enabled || after.Status != "ready" || after.UpdatedAt != beforeMismatch.UpdatedAt {
		t.Fatalf("non-authentication status mutated account: before=%+v after=%+v err=%v", beforeMismatch, after, err)
	}
}
