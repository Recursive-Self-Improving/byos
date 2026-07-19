package xai

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	appcrypto "byos/internal/crypto"
	"byos/internal/provider"
	"byos/internal/store"
)

type providerCredentialRefresher struct {
	account store.Account
	err     error
	calls   []string
}

func (f *providerCredentialRefresher) Refresh(_ context.Context, id string) (store.Account, error) {
	f.calls = append(f.calls, id)
	return f.account, f.err
}

func TestProviderCredentialManagerFreshAndProactiveRefresh(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, _ := appcrypto.DeriveKeys(bytes.Repeat([]byte{19}, 32))
	repository := store.NewAccountRepository(database.DB, keys)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	expires := now.Add(time.Minute)
	account, err := repository.UpsertLogin(ctx, store.Account{Provider: provider.XAI, Credentials: store.AccountCredentials{Issuer: Issuer, Subject: "provider-credential", AccessToken: "old", RefreshToken: "refresh", TokenEndpoint: "https://auth.x.ai/token"}, ExpiresAt: &expires})
	if err != nil {
		t.Fatal(err)
	}
	refresher := &providerCredentialRefresher{account: account}
	refresher.account.Credentials.AccessToken = "new"
	manager := NewProviderCredentialManager(repository, refresher)
	manager.now = func() time.Time { return now }
	credential, err := manager.Credential(ctx, account.ID)
	if err != nil || credential.Value != "new" || len(refresher.calls) != 1 || refresher.calls[0] != account.ID {
		t.Fatalf("credential=%+v calls=%v err=%v", credential, refresher.calls, err)
	}
}

func TestProviderCredentialManagerAuthenticationRecoveryAndGuards(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, _ := appcrypto.DeriveKeys(bytes.Repeat([]byte{20}, 32))
	repository := store.NewAccountRepository(database.DB, keys)
	account, err := repository.UpsertLogin(ctx, store.Account{Provider: provider.XAI, Credentials: store.AccountCredentials{Issuer: Issuer, Subject: "provider-auth", AccessToken: "token"}})
	if err != nil {
		t.Fatal(err)
	}
	refresher := &providerCredentialRefresher{account: account}
	manager := NewProviderCredentialManager(repository, refresher)
	unauthorized := &provider.UpstreamError{Provider: provider.XAI, Status: 401, Classification: provider.ErrorClassification{Class: provider.ClassUnauthorized, RefreshSame: true}}
	if err := manager.AuthenticationFailed(ctx, account.ID, unauthorized); err != nil || len(refresher.calls) != 1 {
		t.Fatalf("calls=%v err=%v", refresher.calls, err)
	}
	if err := manager.AuthenticationFailed(ctx, account.ID, &provider.UpstreamError{Provider: provider.XAI, Status: 429, Classification: provider.ErrorClassification{Class: provider.ClassRateLimit}}); err == nil {
		t.Fatal("non-authentication error triggered recovery")
	}
	refresher.err = &OAuthError{Code: "invalid_grant", Description: "sensitive provider detail"}
	recoveryErr := manager.AuthenticationFailed(ctx, account.ID, unauthorized)
	var upstream *provider.UpstreamError
	if !errors.As(recoveryErr, &upstream) {
		t.Fatalf("refresh error type=%T value=%v", recoveryErr, recoveryErr)
	}
	classification := upstream.Classification
	if classification.Class != provider.ClassInvalidGrant || !classification.RetryNext || !classification.DisableAccount || !classification.ReloginRequired || classification.CooldownScope != provider.CooldownAccount {
		t.Fatalf("classification=%+v", classification)
	}
	if upstream.Error() == refresher.err.Error() || classification.PublicMessage == "sensitive provider detail" {
		t.Fatalf("provider detail escaped sanitized error: %v %+v", upstream, classification)
	}
}

func TestProviderCredentialManagerCredentialUsableDoesNotRefreshOrExposeCredential(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, _ := appcrypto.DeriveKeys(bytes.Repeat([]byte{21}, 32))
	repository := store.NewAccountRepository(database.DB, keys)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	expired := now.Add(-time.Hour)
	fresh := now.Add(time.Hour)
	tests := []struct {
		name        string
		expires     *time.Time
		credentials store.AccountCredentials
		want        bool
	}{
		{name: "fresh access token", expires: &fresh, credentials: store.AccountCredentials{AccessToken: "fresh-secret"}, want: true},
		{name: "expired but refreshable", expires: &expired, credentials: store.AccountCredentials{AccessToken: "rejected-secret", RefreshToken: "refresh-secret", TokenEndpoint: "https://auth.x.ai/token"}, want: true},
		{name: "expired without refresh token", expires: &expired, credentials: store.AccountCredentials{AccessToken: "rejected-secret", TokenEndpoint: "https://auth.x.ai/token"}},
		{name: "missing access token", expires: &fresh, credentials: store.AccountCredentials{RefreshToken: "refresh-secret", TokenEndpoint: "https://auth.x.ai/token"}},
	}
	refresher := &providerCredentialRefresher{}
	manager := NewProviderCredentialManager(repository, refresher)
	manager.now = func() time.Time { return now }
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			account, err := repository.UpsertLogin(ctx, store.Account{Provider: provider.XAI, Credentials: store.AccountCredentials{Issuer: Issuer, Subject: test.name, AccessToken: test.credentials.AccessToken, RefreshToken: test.credentials.RefreshToken, TokenEndpoint: test.credentials.TokenEndpoint}, ExpiresAt: test.expires})
			if err != nil {
				t.Fatal(err)
			}
			got, err := manager.CredentialUsable(ctx, account.ID)
			if err != nil || got != test.want {
				t.Fatalf("usable=%v want=%v err=%v", got, test.want, err)
			}
		})
	}
	if len(refresher.calls) != 0 {
		t.Fatalf("usability check refreshed accounts: %v", refresher.calls)
	}
}
