package xai

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"strings"
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

func TestProviderCredentialManagerExplicitRefreshCapability(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, _ := appcrypto.DeriveKeys(bytes.Repeat([]byte{22}, 32))
	repository := store.NewAccountRepository(database.DB, keys)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	exact := now.Add(RefreshLead)
	xaiAccount, err := repository.UpsertLogin(ctx, store.Account{Provider: provider.XAI, Credentials: store.AccountCredentials{Issuer: Issuer, Subject: "explicit-refresh", AccessToken: "secret", RefreshToken: "refresh-secret", TokenEndpoint: "https://auth.x.ai/token"}, ExpiresAt: &exact})
	if err != nil {
		t.Fatal(err)
	}
	refresher := &providerCredentialRefresher{account: xaiAccount}
	manager := NewProviderCredentialManager(repository, refresher)
	due, err := manager.NeedsRefresh(ctx, xaiAccount.ID, now)
	if err != nil || !due {
		t.Fatalf("needs refresh=%v err=%v", due, err)
	}
	if err := manager.Refresh(ctx, xaiAccount.ID); err != nil || len(refresher.calls) != 1 || refresher.calls[0] != xaiAccount.ID {
		t.Fatalf("calls=%v err=%v", refresher.calls, err)
	}
	refresher.err = &OAuthError{Code: "invalid_grant", Description: "sensitive provider detail"}
	err = manager.Refresh(ctx, xaiAccount.ID)
	var upstream *provider.UpstreamError
	if !errors.As(err, &upstream) || upstream.Classification.Class != provider.ClassInvalidGrant || !upstream.Classification.ReloginRequired {
		t.Fatalf("invalid grant error=%T %v", err, err)
	}
	if strings.Contains(err.Error(), "sensitive provider detail") {
		t.Fatalf("provider detail escaped explicit refresh: %v", err)
	}

	const opaqueTokenSentinel = "devin-opaque-token-mismatch-sentinel"
	opaqueTokenExpiresAt := exact.Add(time.Hour)
	devinAccount, err := repository.UpsertLogin(ctx, store.Account{
		Provider: provider.Devin,
		Credentials: store.AccountCredentials{
			OpaqueToken:          opaqueTokenSentinel,
			OpaqueTokenExpiresAt: &opaqueTokenExpiresAt,
		},
		ExpiresAt: &opaqueTokenExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	callsBefore := len(refresher.calls)
	_, needsRefreshErr := manager.NeedsRefresh(ctx, devinAccount.ID, now)
	if !errors.Is(needsRefreshErr, provider.ErrProviderMismatch) {
		t.Fatalf("needs refresh mismatch error=%v", needsRefreshErr)
	}
	refreshErr := manager.Refresh(ctx, devinAccount.ID)
	if !errors.Is(refreshErr, provider.ErrProviderMismatch) {
		t.Fatalf("refresh mismatch error=%v", refreshErr)
	}
	if len(refresher.calls) != callsBefore {
		t.Fatalf("provider mismatch reached refresh service: calls=%v", refresher.calls)
	}
	for _, mismatchErr := range []error{needsRefreshErr, refreshErr} {
		if strings.Contains(mismatchErr.Error(), opaqueTokenSentinel) {
			t.Fatalf("provider mismatch exposed Devin credential sentinel: %v", mismatchErr)
		}
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

type providerCredentialTimeoutError struct{ message string }

func (e providerCredentialTimeoutError) Error() string { return e.message }
func (providerCredentialTimeoutError) Timeout() bool   { return true }
func (providerCredentialTimeoutError) Temporary() bool { return true }

func TestProviderCredentialManagerSanitizesEveryRefreshBoundary(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, _ := appcrypto.DeriveKeys(bytes.Repeat([]byte{23}, 32))
	repository := store.NewAccountRepository(database.DB, keys)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	expired := now.Add(-time.Hour)
	account, err := repository.UpsertLogin(ctx, store.Account{Provider: provider.XAI, Credentials: store.AccountCredentials{Issuer: Issuer, Subject: "sanitized-refresh", AccessToken: "rejected-token", RefreshToken: "refresh-token", TokenEndpoint: "https://token-sentinel.invalid/oauth/body-sentinel"}, ExpiresAt: &expired})
	if err != nil {
		t.Fatal(err)
	}
	refresher := &providerCredentialRefresher{account: account}
	manager := NewProviderCredentialManager(repository, refresher)
	manager.now = func() time.Time { return now }
	unauthorized := &provider.UpstreamError{Provider: provider.XAI, Status: 401, Classification: provider.ErrorClassification{Class: provider.ClassUnauthorized, RefreshSame: true}}
	boundaries := []struct {
		name string
		call func() error
	}{
		{name: "proactive credential", call: func() error { _, err := manager.Credential(ctx, account.ID); return err }},
		{name: "explicit refresh", call: func() error { return manager.Refresh(ctx, account.ID) }},
		{name: "authentication recovery", call: func() error { return manager.AuthenticationFailed(ctx, account.ID, unauthorized) }},
	}
	errorsToSanitize := []struct {
		name      string
		err       error
		wantClass provider.ErrorClass
		wantRetry bool
	}{
		{name: "typed upstream", err: &provider.UpstreamError{Provider: provider.XAI, Status: 403, Classification: provider.ErrorClassification{Class: provider.ClassPermission, RetryNext: true, PublicStatus: 403, PublicCode: "provider_permission_error"}}, wantClass: provider.ClassPermission, wantRetry: true},
		{name: "invalid grant", err: &OAuthError{Code: "invalid_grant", Description: "body-sentinel refresh-token"}, wantClass: provider.ClassInvalidGrant, wantRetry: true},
		{name: "cancelled", err: context.Canceled, wantClass: provider.ClassCancelled},
		{name: "deadline", err: context.DeadlineExceeded, wantClass: provider.ClassConnection, wantRetry: true},
		{name: "URL timeout", err: &url.Error{Op: "Post", URL: "https://token-sentinel.invalid/oauth?token=refresh-token", Err: providerCredentialTimeoutError{message: "body-sentinel"}}, wantClass: provider.ClassConnection, wantRetry: true},
		{name: "other OAuth", err: &OAuthError{Code: "server_error", Description: "body-sentinel refresh-token"}, wantClass: provider.ClassUpstream},
		{name: "HTTP schema upstream", err: errors.New("https://token-sentinel.invalid/oauth returned body-sentinel refresh-token"), wantClass: provider.ClassUpstream},
	}
	for _, boundary := range boundaries {
		t.Run(boundary.name, func(t *testing.T) {
			for _, test := range errorsToSanitize {
				t.Run(test.name, func(t *testing.T) {
					refresher.err = test.err
					err := boundary.call()
					var upstream *provider.UpstreamError
					if !errors.As(err, &upstream) {
						t.Fatalf("error type=%T value=%v", err, err)
					}
					if upstream.Provider != provider.XAI || upstream.Classification.Class != test.wantClass || upstream.Classification.RetryNext != test.wantRetry {
						t.Fatalf("upstream=%+v classification=%+v", upstream, upstream.Classification)
					}
					if test.wantClass == provider.ClassInvalidGrant {
						classification := upstream.Classification
						if upstream.Status != 401 || !classification.DisableAccount || !classification.ReloginRequired || classification.CooldownScope != provider.CooldownAccount {
							t.Fatalf("invalid grant metadata: status=%d classification=%+v", upstream.Status, classification)
						}
					}
					message := err.Error()
					for _, sentinel := range []string{"token-sentinel", "body-sentinel", "refresh-token"} {
						if strings.Contains(message, sentinel) {
							t.Fatalf("%q escaped provider boundary in %q", sentinel, message)
						}
					}
				})
			}
		})
	}
}

func TestProviderCredentialManagerAuthenticationRecoveryClassificationParity(t *testing.T) {
	typed := &provider.UpstreamError{Provider: provider.XAI, Status: 503, Classification: provider.ErrorClassification{Class: provider.ClassTransient, RetryNext: true, PublicStatus: 503, PublicCode: "provider_unavailable"}}
	err := providerCredentialError(typed)
	var upstream *provider.UpstreamError
	if !errors.As(err, &upstream) || upstream == typed || upstream.Status != typed.Status || upstream.Classification != typed.Classification {
		t.Fatalf("typed recovery classification was not safely cloned: error=%T %v classification=%+v", err, err, upstream)
	}
	joined := providerCredentialError(errors.Join(typed, &OAuthError{Code: "invalid_grant", Description: "body-sentinel"}))
	var joinedUpstream *provider.UpstreamError
	if !errors.As(joined, &joinedUpstream) || joinedUpstream.Classification.Class != provider.ClassTransient || joinedUpstream.Status != typed.Status {
		t.Fatalf("typed precedence lost for joined error: %T %v", joined, joined)
	}

	err = providerCredentialError(errors.New("raw refresh transport failure"))
	if !errors.As(err, &upstream) || upstream.Classification.Class != provider.ClassUpstream {
		t.Fatalf("generic provider recovery error=%T %v", err, err)
	}

	ctx := context.Background()
	database, openErr := store.Open(ctx, t.TempDir())
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer database.Close()
	keys, _ := appcrypto.DeriveKeys(bytes.Repeat([]byte{24}, 32))
	repository := store.NewAccountRepository(database.DB, keys)
	account, saveErr := repository.UpsertLogin(ctx, store.Account{Provider: provider.XAI, Credentials: store.AccountCredentials{Issuer: Issuer, Subject: "recovery-guard", AccessToken: "token"}})
	if saveErr != nil {
		t.Fatal(saveErr)
	}
	manager := NewProviderCredentialManager(repository, &providerCredentialRefresher{account: account})
	guardErr := manager.AuthenticationFailed(ctx, account.ID, &provider.UpstreamError{Provider: provider.XAI, Status: 429, Classification: provider.ErrorClassification{Class: provider.ClassRateLimit}})
	if guardErr == nil || errors.As(guardErr, &upstream) {
		t.Fatalf("local recovery guard must remain untyped for original-classification fallback: %T %v", guardErr, guardErr)
	}
}
