package xai

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"byos/internal/provider"
	"byos/internal/store"
)

type lifecycleServiceFake struct {
	calls                            atomic.Int32
	flow                             DeviceAuthorization
	session                          store.OAuthSession
	sessions                         []store.OAuthSession
	token                            TokenResponse
	completedState, completedAccount string
}

func (f *lifecycleServiceFake) Start(context.Context) (DeviceAuthorization, error) {
	f.calls.Add(1)
	return f.flow, nil
}
func (f *lifecycleServiceFake) Get(context.Context, string) (store.OAuthSession, error) {
	f.calls.Add(1)
	return f.session, nil
}
func (f *lifecycleServiceFake) ListResumable(context.Context) ([]store.OAuthSession, error) {
	f.calls.Add(1)
	return f.sessions, nil
}
func (f *lifecycleServiceFake) Poll(context.Context, string) (TokenResponse, error) {
	f.calls.Add(1)
	return f.token, nil
}
func (f *lifecycleServiceFake) Complete(_ context.Context, state, account string) error {
	f.calls.Add(1)
	f.completedState, f.completedAccount = state, account
	return nil
}
func (f *lifecycleServiceFake) Fail(context.Context, string, string) error {
	f.calls.Add(1)
	return nil
}
func (f *lifecycleServiceFake) Cancel(context.Context, string) error { f.calls.Add(1); return nil }
func (f *lifecycleServiceFake) Stop(string)                          { f.calls.Add(1) }

type lifecycleAccountsFake struct {
	calls atomic.Int32
	saved store.Account
}

func (f *lifecycleAccountsFake) Get(context.Context, string) (store.Account, error) {
	f.calls.Add(1)
	return f.saved, nil
}
func (f *lifecycleAccountsFake) UpsertLogin(_ context.Context, account store.Account) (store.Account, error) {
	f.calls.Add(1)
	f.saved = account
	f.saved.ID = "acct_xai"
	return f.saved, nil
}

type lifecycleIdentityFake struct {
	calls atomic.Int32
	raw   string
}

func (f *lifecycleIdentityFake) Verify(_ context.Context, raw string) (Identity, error) {
	f.calls.Add(1)
	f.raw = raw
	return Identity{Issuer: "issuer", Subject: "subject", Email: "person@example.test", Claims: map[string]any{"private_claim": "claim-secret"}}, nil
}

func TestProviderLifecycleProjectsSafeFieldsAndPrefersCompleteURL(t *testing.T) {
	now := time.Now().UTC()
	service := &lifecycleServiceFake{flow: DeviceAuthorization{State: "state", UserCode: "USER", VerificationURI: "https://verify", VerificationURIComplete: "https://verify?code=USER", ExpiresAt: now, PollInterval: 5 * time.Second}}
	lifecycle := NewProviderLifecycle(service, &lifecycleAccountsFake{}, &lifecycleIdentityFake{})
	authorization, err := lifecycle.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Ref != (provider.AuthorizationRef{Provider: provider.XAI, State: "state"}) || authorization.VerificationURL != service.flow.VerificationURIComplete || authorization.VerificationURLComplete != service.flow.VerificationURIComplete || authorization.UserCode != "USER" {
		t.Fatalf("authorization = %+v", authorization)
	}
	text := strings.ToLower(strings.Join([]string{authorization.Ref.State, authorization.UserCode, authorization.VerificationURL, authorization.VerificationURLComplete}, " "))
	for _, secret := range []string{"device-secret", "access-secret", "refresh-secret", "id-secret", "claim-secret"} {
		if strings.Contains(text, secret) {
			t.Fatalf("authorization exposed %q", secret)
		}
	}
}

func TestProviderLifecycleMismatchRejectedBeforeDependencies(t *testing.T) {
	service := &lifecycleServiceFake{}
	accounts := &lifecycleAccountsFake{}
	identity := &lifecycleIdentityFake{}
	lifecycle := NewProviderLifecycle(service, accounts, identity)
	wrong := provider.AuthorizationRef{Provider: provider.Devin, State: "state"}
	if _, err := lifecycle.Status(context.Background(), wrong); !errors.Is(err, provider.ErrProviderMismatch) {
		t.Fatalf("status error = %v", err)
	}
	if _, err := lifecycle.Complete(context.Background(), wrong); !errors.Is(err, provider.ErrProviderMismatch) {
		t.Fatalf("complete error = %v", err)
	}
	if err := lifecycle.Cancel(context.Background(), wrong); !errors.Is(err, provider.ErrProviderMismatch) {
		t.Fatalf("cancel error = %v", err)
	}
	if calls := service.calls.Load(); calls != 0 {
		t.Fatalf("service calls after mismatches = %d", calls)
	}
	if calls := accounts.calls.Load(); calls != 0 {
		t.Fatalf("repository calls after mismatches = %d", calls)
	}
	if calls := identity.calls.Load(); calls != 0 {
		t.Fatalf("identity calls after mismatches = %d", calls)
	}
}

func TestProviderLifecycleCompleteKeepsCredentialsAndIdentityInternal(t *testing.T) {
	expires := time.Now().UTC().Add(time.Hour)
	service := &lifecycleServiceFake{
		session: store.OAuthSession{State: "state", Status: "authorized"},
		token:   TokenResponse{AccessToken: "access-secret", RefreshToken: "refresh-secret", IDToken: "id-secret", TokenEndpoint: "https://token", ExpiresAt: expires},
	}
	accounts := &lifecycleAccountsFake{}
	identity := &lifecycleIdentityFake{}
	lifecycle := NewProviderLifecycle(service, accounts, identity)
	result, err := lifecycle.Complete(context.Background(), provider.AuthorizationRef{Provider: provider.XAI, State: "state"})
	if err != nil {
		t.Fatal(err)
	}
	if result != (provider.AccountResult{Provider: provider.XAI, AccountID: "acct_xai"}) {
		t.Fatalf("result = %+v", result)
	}
	if identity.raw != "id-secret" || accounts.saved.Credentials.AccessToken != "access-secret" || accounts.saved.Credentials.RefreshToken != "refresh-secret" || !strings.Contains(string(accounts.saved.Credentials.RawIdentity), "claim-secret") {
		t.Fatal("credentials or identity were not retained internally")
	}
	if service.completedState != "state" || service.completedAccount != "acct_xai" {
		t.Fatalf("completion = %q/%q", service.completedState, service.completedAccount)
	}
	public := result.Provider.String() + result.AccountID
	for _, secret := range []string{"access-secret", "refresh-secret", "id-secret", "claim-secret"} {
		if strings.Contains(public, secret) {
			t.Fatalf("account result exposed %q", secret)
		}
	}
}

func TestProviderLifecycleResumeNormalizesSafeStatus(t *testing.T) {
	service := &lifecycleServiceFake{sessions: []store.OAuthSession{{State: "resume", Status: "failed", SanitizedError: "Authorization was denied.", UserCode: "USER", VerificationURI: "https://verify", DeviceCode: "device-secret", Authorization: &store.OAuthAuthorization{AccessToken: "access-secret"}}}}
	lifecycle := NewProviderLifecycle(service, &lifecycleAccountsFake{}, &lifecycleIdentityFake{})
	values, err := lifecycle.Resume(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || values[0].Status != provider.AuthorizationFailed || values[0].SanitizedMessage != "Authorization was denied." {
		t.Fatalf("resume = %+v", values)
	}
	text := values[0].UserCode + values[0].VerificationURL + values[0].SanitizedMessage
	if strings.Contains(text, "device-secret") || strings.Contains(text, "access-secret") {
		t.Fatalf("resume exposed secret: %+v", values[0])
	}
}
