package xai

import (
	"context"
	"database/sql"
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
	cancelErr                        error
}

func (f *lifecycleServiceFake) Start(context.Context) (DeviceAuthorization, error) {
	f.calls.Add(1)
	return f.flow, nil
}
func (f *lifecycleServiceFake) Get(context.Context, string) (store.OAuthSession, error) {
	f.calls.Add(1)
	return f.session, nil
}
func (f *lifecycleServiceFake) GetBySessionID(context.Context, string) (store.OAuthSession, error) {
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
func (f *lifecycleServiceFake) CancelBySessionID(context.Context, string, string) error {
	f.calls.Add(1)
	return f.cancelErr
}
func (f *lifecycleServiceFake) Stop(string) { f.calls.Add(1) }

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
	service := &lifecycleServiceFake{flow: DeviceAuthorization{SessionID: "session", State: "state", UserCode: "USER", VerificationURI: "https://verify", VerificationURIComplete: "https://verify?code=USER", ExpiresAt: now, PollInterval: 5 * time.Second}}
	lifecycle := NewProviderLifecycle(service, &lifecycleAccountsFake{}, &lifecycleIdentityFake{})
	authorization, err := lifecycle.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Ref != (provider.AuthorizationRef{Provider: provider.XAI, SessionID: "session"}) || authorization.Ref.State != "" || authorization.SessionID != "session" || authorization.VerificationURL != service.flow.VerificationURIComplete || authorization.VerificationURLComplete != service.flow.VerificationURIComplete || authorization.UserCode != "USER" {
		t.Fatalf("authorization = %+v", authorization)
	}
	text := strings.ToLower(strings.Join([]string{authorization.Ref.SessionID.String(), authorization.Ref.State, authorization.UserCode, authorization.VerificationURL, authorization.VerificationURLComplete}, " "))
	if strings.Contains(text, "state") {
		t.Fatalf("authorization projected raw state %q", authorization.Ref.State)
	}
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
	if _, err := lifecycle.Complete(context.Background(), wrong, provider.AuthorizationCompletion{}); !errors.Is(err, provider.ErrProviderMismatch) {
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
func TestProviderLifecycleRejectsCallbackCodeBeforeDependencies(t *testing.T) {
	service := &lifecycleServiceFake{}
	accounts := &lifecycleAccountsFake{}
	identity := &lifecycleIdentityFake{}
	lifecycle := NewProviderLifecycle(service, accounts, identity)
	_, err := lifecycle.Complete(context.Background(), provider.AuthorizationRef{Provider: provider.XAI, SessionID: "session"}, provider.AuthorizationCompletion{Code: "callback-secret"})
	if err == nil {
		t.Fatal("completion with callback code succeeded")
	}
	if service.calls.Load() != 0 || accounts.calls.Load() != 0 || identity.calls.Load() != 0 {
		t.Fatalf("dependencies called: service=%d accounts=%d identity=%d", service.calls.Load(), accounts.calls.Load(), identity.calls.Load())
	}
}

func TestProviderLifecycleCompleteKeepsCredentialsAndIdentityInternal(t *testing.T) {
	expires := time.Now().UTC().Add(time.Hour)
	service := &lifecycleServiceFake{
		session: store.OAuthSession{SessionID: "session", State: "state", Status: "authorized"},
		token:   TokenResponse{AccessToken: "access-secret", RefreshToken: "refresh-secret", IDToken: "id-secret", TokenEndpoint: "https://token", ExpiresAt: expires},
	}
	accounts := &lifecycleAccountsFake{}
	identity := &lifecycleIdentityFake{}
	lifecycle := NewProviderLifecycle(service, accounts, identity)
	result, err := lifecycle.Complete(context.Background(), provider.AuthorizationRef{Provider: provider.XAI, SessionID: "session"}, provider.AuthorizationCompletion{})
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
	service := &lifecycleServiceFake{sessions: []store.OAuthSession{{SessionID: "resume", State: "resume", Status: "failed", SanitizedError: "Authorization was denied.", UserCode: "USER", VerificationURI: "https://verify", DeviceCode: "device-secret", Authorization: &store.OAuthAuthorization{AccessToken: "access-secret"}}}}
	lifecycle := NewProviderLifecycle(service, &lifecycleAccountsFake{}, &lifecycleIdentityFake{})
	values, err := lifecycle.Resume(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || values[0].Status != provider.AuthorizationFailed || values[0].SanitizedMessage != "Authorization was denied." {
		t.Fatalf("resume = %+v", values)
	}
	if values[0].Ref.Provider != provider.XAI || values[0].Ref.SessionID != "resume" || values[0].Ref.State != "" {
		t.Fatalf("resume ref = %+v, want SessionID=resume State empty", values[0].Ref)
	}
	text := values[0].UserCode + values[0].VerificationURL + values[0].SanitizedMessage
	if strings.Contains(text, "device-secret") || strings.Contains(text, "access-secret") {
		t.Fatalf("resume exposed secret: %+v", values[0])
	}
}

// TestProviderLifecycleStatusResolvesBySessionID verifies that management
// Status resolves the session by its public SessionID and never accepts raw
// state from a caller. The projected ref carries only SessionID; State is
// never projected back.
func TestProviderLifecycleStatusResolvesBySessionID(t *testing.T) {
	service := &lifecycleServiceFake{session: store.OAuthSession{SessionID: "session", State: "state", Status: "pending", UserCode: "USER", VerificationURI: "https://verify"}}
	lifecycle := NewProviderLifecycle(service, &lifecycleAccountsFake{}, &lifecycleIdentityFake{})
	session, err := lifecycle.Status(context.Background(), provider.AuthorizationRef{Provider: provider.XAI, SessionID: "session"})
	if err != nil {
		t.Fatal(err)
	}
	if session.Ref.Provider != provider.XAI || session.Ref.SessionID != "session" || session.Ref.State != "" {
		t.Fatalf("status ref = %+v, want SessionID=session State empty", session.Ref)
	}
	if session.Status != provider.AuthorizationPending {
		t.Fatalf("status = %q, want pending", session.Status)
	}
	if service.calls.Load() != 1 {
		t.Fatalf("service calls = %d, want 1 (GetBySessionID only)", service.calls.Load())
	}
}

// TestProviderLifecycleStatusRejectsRawState verifies that a ref carrying only
// raw state (no SessionID) is rejected before any service call. xAI management
// never resolves by state; state is internal to callback/poll completion.
func TestProviderLifecycleStatusRejectsRawState(t *testing.T) {
	service := &lifecycleServiceFake{}
	lifecycle := NewProviderLifecycle(service, &lifecycleAccountsFake{}, &lifecycleIdentityFake{})
	if _, err := lifecycle.Status(context.Background(), provider.AuthorizationRef{Provider: provider.XAI, State: "state"}); err == nil {
		t.Fatal("status by raw state succeeded")
	}
	if service.calls.Load() != 0 {
		t.Fatalf("service calls = %d, want 0 (rejected before service)", service.calls.Load())
	}
}

// TestProviderLifecycleCancelRoutesThroughCancelBySessionID verifies that
// Cancel resolves by SessionID and dispatches to CancelBySessionID (not the
// legacy state-based Cancel), preserving the in-flight poll stop behavior
// owned by the service implementation.
func TestProviderLifecycleCancelRoutesThroughCancelBySessionID(t *testing.T) {
	service := &lifecycleServiceFake{}
	lifecycle := NewProviderLifecycle(service, &lifecycleAccountsFake{}, &lifecycleIdentityFake{})
	if err := lifecycle.Cancel(context.Background(), provider.AuthorizationRef{Provider: provider.XAI, SessionID: "session"}); err != nil {
		t.Fatalf("cancel error = %v", err)
	}
	if service.calls.Load() != 1 {
		t.Fatalf("service calls = %d, want 1 (CancelBySessionID only)", service.calls.Load())
	}
}

// TestProviderLifecycleCancelRejectsRawState verifies that Cancel by raw state
// (no SessionID) is rejected before touching the service.
func TestProviderLifecycleCancelRejectsRawState(t *testing.T) {
	service := &lifecycleServiceFake{}
	lifecycle := NewProviderLifecycle(service, &lifecycleAccountsFake{}, &lifecycleIdentityFake{})
	if err := lifecycle.Cancel(context.Background(), provider.AuthorizationRef{Provider: provider.XAI, State: "state"}); err == nil {
		t.Fatal("cancel by raw state succeeded")
	}
	if service.calls.Load() != 0 {
		t.Fatalf("service calls = %d, want 0 (rejected before service)", service.calls.Load())
	}
}

// TestProviderLifecycleCancelMapsTerminalConflict verifies that when the
// store signals a known-but-terminal session (ErrOAuthTerminalConflict), the
// xAI lifecycle maps it to the stable provider.ErrOAuthConflict sentinel so
// the admin layer can classify 409 without leaking storage detail. A genuine
// unknown (sql.ErrNoRows) is propagated as-is for 404 classification.
func TestProviderLifecycleCancelMapsTerminalConflict(t *testing.T) {
	service := &lifecycleServiceFake{cancelErr: store.ErrOAuthTerminalConflict}
	lifecycle := NewProviderLifecycle(service, &lifecycleAccountsFake{}, &lifecycleIdentityFake{})
	err := lifecycle.Cancel(context.Background(), provider.AuthorizationRef{Provider: provider.XAI, SessionID: "session"})
	if !errors.Is(err, provider.ErrOAuthConflict) {
		t.Fatalf("terminal cancel error = %v, want ErrOAuthConflict", err)
	}
	if errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("terminal conflict must not be classifiable as not-found")
	}
}

// TestProviderLifecycleCancelPropagatesUnknown verifies that a genuine
// unknown session (sql.ErrNoRows from the store) is propagated without
// wrapping so the admin layer classifies it as 404, not 409.
func TestProviderLifecycleCancelPropagatesUnknown(t *testing.T) {
	service := &lifecycleServiceFake{cancelErr: sql.ErrNoRows}
	lifecycle := NewProviderLifecycle(service, &lifecycleAccountsFake{}, &lifecycleIdentityFake{})
	err := lifecycle.Cancel(context.Background(), provider.AuthorizationRef{Provider: provider.XAI, SessionID: "missing"})
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unknown cancel error = %v, want sql.ErrNoRows", err)
	}
	if errors.Is(err, provider.ErrOAuthConflict) {
		t.Fatalf("unknown must not be classified as conflict")
	}
}

// TestProviderLifecycleCancelMatrix verifies the xAI lifecycle cancel
// classification matrix: every known-but-terminal session (consumed,
// completed, failed, expired, already cancelled) surfaces the stable
// provider.ErrOAuthConflict sentinel (409 at the admin layer), while a
// genuine unknown or wrong-provider SessionID propagates sql.ErrNoRows
// (404). ErrOAuthConflict must not wrap sql.ErrNoRows so the two classes
// are distinguishable by errors.Is. The matrix is driven by the fake
// service returning the exact sentinel the store would return for each
// terminal status, so the lifecycle mapping is exercised independently of
// store state-machine plumbing.
func TestProviderLifecycleCancelMatrix(t *testing.T) {
	cases := []struct {
		name         string
		cancelErr    error
		wantConflict bool
		wantNotFound bool
	}{
		{"consumed", store.ErrOAuthTerminalConflict, true, false},
		{"completed", store.ErrOAuthTerminalConflict, true, false},
		{"failed", store.ErrOAuthTerminalConflict, true, false},
		{"expired", store.ErrOAuthTerminalConflict, true, false},
		{"cancelled", store.ErrOAuthTerminalConflict, true, false},
		{"unknown", sql.ErrNoRows, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			service := &lifecycleServiceFake{cancelErr: tc.cancelErr}
			lifecycle := NewProviderLifecycle(service, &lifecycleAccountsFake{}, &lifecycleIdentityFake{})
			err := lifecycle.Cancel(context.Background(), provider.AuthorizationRef{Provider: provider.XAI, SessionID: "session"})
			if tc.wantConflict {
				if !errors.Is(err, provider.ErrOAuthConflict) {
					t.Fatalf("cancel %s error = %v, want ErrOAuthConflict", tc.name, err)
				}
				// ErrOAuthConflict must not be classifiable as not-found.
				if errors.Is(err, sql.ErrNoRows) {
					t.Fatalf("conflict for %s must not satisfy errors.Is(sql.ErrNoRows): %v", tc.name, err)
				}
			}
			if tc.wantNotFound {
				if !errors.Is(err, sql.ErrNoRows) {
					t.Fatalf("cancel %s error = %v, want sql.ErrNoRows", tc.name, err)
				}
				if errors.Is(err, provider.ErrOAuthConflict) {
					t.Fatalf("unknown %s must not be classified as conflict: %v", tc.name, err)
				}
			}
		})
	}
}
