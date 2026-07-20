package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"byos/internal/accounts"
	"byos/internal/api/admin"
	"byos/internal/config"
	"byos/internal/models"
	oauthdevin "byos/internal/oauth/devin"
	"byos/internal/provider"
	"byos/internal/store"
	"byos/internal/usage"
	"byos/internal/web"
)

type adapterAccountManager struct {
	values  []store.Account
	updated store.Account
}

func (m *adapterAccountManager) List(context.Context) ([]store.Account, error) {
	return append([]store.Account(nil), m.values...), nil
}
func (m *adapterAccountManager) Get(_ context.Context, id string) (store.Account, error) {
	for _, value := range m.values {
		if value.ID == id {
			return value, nil
		}
	}
	return store.Account{}, web.ErrNotFound
}
func (m *adapterAccountManager) Update(_ context.Context, id, label string, enabled bool) error {
	m.updated = store.Account{ID: id, Label: label, Enabled: enabled}
	return nil
}
func (m *adapterAccountManager) Delete(context.Context, string) error { return nil }
func (m *adapterAccountManager) Refresh(ctx context.Context, id string) (store.Account, error) {
	return m.Get(ctx, id)
}

type adapterCapabilities struct {
	values []models.Capability
}

func (c adapterCapabilities) Capabilities(context.Context, string) ([]models.Capability, error) {
	return append([]models.Capability(nil), c.values...), nil
}
func (c adapterCapabilities) Resolve(value string) (string, bool) {
	return value, value == "grok-4.5"
}

type adapterStaticModels []provider.ResolvedModel

func (m adapterStaticModels) Models() []provider.ResolvedModel {
	return append([]provider.ResolvedModel(nil), m...)
}

type adapterCredentialRefresher struct{}

func (adapterCredentialRefresher) NeedsRefresh(context.Context, string, time.Time) (bool, error) {
	return false, nil
}
func (adapterCredentialRefresher) Refresh(context.Context, string) error { return nil }

type adapterDiscoverer struct{}

func (adapterDiscoverer) Discover(context.Context, provider.Credential) ([]provider.DiscoveredModel, error) {
	return nil, nil
}

type adapterUsageFetcher struct{}

func (adapterUsageFetcher) FetchUsage(context.Context, provider.Credential) (provider.UsageSnapshot, error) {
	return provider.UsageSnapshot{}, nil
}

type adapterRegistry struct {
	values map[provider.Kind]provider.Capabilities
}

func (r adapterRegistry) Capabilities(kind provider.Kind, policyKey string) (provider.Capabilities, bool) {
	value, ok := r.values[kind]
	return value, ok && policyKey == kind.String()
}

type adapterUsage struct {
	value usage.Snapshot
}

func (u adapterUsage) Latest(context.Context, string) (usage.Snapshot, error) { return u.value, nil }

type adapterCooldowns struct {
	value store.Cooldown
}

func (c adapterCooldowns) Get(_ context.Context, _, model string, _ time.Time) (store.Cooldown, error) {
	if model == "*" {
		return store.Cooldown{}, sql.ErrNoRows
	}
	value := c.value
	value.Model = model
	return value, nil
}

type adapterRefresher struct{}

func (adapterRefresher) Refresh(context.Context, string) error { return nil }

type adapterAPIKeys struct {
	values []store.APIKey
}

func (a adapterAPIKeys) List(context.Context) ([]store.APIKey, error) {
	return append([]store.APIKey(nil), a.values...), nil
}
func (adapterAPIKeys) Create(context.Context, string) (accounts.CreatedAPIKey, error) {
	return accounts.CreatedAPIKey{Key: store.APIKey{ID: "key_new", Prefix: "byos_new", Label: "New"}, Plaintext: "byos_one_time_secret"}, nil
}
func (adapterAPIKeys) Revoke(context.Context, string) error { return nil }

func TestWebAdaptersProjectOnlySafeManagementData(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	expires := now.Add(time.Hour)
	cooldownUntil := now.Add(5 * time.Minute)
	accountManager := &adapterAccountManager{values: []store.Account{{
		Provider:  provider.XAI,
		ID:        "acct_safe",
		Label:     "Primary",
		Enabled:   true,
		Status:    "ready",
		ExpiresAt: &expires,
		LastError: "raw upstream access_token=account-error-secret",
		Credentials: store.AccountCredentials{
			Issuer: "https://auth.x.ai", Subject: "private-subject", Email: "private@example.com", AccessToken: "access-token-secret", RefreshToken: "refresh-token-secret", IDToken: "id-token-secret", RawIdentity: json.RawMessage(`{"billing":"raw-billing-secret"}`),
		},
	}}}
	capabilities := adapterCapabilities{values: []models.Capability{{Model: models.Model{ID: "grok-4.5", DisplayName: "Grok 4.5", ReasoningEfforts: []string{"low"}}, Supported: true, DiscoveredAt: now}}}
	usageReader := adapterUsage{value: usage.Snapshot{AccountID: "acct_safe", Monthly: &usage.Monthly{Used: 25, Limit: 100}, Weekly: &usage.Weekly{UsedPercent: 40}, Local: usage.Counters{Requests: 2, InputTokens: 10, OutputTokens: 4, CacheReadTokens: 6}, FetchedAt: now, Stale: true, Error: "raw billing endpoint secret"}}
	staticModels := adapterStaticModels{{PublicName: "grok-4.5", UpstreamName: "grok-4.5", Provider: provider.XAI, OwnedBy: "xai", PolicyKey: "xai"}}
	registry := adapterRegistry{values: map[provider.Kind]provider.Capabilities{provider.XAI: {CredentialRefresher: adapterCredentialRefresher{}, ModelDiscoverer: adapterDiscoverer{}, UsageFetcher: adapterUsageFetcher{}}}}
	accountAdapter := &webAccountAdapter{accounts: accountManager, models: capabilities, static: staticModels, registry: registry, usage: usageReader, cooldowns: adapterCooldowns{value: store.Cooldown{Until: &cooldownUntil, LastErrorClass: "raw provider error secret"}}, now: func() time.Time { return now }}
	usageAdapter := &webUsageAdapter{accounts: accountManager, usage: usageReader, registry: registry, refresher: adapterRefresher{}}
	modelAdapter := &webModelAdapter{accounts: accountManager, models: capabilities, static: staticModels, registry: registry, refresher: adapterRefresher{}}
	keyAdapter := &webAPIKeyAdapter{service: adapterAPIKeys{values: []store.APIKey{{ID: "key_safe", Prefix: "byos_prefix", Label: "Client", CreatedAt: now}}}}

	details, err := accountAdapter.Get(context.Background(), "acct_safe")
	if err != nil {
		t.Fatal(err)
	}
	usageValues, err := usageAdapter.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	modelValues, err := modelAdapter.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	keyValues, err := keyAdapter.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(struct {
		Account web.AccountDetail
		Usage   []web.AccountUsage
		Models  []web.ModelSupport
		Keys    []web.APIKey
	}{details, usageValues, modelValues, keyValues})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private-subject", "private@example.com", "access-token-secret", "refresh-token-secret", "id-token-secret", "raw-billing-secret", "account-error-secret", "billing endpoint secret", "provider error secret"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("Web projection contains %q: %s", forbidden, encoded)
		}
	}
	if details.SanitizedError != "Account refresh failed." || len(details.Cooldowns) != 1 || details.Cooldowns[0].LastErrorClass != "upstream" {
		t.Fatalf("safe account detail = %+v", details)
	}
	if len(usageValues) != 1 || usageValues[0].SanitizedStatus != "Usage data may be stale." || usageValues[0].Monthly.Percent == nil || *usageValues[0].Monthly.Percent != 25 || usageValues[0].Local.CacheReadTokens != 6 {
		t.Fatalf("safe usage = %+v", usageValues)
	}
	label := "Renamed"
	if err := accountAdapter.Update(context.Background(), "acct_safe", web.AccountUpdate{Label: &label}); err != nil {
		t.Fatal(err)
	}
	if accountManager.updated.Label != label || !accountManager.updated.Enabled {
		t.Fatalf("partial update lost existing fields: %+v", accountManager.updated)
	}
	created, err := keyAdapter.Create(context.Background(), "New")
	if err != nil || created.Plaintext != "byos_one_time_secret" {
		t.Fatalf("created key = %+v, %v", created, err)
	}
	listedAgain, err := keyAdapter.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	listedJSON, _ := json.Marshal(listedAgain)
	if bytes.Contains(listedJSON, []byte(created.Plaintext)) {
		t.Fatal("one-time API key appeared in list projection")
	}
}

type adapterOAuthAccounts struct {
	mu           sync.Mutex
	sessions     map[string]provider.AuthorizationSession
	started      chan struct{}
	release      chan struct{}
	once         sync.Once
	calls        atomic.Int32
	cancels      atomic.Int32
	startKinds   []provider.Kind
	resumeSignal chan provider.Kind
	cancelErr    error
	lastRef      provider.AuthorizationRef
	lastComplete provider.AuthorizationCompletion
}

func (a *adapterOAuthAccounts) sessionLocked(kind provider.Kind, sessionID provider.SessionID) (string, provider.AuthorizationSession, bool) {
	key := oauthCompletionKey(kind, sessionID.String())
	value, ok := a.sessions[key]
	if ok {
		return key, value, true
	}
	key = sessionID.String()
	value, ok = a.sessions[key]
	if !ok || value.Ref.Provider != kind {
		return "", provider.AuthorizationSession{}, false
	}
	return key, value, true
}

func (a *adapterOAuthAccounts) LoginStatus(_ context.Context, kind provider.Kind, sessionID provider.SessionID) (provider.AuthorizationSession, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, value, ok := a.sessionLocked(kind, sessionID)
	if !ok {
		return provider.AuthorizationSession{}, web.ErrNotFound
	}
	return value, nil
}

func (a *adapterOAuthAccounts) ResumeLogins(_ context.Context, kind provider.Kind) ([]provider.AuthorizationSession, error) {
	a.mu.Lock()
	result := make([]provider.AuthorizationSession, 0, len(a.sessions))
	for key, value := range a.sessions {
		if value.Ref.Provider != kind {
			continue
		}
		if kind == provider.Devin && value.Status == provider.AuthorizationConsumed {
			value.Status = provider.AuthorizationFailed
			value.SanitizedMessage = "Devin authorization could not be completed after restart. Start a new connection."
			a.sessions[key] = value
			continue
		}
		if value.Status == provider.AuthorizationPending || value.Status == provider.AuthorizationAuthorized || value.Status == provider.AuthorizationConsumed {
			result = append(result, value)
		}
	}
	signal := a.resumeSignal
	a.mu.Unlock()
	if signal != nil {
		signal <- kind
	}
	return result, nil
}

func (a *adapterOAuthAccounts) CancelLogin(_ context.Context, kind provider.Kind, sessionID provider.SessionID) error {
	a.cancels.Add(1)
	a.mu.Lock()
	defer a.mu.Unlock()
	key, value, ok := a.sessionLocked(kind, sessionID)
	if !ok {
		return web.ErrNotFound
	}
	if a.cancelErr != nil {
		return a.cancelErr
	}
	value.Status = provider.AuthorizationCancelled
	a.sessions[key] = value
	return nil
}

func (a *adapterOAuthAccounts) StartLogin(_ context.Context, kind provider.Kind) (provider.Authorization, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.startKinds = append(a.startKinds, kind)
	for _, value := range a.sessions {
		if value.Ref.Provider == kind {
			return value.Authorization, nil
		}
	}
	return provider.Authorization{}, web.ErrNotFound
}

func (a *adapterOAuthAccounts) CompleteLogin(ctx context.Context, kind provider.Kind, ref provider.AuthorizationRef, completion provider.AuthorizationCompletion) (store.Account, error) {
	a.calls.Add(1)
	if a.started != nil {
		a.once.Do(func() { close(a.started) })
	}
	select {
	case <-ctx.Done():
		return store.Account{}, ctx.Err()
	case <-a.release:
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastRef = ref
	a.lastComplete = completion
	key, value, ok := a.sessionLocked(kind, ref.SessionID)
	if !ok {
		return store.Account{}, web.ErrNotFound
	}
	value.Status = provider.AuthorizationCompleted
	value.AccountID = "acct_adapter"
	a.sessions[key] = value
	return store.Account{ID: "acct_adapter", Provider: kind}, nil
}

func TestWebOAuthManualDevinCallbackUsesBoundSession(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	const sessionID = "manual_devin_session"
	release := make(chan struct{})
	close(release)
	accountsService := &adapterOAuthAccounts{
		sessions: map[string]provider.AuthorizationSession{
			sessionID: {
				Authorization: provider.Authorization{
					Ref:       provider.AuthorizationRef{Provider: provider.Devin, SessionID: provider.SessionID(sessionID)},
					SessionID: provider.SessionID(sessionID), VerificationURL: "https://app.devin.ai/auth/cli/continue", ExpiresAt: now.Add(time.Minute),
				},
				Status: provider.AuthorizationPending,
			},
		},
		release: release,
	}
	adapter := newWebOAuthAdapter(context.Background(), accountsService)
	adapter.now = func() time.Time { return now }
	adapter.devinCallbackURL = "http://127.0.0.1:59653/callback"
	if _, err := adapter.Start(context.Background(), web.ProviderDevin); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.CompleteDevinCallback(context.Background(), sessionID, "https://byos.example.test/callback?state=s&code=c"); !errors.Is(err, oauthdevin.ErrInvalidCallback) {
		t.Fatalf("public callback error=%v", err)
	}
	if accountsService.calls.Load() != 0 {
		t.Fatal("invalid callback reached account completion")
	}
	accountID, err := adapter.CompleteDevinCallback(context.Background(), sessionID, "http://127.0.0.1:59653/callback?code=manual-code&state=manual-state")
	if err != nil || accountID != "acct_adapter" {
		t.Fatalf("account=%q err=%v", accountID, err)
	}
	accountsService.mu.Lock()
	ref, completion := accountsService.lastRef, accountsService.lastComplete
	accountsService.mu.Unlock()
	if ref.Provider != provider.Devin || ref.State != "manual-state" || ref.SessionID != provider.SessionID(sessionID) || completion.Code != "manual-code" {
		t.Fatalf("completion ref=%+v completion=%+v", ref, completion)
	}
	if adapter.authorizationURL(provider.Devin, sessionID) != "" {
		t.Fatal("completed manual callback retained authorization URL")
	}
}

func TestWebOAuthStartAndGetShareOneCompletion(t *testing.T) {
	now := time.Now().UTC()
	accountsService := &adapterOAuthAccounts{sessions: map[string]provider.AuthorizationSession{"state_adapter": {Authorization: provider.Authorization{Ref: provider.AuthorizationRef{Provider: provider.XAI, SessionID: provider.SessionID("state_adapter")}, SessionID: provider.SessionID("state_adapter"), UserCode: "CODE", VerificationURLComplete: "https://auth.x.ai/device", PollInterval: 5 * time.Second, ExpiresAt: now.Add(time.Minute)}, Status: provider.AuthorizationPending}}, started: make(chan struct{}), release: make(chan struct{})}
	rootCtx, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()
	adapter := newWebOAuthAdapter(rootCtx, accountsService)
	adapter.now = func() time.Time { return now }
	flow, err := adapter.Start(context.Background(), web.ProviderXAI)
	if err != nil || flow.SessionID != "state_adapter" || flow.State != "xai/state_adapter" {
		t.Fatalf("started flow = %+v, %v", flow, err)
	}
	<-accountsService.started
	for range 3 {
		if _, err := adapter.Get(context.Background(), web.ProviderXAI, flow.SessionID); err != nil {
			t.Fatal(err)
		}
	}
	if accountsService.calls.Load() != 1 {
		t.Fatalf("Start/Get spawned %d completion paths", accountsService.calls.Load())
	}
	close(accountsService.release)
	deadline := time.Now().Add(time.Second)
	for {
		completed, err := adapter.Get(context.Background(), web.ProviderXAI, flow.SessionID)
		if err != nil {
			t.Fatal(err)
		}
		if completed.Status == "completed" {
			if completed.AccountID != "acct_adapter" {
				t.Fatalf("completed flow = %+v", completed)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("completion did not become observable")
		}
		time.Sleep(time.Millisecond)
	}
}

type adminOAuthAccounts struct{ *adapterOAuthAccounts }

func (a *adminOAuthAccounts) List(context.Context) ([]store.Account, error) {
	value, err := a.LoginStatus(context.Background(), provider.XAI, provider.SessionID("state_adapter"))
	if err != nil || value.AccountID == "" {
		return nil, err
	}
	return []store.Account{{ID: value.AccountID, Provider: provider.XAI}}, nil
}

func (*adminOAuthAccounts) Update(context.Context, string, string, bool) error { return nil }
func (*adminOAuthAccounts) Delete(context.Context, string) error               { return nil }
func (*adminOAuthAccounts) Refresh(context.Context, string) (store.Account, error) {
	return store.Account{}, nil
}

func TestAdminDeviceFlowUsesSharedBackgroundCompletion(t *testing.T) {
	now := time.Now().UTC()
	accountsService := &adapterOAuthAccounts{sessions: map[string]provider.AuthorizationSession{"state_adapter": {Authorization: provider.Authorization{Ref: provider.AuthorizationRef{Provider: provider.XAI, SessionID: provider.SessionID("state_adapter")}, SessionID: provider.SessionID("state_adapter"), UserCode: "CODE", VerificationURLComplete: "https://auth.x.ai/device", PollInterval: time.Millisecond, ExpiresAt: now.Add(time.Minute)}, Status: provider.AuthorizationPending}}, started: make(chan struct{}), release: make(chan struct{})}
	adminAccounts := &adminOAuthAccounts{adapterOAuthAccounts: accountsService}
	rootCtx, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()
	completion := newWebOAuthAdapter(rootCtx, accountsService)
	handler := admin.NewHandler(admin.Services{Accounts: adminAccounts, Completion: completion})

	postCtx, cancelPost := context.WithCancel(context.Background())
	postRequest := httptest.NewRequest(http.MethodPost, "/admin/api/v1/oauth/xai/device", nil).WithContext(postCtx)
	postResponse := httptest.NewRecorder()
	handler.ServeHTTP(postResponse, postRequest)
	if postResponse.Code != http.StatusCreated {
		t.Fatalf("POST status = %d, body = %s", postResponse.Code, postResponse.Body.String())
	}
	cancelPost()
	<-accountsService.started
	for range 2 {
		pollRequest := httptest.NewRequest(http.MethodGet, "/admin/api/v1/oauth/xai/device/state_adapter", nil)
		pollResponse := httptest.NewRecorder()
		handler.ServeHTTP(pollResponse, pollRequest)
		if pollResponse.Code != http.StatusAccepted {
			t.Fatalf("pending GET status = %d, body = %s", pollResponse.Code, pollResponse.Body.String())
		}
	}
	if accountsService.calls.Load() != 1 {
		t.Fatalf("REST start/polls spawned %d completion paths", accountsService.calls.Load())
	}

	close(accountsService.release)
	deadline := time.Now().Add(time.Second)
	for {
		pollRequest := httptest.NewRequest(http.MethodGet, "/admin/api/v1/oauth/xai/device/state_adapter", nil)
		pollResponse := httptest.NewRecorder()
		handler.ServeHTTP(pollResponse, pollRequest)
		if pollResponse.Code == http.StatusOK {
			var body struct {
				Status    string `json:"status"`
				AccountID string `json:"account_id"`
			}
			if err := json.Unmarshal(pollResponse.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Status != "completed" || body.AccountID != "acct_adapter" {
				t.Fatalf("completed GET body = %+v", body)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("REST completion not observable: status=%d body=%s", pollResponse.Code, pollResponse.Body.String())
		}
		time.Sleep(time.Millisecond)
	}
	if accountsService.calls.Load() != 1 {
		t.Fatalf("completed polls spawned %d completion paths", accountsService.calls.Load())
	}
}

func TestWebOAuthRunResumesPersistedSession(t *testing.T) {
	now := time.Now().UTC()
	accountsService := &adapterOAuthAccounts{sessions: map[string]provider.AuthorizationSession{"restart_state": {Authorization: provider.Authorization{Ref: provider.AuthorizationRef{Provider: provider.XAI, SessionID: provider.SessionID("restart_state")}, SessionID: provider.SessionID("restart_state"), ExpiresAt: now.Add(time.Minute), PollInterval: 5 * time.Second}, Status: provider.AuthorizationPending}}, started: make(chan struct{}), release: make(chan struct{})}
	rootCtx, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()
	adapter := newWebOAuthAdapter(rootCtx, accountsService)
	runCtx, cancelRun := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- adapter.Run(runCtx) }()
	<-accountsService.started
	if accountsService.calls.Load() != 1 {
		t.Fatalf("restart resume calls = %d", accountsService.calls.Load())
	}
	close(accountsService.release)
	deadline := time.Now().Add(time.Second)
	for {
		value, _ := accountsService.LoginStatus(context.Background(), provider.XAI, provider.SessionID("restart_state"))
		if value.Status == provider.AuthorizationCompleted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("resumed flow did not complete")
		}
		time.Sleep(time.Millisecond)
	}
	cancelRun()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
}

func TestWebOAuthRunShutdownDoesNotPersistCancellation(t *testing.T) {
	now := time.Now().UTC()
	accountsService := &adapterOAuthAccounts{sessions: map[string]provider.AuthorizationSession{"shutdown_state": {Authorization: provider.Authorization{Ref: provider.AuthorizationRef{Provider: provider.XAI, SessionID: provider.SessionID("shutdown_state")}, SessionID: provider.SessionID("shutdown_state"), ExpiresAt: now.Add(time.Minute)}, Status: provider.AuthorizationAuthorized}}, started: make(chan struct{}), release: make(chan struct{})}
	rootCtx, cancelRoot := context.WithCancel(context.Background())
	adapter := newWebOAuthAdapter(rootCtx, accountsService)
	runCtx, cancelRun := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- adapter.Run(runCtx) }()
	<-accountsService.started
	cancelRun()
	cancelRoot()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
	if accountsService.cancels.Load() != 0 {
		t.Fatalf("shutdown persisted %d cancellations", accountsService.cancels.Load())
	}
	value, err := accountsService.LoginStatus(context.Background(), provider.XAI, provider.SessionID("shutdown_state"))
	if err != nil || value.Status != provider.AuthorizationAuthorized {
		t.Fatalf("shutdown session = %+v, %v", value, err)
	}
}

func TestRuntimeMountsWebHandler(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Server.TrustedProxies = []string{"192.0.2.0/24"}
	master := bytes.Repeat([]byte{31}, 32)
	t.Setenv("BYOS_MASTER_KEY", base64.StdEncoding.EncodeToString(master))
	t.Setenv("BYOS_ADMIN_PASSWORD", "runtime-admin-password")
	t.Setenv("BYOS_ADMIN_API_KEY", "runtime-admin-api-key")
	secrets, err := config.LoadSecrets()
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := New(context.Background(), cfg, secrets, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	request := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	response := httptest.NewRecorder()
	runtime.Server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Administrator password") {
		t.Fatalf("Web login route = %d %q", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Security-Policy") == "" || len(response.Result().Cookies()) == 0 {
		t.Fatalf("Web login route missing security state: headers=%v", response.Header())
	}

	trustedRequest := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	trustedRequest.RemoteAddr = "192.0.2.10:1234"
	trustedRequest.Header.Set("X-Forwarded-Proto", "https")
	trustedResponse := httptest.NewRecorder()
	runtime.Server.Handler.ServeHTTP(trustedResponse, trustedRequest)
	if trustedResponse.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("trusted HTTPS proxy did not enable HSTS")
	}
	for _, cookie := range trustedResponse.Result().Cookies() {
		if !cookie.Secure {
			t.Fatalf("trusted proxy cookie is not Secure: %+v", cookie)
		}
	}
	untrustedRequest := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	untrustedRequest.RemoteAddr = "203.0.113.10:1234"
	untrustedRequest.Header.Set("X-Forwarded-Proto", "https")
	untrustedResponse := httptest.NewRecorder()
	runtime.Server.Handler.ServeHTTP(untrustedResponse, untrustedRequest)
	if untrustedResponse.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("untrusted proxy enabled HSTS")
	}
	for _, cookie := range untrustedResponse.Result().Cookies() {
		if cookie.Secure {
			t.Fatalf("untrusted proxy enabled Secure cookie: %+v", cookie)
		}
	}

	request = httptest.NewRequest(http.MethodGet, "/admin/", nil)
	response = httptest.NewRecorder()
	runtime.Server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/admin/login" {
		t.Fatalf("mounted Web root = %d %q", response.Code, response.Header().Get("Location"))
	}
}

func webTestAuthorizationSession(kind provider.Kind, sessionID, authorizationURL string, status provider.AuthorizationStatus, expiresAt time.Time) provider.AuthorizationSession {
	return provider.AuthorizationSession{
		Authorization: provider.Authorization{
			Ref:             provider.AuthorizationRef{Provider: kind, SessionID: provider.SessionID(sessionID)},
			SessionID:       provider.SessionID(sessionID),
			VerificationURL: authorizationURL,
			ExpiresAt:       expiresAt,
			PollInterval:    5 * time.Second,
		},
		Status: status,
	}
}

func TestWebOAuthDevinFlowIsProviderBoundAndCallbackDriven(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	const sessionID = "devin_session"
	const authorizationURL = "https://app.devin.ai/oauth/authorize?state=state-secret-canary"
	accountsService := &adapterOAuthAccounts{sessions: map[string]provider.AuthorizationSession{
		sessionID: webTestAuthorizationSession(provider.Devin, sessionID, authorizationURL, provider.AuthorizationPending, now.Add(10*time.Minute)),
	}}
	rootCtx, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()
	adapter := newWebOAuthAdapter(rootCtx, accountsService)
	adapter.now = func() time.Time { return now }

	flow, err := adapter.Start(context.Background(), web.ProviderDevin)
	if err != nil || flow.Provider != web.ProviderDevin || flow.SessionID != sessionID || flow.State != "devin/"+sessionID || flow.AuthorizationURL != authorizationURL {
		t.Fatalf("Devin start = %+v, %v", flow, err)
	}
	if len(accountsService.startKinds) != 1 || accountsService.startKinds[0] != provider.Devin {
		t.Fatalf("Devin start providers = %v", accountsService.startKinds)
	}
	if accountsService.calls.Load() != 0 {
		t.Fatalf("Devin start spawned %d background completions", accountsService.calls.Load())
	}
	if _, err := adapter.Get(context.Background(), web.ProviderXAI, sessionID); !errors.Is(err, web.ErrNotFound) {
		t.Fatalf("wrong-provider Devin status error = %v", err)
	}
	pending, err := adapter.Get(context.Background(), web.ProviderDevin, sessionID)
	if err != nil || pending.Status != "pending" {
		t.Fatalf("Devin pending status = %+v, %v", pending, err)
	}

	accountsService.mu.Lock()
	completed := accountsService.sessions[sessionID]
	completed.Status = provider.AuthorizationCompleted
	completed.AccountID = "acct_devin"
	accountsService.sessions[sessionID] = completed
	accountsService.mu.Unlock()
	flow, err = adapter.Get(context.Background(), web.ProviderDevin, sessionID)
	if err != nil || flow.Status != "completed" || flow.AccountID != "acct_devin" {
		t.Fatalf("callback-completed Devin status = %+v, %v", flow, err)
	}
	if accountsService.calls.Load() != 0 {
		t.Fatalf("Devin callback observation spawned %d background completions", accountsService.calls.Load())
	}
	adapter.mu.Lock()
	active := len(adapter.active)
	adapter.mu.Unlock()
	if active != 0 || adapter.authorizationURL(provider.Devin, sessionID) != "" {
		t.Fatalf("completed Devin flow retained active=%d authorization URL", active)
	}
}

func TestWebOAuthTerminalStatusesForgetAuthorizationURL(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name      string
		status    provider.AuthorizationStatus
		expiresAt time.Time
		want      string
	}{
		{name: "completed", status: provider.AuthorizationCompleted, expiresAt: now.Add(time.Minute), want: "completed"},
		{name: "failed", status: provider.AuthorizationFailed, expiresAt: now.Add(time.Minute), want: "failed"},
		{name: "expired", status: provider.AuthorizationExpired, expiresAt: now.Add(time.Minute), want: "expired"},
		{name: "cancelled", status: provider.AuthorizationCancelled, expiresAt: now.Add(time.Minute), want: "cancelled"},
		{name: "pending past deadline", status: provider.AuthorizationPending, expiresAt: now, want: "expired"},
	} {
		t.Run(test.name, func(t *testing.T) {
			const sessionID = "terminal_session"
			const authorizationURL = "https://app.devin.ai/oauth/authorize?state=terminal-state-canary"
			accountsService := &adapterOAuthAccounts{sessions: map[string]provider.AuthorizationSession{
				sessionID: webTestAuthorizationSession(provider.Devin, sessionID, authorizationURL, test.status, test.expiresAt),
			}}
			adapter := newWebOAuthAdapter(context.Background(), accountsService)
			adapter.now = func() time.Time { return now }
			if _, err := adapter.Start(context.Background(), web.ProviderDevin); err != nil {
				t.Fatal(err)
			}
			flow, err := adapter.Get(context.Background(), web.ProviderDevin, sessionID)
			if err != nil || flow.Status != test.want {
				t.Fatalf("terminal flow = %+v, %v; want %q", flow, err, test.want)
			}
			if adapter.authorizationURL(provider.Devin, sessionID) != "" {
				t.Fatal("terminal flow retained its authorization URL")
			}
		})
	}
}

func TestWebOAuthCancelForgetsOnlyProviderBoundAuthorizationURL(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	const sessionID = "cancel_session"
	cancelErr := errors.New("provider cancellation unavailable")
	accountsService := &adapterOAuthAccounts{
		sessions: map[string]provider.AuthorizationSession{
			sessionID: webTestAuthorizationSession(provider.Devin, sessionID, "https://app.devin.ai/oauth/authorize?state=cancel-state-canary", provider.AuthorizationPending, now.Add(time.Minute)),
		},
		cancelErr: cancelErr,
	}
	adapter := newWebOAuthAdapter(context.Background(), accountsService)
	adapter.now = func() time.Time { return now }
	if _, err := adapter.Start(context.Background(), web.ProviderDevin); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Cancel(context.Background(), web.ProviderXAI, sessionID); !errors.Is(err, web.ErrNotFound) {
		t.Fatalf("wrong-provider cancel error = %v", err)
	}
	if adapter.authorizationURL(provider.Devin, sessionID) == "" {
		t.Fatal("wrong-provider cancel cleared the Devin authorization URL")
	}
	if err := adapter.Cancel(context.Background(), web.ProviderDevin, sessionID); !errors.Is(err, cancelErr) {
		t.Fatalf("Devin cancel error = %v", err)
	}
	if adapter.authorizationURL(provider.Devin, sessionID) != "" {
		t.Fatal("failed Devin cancel retained the authorization URL")
	}
}

func TestWebOAuthCompletionExitForgetsAuthorizationURL(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	const sessionID = "completion_session"
	accountsService := &adapterOAuthAccounts{
		sessions: map[string]provider.AuthorizationSession{
			sessionID: webTestAuthorizationSession(provider.XAI, sessionID, "https://accounts.x.ai/device?state=xai-state-canary", provider.AuthorizationPending, now.Add(time.Minute)),
		},
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	rootCtx, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()
	adapter := newWebOAuthAdapter(rootCtx, accountsService)
	adapter.now = func() time.Time { return now }
	if _, err := adapter.Start(context.Background(), web.ProviderXAI); err != nil {
		t.Fatal(err)
	}
	<-accountsService.started
	key := oauthCompletionKey(provider.XAI, sessionID)
	adapter.mu.Lock()
	completion := adapter.active[key]
	cached := adapter.authorizationURLs[key]
	adapter.mu.Unlock()
	if completion == nil || cached.url == "" {
		t.Fatalf("active completion=%v cached URL=%q", completion != nil, cached.url)
	}
	close(accountsService.release)
	<-completion.done
	if adapter.authorizationURL(provider.XAI, sessionID) != "" {
		t.Fatal("xAI completion exit retained the authorization URL")
	}
}

func TestWebOAuthRunRecoversConsumedDevinWithoutBackgroundCompletion(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	const sessionID = "consumed_session"
	accountsService := &adapterOAuthAccounts{
		sessions: map[string]provider.AuthorizationSession{
			sessionID: webTestAuthorizationSession(provider.Devin, sessionID, "", provider.AuthorizationConsumed, now.Add(time.Minute)),
		},
		resumeSignal: make(chan provider.Kind, 2),
	}
	adapter := newWebOAuthAdapter(context.Background(), accountsService)
	adapter.now = func() time.Time { return now }
	runCtx, cancelRun := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- adapter.Run(runCtx) }()
	if kind := <-accountsService.resumeSignal; kind != provider.XAI {
		t.Fatalf("first resume provider = %q", kind)
	}
	if kind := <-accountsService.resumeSignal; kind != provider.Devin {
		t.Fatalf("second resume provider = %q", kind)
	}
	flow, err := adapter.Get(context.Background(), web.ProviderDevin, sessionID)
	if err != nil || flow.Status != "failed" || !strings.Contains(flow.SanitizedMessage, "after restart") {
		t.Fatalf("recovered consumed Devin flow = %+v, %v", flow, err)
	}
	if accountsService.calls.Load() != 0 {
		t.Fatalf("Devin restart recovery spawned %d background completions", accountsService.calls.Load())
	}
	cancelRun()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
}

func TestWebOAuthRunShutdownClearsAuthorizationState(t *testing.T) {
	accountsService := &adapterOAuthAccounts{sessions: make(map[string]provider.AuthorizationSession), resumeSignal: make(chan provider.Kind, 2)}
	adapter := newWebOAuthAdapter(context.Background(), accountsService)
	adapter.rememberAuthorizationURL(provider.XAI, "xai_session", "https://accounts.x.ai/device?state=xai-shutdown-canary", time.Now().UTC().Add(time.Minute))
	adapter.rememberAuthorizationURL(provider.Devin, "devin_session", "https://app.devin.ai/oauth/authorize?state=devin-shutdown-canary", time.Now().UTC().Add(time.Minute))
	runCtx, cancelRun := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- adapter.Run(runCtx) }()
	<-accountsService.resumeSignal
	<-accountsService.resumeSignal
	cancelRun()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
	adapter.mu.Lock()
	closed := adapter.closed
	activeNil := adapter.active == nil
	URLsNil := adapter.authorizationURLs == nil
	adapter.mu.Unlock()
	if !closed || !activeNil || !URLsNil {
		t.Fatalf("shutdown state closed=%t activeNil=%t URLsNil=%t", closed, activeNil, URLsNil)
	}
	adapter.rememberAuthorizationURL(provider.Devin, "late_session", "https://app.devin.ai/oauth/authorize?state=late-canary", time.Now().UTC().Add(time.Minute))
	if adapter.authorizationURL(provider.Devin, "late_session") != "" {
		t.Fatal("closed adapter retained a late authorization URL")
	}
}

// TestWebOAuthSweepClearsOnCallbackCompletionWithoutPoll proves the cached
// authorization URL is cleared on exact callback completion even when the
// browser never calls Web Get or Cancel. The admin callback handler completes
// Devin out-of-band via accountService.CompleteLogin; the independent sweeper
// observes the terminal status through LoginStatus and evicts the cache entry.
func TestWebOAuthSweepClearsOnCallbackCompletionWithoutPoll(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	const sessionID = "sweep_completion_session"
	const authorizationURL = "https://app.devin.ai/oauth/authorize?state=sweep-completion-canary"
	accountsService := &adapterOAuthAccounts{
		sessions: map[string]provider.AuthorizationSession{
			sessionID: webTestAuthorizationSession(provider.Devin, sessionID, authorizationURL, provider.AuthorizationPending, now.Add(10*time.Minute)),
		},
	}
	adapter := newWebOAuthAdapter(context.Background(), accountsService)
	adapter.now = func() time.Time { return now }
	if _, err := adapter.Start(context.Background(), web.ProviderDevin); err != nil {
		t.Fatal(err)
	}
	if adapter.authorizationURL(provider.Devin, sessionID) != authorizationURL {
		t.Fatalf("cached URL = %q, want %q", adapter.authorizationURL(provider.Devin, sessionID), authorizationURL)
	}
	// Simulate the admin callback handler completing Devin out-of-band, with
	// no Web Get/Cancel involved.
	accountsService.mu.Lock()
	completed := accountsService.sessions[sessionID]
	completed.Status = provider.AuthorizationCompleted
	completed.AccountID = "acct_devin_sweep"
	accountsService.sessions[sessionID] = completed
	accountsService.mu.Unlock()
	// No Get/Cancel call — drive the sweeper directly.
	adapter.sweep(context.Background())
	if adapter.authorizationURL(provider.Devin, sessionID) != "" {
		t.Fatal("sweep did not clear the callback-completed Devin authorization URL without a poll")
	}
	if accountsService.calls.Load() != 0 {
		t.Fatalf("sweep spawned %d background completions for Devin", accountsService.calls.Load())
	}
}

// TestWebOAuthSweepEvictsAbandonedExpiry proves the cached authorization URL
// is evicted at ExpiresAt by the independent sweeper even when the browser
// never polls and the lifecycle session is gone (LoginStatus returns
// not-found). Expiry is driven solely by the cached ExpiresAt metadata.
func TestWebOAuthSweepEvictsAbandonedExpiry(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	const sessionID = "sweep_abandoned_session"
	const authorizationURL = "https://app.devin.ai/oauth/authorize?state=sweep-abandoned-canary"
	accountsService := &adapterOAuthAccounts{
		sessions: map[string]provider.AuthorizationSession{
			sessionID: webTestAuthorizationSession(provider.Devin, sessionID, authorizationURL, provider.AuthorizationPending, now.Add(time.Minute)),
		},
	}
	adapter := newWebOAuthAdapter(context.Background(), accountsService)
	adapter.now = func() time.Time { return now }
	if _, err := adapter.Start(context.Background(), web.ProviderDevin); err != nil {
		t.Fatal(err)
	}
	if adapter.authorizationURL(provider.Devin, sessionID) != authorizationURL {
		t.Fatalf("cached URL = %q, want %q", adapter.authorizationURL(provider.Devin, sessionID), authorizationURL)
	}
	// Abandon: advance time past ExpiresAt and drop the lifecycle session so
	// LoginStatus cannot resolve it. The sweeper must still evict by metadata.
	afterExpiry := now.Add(2 * time.Minute)
	adapter.now = func() time.Time { return afterExpiry }
	accountsService.mu.Lock()
	delete(accountsService.sessions, sessionID)
	accountsService.mu.Unlock()
	adapter.sweep(context.Background())
	if adapter.authorizationURL(provider.Devin, sessionID) != "" {
		t.Fatal("sweep did not evict the abandoned expired authorization URL by ExpiresAt metadata")
	}
}

// TestWebOAuthSweepResumesNoPollXAICompletion proves the sweeper proactively
// completes an xAI session that the provider reports authorized without the
// browser polling, so the cached URL is cleared by the completion exit path
// rather than stranded until the next Get.
func TestWebOAuthSweepResumesNoPollXAICompletion(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	const sessionID = "sweep_xai_no_poll"
	const authorizationURL = "https://accounts.x.ai/device?state=sweep-xai-canary"
	accountsService := &adapterOAuthAccounts{
		sessions: map[string]provider.AuthorizationSession{
			sessionID: webTestAuthorizationSession(provider.XAI, sessionID, authorizationURL, provider.AuthorizationAuthorized, now.Add(10*time.Minute)),
		},
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	rootCtx, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()
	adapter := newWebOAuthAdapter(rootCtx, accountsService)
	adapter.now = func() time.Time { return now }
	if _, err := adapter.Start(context.Background(), web.ProviderXAI); err != nil {
		t.Fatal(err)
	}
	// Start already resumed the xAI completion; wait for it to register, then
	// release it so the goroutine exits and clears the URL.
	<-accountsService.started
	close(accountsService.release)
	key := oauthCompletionKey(provider.XAI, sessionID)
	adapter.mu.Lock()
	completion := adapter.active[key]
	adapter.mu.Unlock()
	if completion == nil {
		t.Fatal("xAI completion goroutine was not registered by Start")
	}
	<-completion.done
	if adapter.authorizationURL(provider.XAI, sessionID) != "" {
		t.Fatal("xAI completion exit did not clear the authorization URL")
	}
}

// TestWebOAuthAuthorizationURLMapBoundedAndCleared proves the cache map is
// bounded by eviction: completed, cancelled, and expired entries are all
// cleared so the map never grows unbounded across flows, and shutdown nils it.
func TestWebOAuthAuthorizationURLMapBoundedAndCleared(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	accountsService := &adapterOAuthAccounts{sessions: map[string]provider.AuthorizationSession{}}
	adapter := newWebOAuthAdapter(context.Background(), accountsService)
	adapter.now = func() time.Time { return now }
	// Seed three cached URLs with distinct fates.
	adapter.rememberAuthorizationURL(provider.Devin, "completed_session", "https://app.devin.ai/oauth/authorize?state=completed-canary", now.Add(time.Minute))
	adapter.rememberAuthorizationURL(provider.Devin, "cancelled_session", "https://app.devin.ai/oauth/authorize?state=cancelled-canary", now.Add(time.Minute))
	adapter.rememberAuthorizationURL(provider.Devin, "expired_session", "https://app.devin.ai/oauth/authorize?state=expired-canary", now.Add(time.Minute))
	accountsService.mu.Lock()
	accountsService.sessions["completed_session"] = webTestAuthorizationSession(provider.Devin, "completed_session", "", provider.AuthorizationCompleted, now.Add(time.Minute))
	accountsService.sessions["cancelled_session"] = webTestAuthorizationSession(provider.Devin, "cancelled_session", "", provider.AuthorizationCancelled, now.Add(time.Minute))
	accountsService.sessions["expired_session"] = webTestAuthorizationSession(provider.Devin, "expired_session", "", provider.AuthorizationExpired, now.Add(time.Minute))
	accountsService.mu.Unlock()
	adapter.sweep(context.Background())
	adapter.mu.Lock()
	count := len(adapter.authorizationURLs)
	adapter.mu.Unlock()
	if count != 0 {
		remaining := make([]string, 0)
		adapter.mu.Lock()
		for key := range adapter.authorizationURLs {
			remaining = append(remaining, key)
		}
		adapter.mu.Unlock()
		t.Fatalf("sweep left %d cached URLs: %v", count, remaining)
	}
}

// TestWebOAuthRunSweepTickerEvictsExpiredWithoutPoll proves the Run loop's
// bounded ticker independently evicts an expired cached URL when the browser
// never polls, exercising the real sweeper path under Run with a short sweep
// interval.
func TestWebOAuthRunSweepTickerEvictsExpiredWithoutPoll(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	const sessionID = "run_sweep_expired"
	const authorizationURL = "https://app.devin.ai/oauth/authorize?state=run-sweep-canary"
	accountsService := &adapterOAuthAccounts{
		sessions: map[string]provider.AuthorizationSession{
			sessionID: webTestAuthorizationSession(provider.Devin, sessionID, authorizationURL, provider.AuthorizationPending, now.Add(20*time.Millisecond)),
		},
		resumeSignal: make(chan provider.Kind, 2),
	}
	rootCtx, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()
	adapter := newWebOAuthAdapter(rootCtx, accountsService)
	adapter.sweepInterval = 10 * time.Millisecond
	var current atomic.Value
	current.Store(now)
	adapter.now = func() time.Time { return current.Load().(time.Time) }
	if _, err := adapter.Start(context.Background(), web.ProviderDevin); err != nil {
		t.Fatal(err)
	}
	runCtx, cancelRun := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- adapter.Run(runCtx) }()
	<-accountsService.resumeSignal
	<-accountsService.resumeSignal
	current.Store(now.Add(time.Minute))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if adapter.authorizationURL(provider.Devin, sessionID) == "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancelRun()
	_ = <-done
	if adapter.authorizationURL(provider.Devin, sessionID) != "" {
		t.Fatal("Run sweep ticker did not evict the expired authorization URL without a poll")
	}
}

// TestWebOAuthShutdownCleansUpSweepAndURLsRace proves shutdown clears the
// cache and drains the active completion goroutines without leaking, even when
// a sweep is concurrent with shutdown. Run with -race to detect data races.
func TestWebOAuthShutdownCleansUpSweepAndURLsRace(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	const sessionID = "shutdown_race_session"
	const authorizationURL = "https://app.devin.ai/oauth/authorize?state=shutdown-race-canary"
	accountsService := &adapterOAuthAccounts{
		sessions: map[string]provider.AuthorizationSession{
			sessionID: webTestAuthorizationSession(provider.Devin, sessionID, authorizationURL, provider.AuthorizationPending, now.Add(10*time.Minute)),
		},
		resumeSignal: make(chan provider.Kind, 2),
	}
	rootCtx, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()
	adapter := newWebOAuthAdapter(rootCtx, accountsService)
	adapter.sweepInterval = 5 * time.Millisecond
	adapter.now = func() time.Time { return now }
	if _, err := adapter.Start(context.Background(), web.ProviderDevin); err != nil {
		t.Fatal(err)
	}
	runCtx, cancelRun := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- adapter.Run(runCtx) }()
	<-accountsService.resumeSignal
	<-accountsService.resumeSignal
	// Let a few sweep ticks fire concurrently with shutdown.
	time.Sleep(20 * time.Millisecond)
	cancelRun()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
	adapter.mu.Lock()
	closed := adapter.closed
	activeNil := adapter.active == nil
	urlsNil := adapter.authorizationURLs == nil
	adapter.mu.Unlock()
	if !closed || !activeNil || !urlsNil {
		t.Fatalf("shutdown state closed=%t activeNil=%t urlsNil=%t", closed, activeNil, urlsNil)
	}
	// A late remember after shutdown must not re-populate the cache.
	adapter.rememberAuthorizationURL(provider.Devin, "late_shutdown_session", "https://app.devin.ai/oauth/authorize?state=late-shutdown-canary", now.Add(time.Minute))
	if adapter.authorizationURL(provider.Devin, "late_shutdown_session") != "" {
		t.Fatal("closed adapter retained a late authorization URL after shutdown race")
	}
}
