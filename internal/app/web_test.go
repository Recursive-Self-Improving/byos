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
	usageReader := adapterUsage{value: usage.Snapshot{AccountID: "acct_safe", Monthly: &usage.Monthly{Used: 25, Limit: 100}, Weekly: &usage.Weekly{UsedPercent: 40}, Local: usage.Counters{Requests: 2, InputTokens: 10, OutputTokens: 4}, FetchedAt: now, Stale: true, Error: "raw billing endpoint secret"}}
	accountAdapter := &webAccountAdapter{accounts: accountManager, models: capabilities, usage: usageReader, cooldowns: adapterCooldowns{value: store.Cooldown{Until: &cooldownUntil, LastErrorClass: "raw provider error secret"}}, now: func() time.Time { return now }}
	usageAdapter := &webUsageAdapter{accounts: accountManager, usage: usageReader, refresher: adapterRefresher{}}
	modelAdapter := &webModelAdapter{accounts: accountManager, models: capabilities, refresher: adapterRefresher{}}
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
	if len(usageValues) != 1 || usageValues[0].SanitizedStatus != "Usage data may be stale." || usageValues[0].Monthly.Percent == nil || *usageValues[0].Monthly.Percent != 25 {
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
	mu       sync.Mutex
	sessions map[string]provider.AuthorizationSession
	started  chan struct{}
	release  chan struct{}
	once     sync.Once
	calls    atomic.Int32
	cancels  atomic.Int32
}

func (a *adapterOAuthAccounts) LoginStatus(_ context.Context, _ provider.Kind, state string) (provider.AuthorizationSession, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	value, ok := a.sessions[state]
	if !ok {
		return provider.AuthorizationSession{}, web.ErrNotFound
	}
	return value, nil
}
func (a *adapterOAuthAccounts) ResumeLogins(context.Context, provider.Kind) ([]provider.AuthorizationSession, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	result := make([]provider.AuthorizationSession, 0, len(a.sessions))
	for _, value := range a.sessions {
		if value.Status == provider.AuthorizationPending || value.Status == provider.AuthorizationAuthorized {
			result = append(result, value)
		}
	}
	return result, nil
}
func (a *adapterOAuthAccounts) CancelLogin(_ context.Context, _ provider.Kind, state string) error {
	a.cancels.Add(1)
	a.mu.Lock()
	defer a.mu.Unlock()
	value, ok := a.sessions[state]
	if !ok {
		return web.ErrNotFound
	}
	value.Status = provider.AuthorizationCancelled
	a.sessions[state] = value
	return nil
}
func (a *adapterOAuthAccounts) StartLogin(context.Context, provider.Kind) (provider.Authorization, error) {
	value, _ := a.LoginStatus(context.Background(), provider.XAI, "state_adapter")
	return value.Authorization, nil
}
func (a *adapterOAuthAccounts) CompleteLogin(ctx context.Context, _ provider.Kind, state string, _ provider.AuthorizationCompletion) (store.Account, error) {
	a.calls.Add(1)
	a.once.Do(func() { close(a.started) })
	select {
	case <-ctx.Done():
		return store.Account{}, ctx.Err()
	case <-a.release:
	}
	a.mu.Lock()
	value := a.sessions[state]
	value.Status = provider.AuthorizationCompleted
	value.AccountID = "acct_adapter"
	a.sessions[state] = value
	a.mu.Unlock()
	return store.Account{ID: "acct_adapter"}, nil
}

func TestWebOAuthStartAndGetShareOneCompletion(t *testing.T) {
	now := time.Now().UTC()
	accountsService := &adapterOAuthAccounts{sessions: map[string]provider.AuthorizationSession{"state_adapter": {Authorization: provider.Authorization{Ref: provider.AuthorizationRef{Provider: provider.XAI, State: "state_adapter"}, UserCode: "CODE", VerificationURLComplete: "https://auth.x.ai/device", PollInterval: 5 * time.Second, ExpiresAt: now.Add(time.Minute)}, Status: provider.AuthorizationPending}}, started: make(chan struct{}), release: make(chan struct{})}
	rootCtx, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()
	adapter := newWebOAuthAdapter(rootCtx, accountsService)
	adapter.now = func() time.Time { return now }
	flow, err := adapter.Start(context.Background())
	if err != nil || flow.State != "state_adapter" {
		t.Fatalf("started flow = %+v, %v", flow, err)
	}
	<-accountsService.started
	for range 3 {
		if _, err := adapter.Get(context.Background(), flow.State); err != nil {
			t.Fatal(err)
		}
	}
	if accountsService.calls.Load() != 1 {
		t.Fatalf("Start/Get spawned %d completion paths", accountsService.calls.Load())
	}
	close(accountsService.release)
	deadline := time.Now().Add(time.Second)
	for {
		completed, err := adapter.Get(context.Background(), flow.State)
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
	value, err := a.LoginStatus(context.Background(), provider.XAI, "state_adapter")
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
	accountsService := &adapterOAuthAccounts{sessions: map[string]provider.AuthorizationSession{"state_adapter": {Authorization: provider.Authorization{Ref: provider.AuthorizationRef{Provider: provider.XAI, State: "state_adapter"}, UserCode: "CODE", VerificationURLComplete: "https://auth.x.ai/device", PollInterval: time.Millisecond, ExpiresAt: now.Add(time.Minute)}, Status: provider.AuthorizationPending}}, started: make(chan struct{}), release: make(chan struct{})}
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
	accountsService := &adapterOAuthAccounts{sessions: map[string]provider.AuthorizationSession{"restart_state": {Authorization: provider.Authorization{Ref: provider.AuthorizationRef{Provider: provider.XAI, State: "restart_state"}, ExpiresAt: now.Add(time.Minute), PollInterval: 5 * time.Second}, Status: provider.AuthorizationPending}}, started: make(chan struct{}), release: make(chan struct{})}
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
		value, _ := accountsService.LoginStatus(context.Background(), provider.XAI, "restart_state")
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
	accountsService := &adapterOAuthAccounts{sessions: map[string]provider.AuthorizationSession{"shutdown_state": {Authorization: provider.Authorization{Ref: provider.AuthorizationRef{Provider: provider.XAI, State: "shutdown_state"}, ExpiresAt: now.Add(time.Minute)}, Status: provider.AuthorizationAuthorized}}, started: make(chan struct{}), release: make(chan struct{})}
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
	value, err := accountsService.LoginStatus(context.Background(), provider.XAI, "shutdown_state")
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
