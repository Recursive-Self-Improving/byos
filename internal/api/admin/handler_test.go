package admin

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"byos/internal/accounts"
	"byos/internal/models"
	"byos/internal/provider"
	"byos/internal/store"
	"byos/internal/usage"
)

type fakeAccounts struct {
	values       []store.Account
	flow         provider.Authorization
	completed    store.Account
	startErr     error
	completeErr  error
	refreshErr   error
	updatedID    string
	updatedLabel string
	updatedOn    bool
	deletedID    string
	refreshedID  string
	loginState   string
	loginErr     error
	session      provider.AuthorizationSession
}

func (f *fakeAccounts) StartLogin(context.Context, provider.Kind) (provider.Authorization, error) {
	return f.flow, f.startErr
}
func (f *fakeAccounts) CompleteLogin(_ context.Context, _ provider.Kind, ref provider.AuthorizationRef, _ provider.AuthorizationCompletion) (store.Account, error) {
	f.loginState = ref.State
	return f.completed, f.completeErr
}
func (f *fakeAccounts) LoginStatus(_ context.Context, _ provider.Kind, sessionID provider.SessionID) (provider.AuthorizationSession, error) {
	if f.loginErr != nil {
		return provider.AuthorizationSession{}, f.loginErr
	}
	value := f.session
	value.Ref.State = string(sessionID)
	value.SessionID = sessionID
	return value, nil
}
func (f *fakeAccounts) CancelLogin(_ context.Context, _ provider.Kind, sessionID provider.SessionID) error {
	f.loginState = string(sessionID)
	return f.loginErr
}
func (f *fakeAccounts) List(context.Context) ([]store.Account, error) { return f.values, nil }
func (f *fakeAccounts) Update(_ context.Context, id, label string, enabled bool) error {
	f.updatedID, f.updatedLabel, f.updatedOn = id, label, enabled
	return nil
}
func (f *fakeAccounts) Delete(_ context.Context, id string) error {
	f.deletedID = id
	if id == "missing" {
		return sql.ErrNoRows
	}
	return nil
}
func (f *fakeAccounts) Refresh(_ context.Context, id string) (store.Account, error) {
	f.refreshedID = id
	return f.completed, f.refreshErr
}

type fakeCompletion struct {
	resumed          []string
	ensured          []string
	devinSessionID   string
	devinCallbackURL string
	devinAccountID   string
	devinCompleteErr error
}

func (f *fakeCompletion) Resume(state string) { f.resumed = append(f.resumed, state) }
func (f *fakeCompletion) EnsureCompletion(state string) {
	f.ensured = append(f.ensured, state)
}
func (f *fakeCompletion) CompleteDevinCallback(_ context.Context, sessionID, callbackURL string) (string, error) {
	f.devinSessionID = sessionID
	f.devinCallbackURL = callbackURL
	return f.devinAccountID, f.devinCompleteErr
}

type fakeUsage struct {
	values  map[string]usage.Snapshot
	errors  map[string]error
	refresh map[string]error
	calls   []usage.Account
	status  map[string]usage.RefreshStatus
}

func (f *fakeUsage) Latest(_ context.Context, id string) (usage.Snapshot, error) {
	if err := f.errors[id]; err != nil {
		return usage.Snapshot{}, err
	}
	value, ok := f.values[id]
	if !ok {
		return usage.Snapshot{}, sql.ErrNoRows
	}
	return value, nil
}
func (f *fakeUsage) RefreshAccount(_ context.Context, account usage.Account) error {
	f.calls = append(f.calls, account)
	return f.refresh[account.ID]
}
func (f *fakeUsage) Status(id string) usage.RefreshStatus { return f.status[id] }

type fakeModels struct {
	values  map[string][]models.Capability
	refresh map[string]error
	calls   []models.Account
	status  map[string]models.RefreshStatus
}

func (f *fakeModels) Capabilities(_ context.Context, id string) ([]models.Capability, error) {
	return f.values[id], nil
}
func (f *fakeModels) RefreshAccount(_ context.Context, account models.Account) error {
	f.calls = append(f.calls, account)
	return f.refresh[account.ID]
}
func (f *fakeModels) Status(id string) models.RefreshStatus { return f.status[id] }

type fakeCooldowns struct{ values map[string]store.Cooldown }

func (f *fakeCooldowns) Get(_ context.Context, accountID, model string, _ time.Time) (store.Cooldown, error) {
	value, ok := f.values[accountID+"/"+model]
	if !ok {
		return store.Cooldown{}, sql.ErrNoRows
	}
	return value, nil
}

type fakeCapabilityRegistry struct {
	xai   bool
	devin bool
}

func (f fakeCapabilityRegistry) Capabilities(kind provider.Kind, policyKey string) (provider.Capabilities, bool) {
	switch kind {
	case provider.XAI:
		if !f.xai {
			return provider.Capabilities{}, false
		}
		return provider.Capabilities{
			CredentialRefresher: fakeCredentialRefresher{},
			Lifecycle:           fakeAccountLifecycle{},
			ModelDiscoverer:     fakeModelDiscoverer{},
			UsageFetcher:        fakeUsageFetcher{},
			Credentials:         fakeCredentialManager{},
		}, true
	case provider.Devin:
		if !f.devin {
			return provider.Capabilities{}, false
		}
		return provider.Capabilities{Lifecycle: fakeAccountLifecycle{}}, true
	default:
		return provider.Capabilities{}, false
	}
}

type fakeCredentialRefresher struct{ err error }

func (f fakeCredentialRefresher) NeedsRefresh(context.Context, string, time.Time) (bool, error) {
	return false, nil
}
func (f fakeCredentialRefresher) Refresh(context.Context, string) error { return f.err }

type fakeAccountLifecycle struct{}

func (fakeAccountLifecycle) Start(context.Context) (provider.Authorization, error) {
	return provider.Authorization{}, nil
}
func (fakeAccountLifecycle) Status(context.Context, provider.AuthorizationRef) (provider.AuthorizationSession, error) {
	return provider.AuthorizationSession{}, nil
}
func (fakeAccountLifecycle) Complete(context.Context, provider.AuthorizationRef, provider.AuthorizationCompletion) (provider.AccountResult, error) {
	return provider.AccountResult{}, nil
}
func (fakeAccountLifecycle) Cancel(context.Context, provider.AuthorizationRef) error { return nil }
func (fakeAccountLifecycle) Resume(context.Context) ([]provider.AuthorizationSession, error) {
	return nil, nil
}

type fakeModelDiscoverer struct{}

func (fakeModelDiscoverer) Discover(context.Context, provider.Credential) ([]provider.DiscoveredModel, error) {
	return nil, nil
}

type fakeUsageFetcher struct{}

func (fakeUsageFetcher) FetchUsage(context.Context, provider.Credential) (provider.UsageSnapshot, error) {
	return provider.UsageSnapshot{}, nil
}

type fakeCredentialManager struct{}

func (fakeCredentialManager) Credential(context.Context, string) (provider.Credential, error) {
	return provider.Credential{Value: "opaque"}, nil
}
func (fakeCredentialManager) AuthenticationFailed(context.Context, string, *provider.UpstreamError) error {
	return nil
}

// xaiCapabilityRegistry returns a registry that registers the full xAI
// capability set and no Devin capabilities, mirroring production wiring.
func xaiCapabilityRegistry() fakeCapabilityRegistry {
	return fakeCapabilityRegistry{xai: true}
}

type fakeKeys struct {
	values  []store.APIKey
	created accounts.CreatedAPIKey
	label   string
	revoked string
	err     error
}

func (f *fakeKeys) List(context.Context) ([]store.APIKey, error) { return f.values, f.err }
func (f *fakeKeys) Create(_ context.Context, label string) (accounts.CreatedAPIKey, error) {
	f.label = label
	return f.created, f.err
}
func (f *fakeKeys) Revoke(_ context.Context, id string) error { f.revoked = id; return f.err }

func request(t *testing.T, handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var input *bytes.Reader
	if body == "" {
		input = bytes.NewReader(nil)
	} else {
		input = bytes.NewReader([]byte(body))
	}
	req := httptest.NewRequest(method, path, input)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func requireStatus(t *testing.T, response *httptest.ResponseRecorder, want int) {
	t.Helper()
	if response.Code != want {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, want, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
	}
}

func decodeMap(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, response.Body.String())
	}
	return value
}

func TestOAuthDeviceLifecycleAndSafeProjection(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	account := store.Account{
		ID: "acct_1", Provider: provider.XAI, Label: "primary", Enabled: true, Status: "ready",
		Credentials: store.AccountCredentials{Email: "owner@example.com", Subject: "private-subject", AccessToken: "private-access", RefreshToken: "private-refresh", IDToken: "private-id", RawIdentity: json.RawMessage(`{"secret":"claim"}`)},
		CreatedAt:   now, UpdatedAt: now,
	}
	accountsService := &fakeAccounts{
		flow:      provider.Authorization{Ref: provider.AuthorizationRef{Provider: provider.XAI, State: "raw-oauth-state"}, SessionID: provider.SessionID("opaque-state"), UserCode: "ABCD-EFGH", VerificationURL: "https://accounts.x.ai/device", VerificationURLComplete: "https://accounts.x.ai/device?user_code=ABCD-EFGH", ExpiresAt: now.Add(10 * time.Minute), PollInterval: 5 * time.Second},
		completed: account,
		session:   provider.AuthorizationSession{Authorization: provider.Authorization{Ref: provider.AuthorizationRef{Provider: provider.XAI}}, Status: provider.AuthorizationCompleted, AccountID: "acct_1"},
	}
	completion := &fakeCompletion{}
	handler := NewHandler(Services{Accounts: accountsService, Completion: completion})

	started := request(t, handler, http.MethodPost, basePath+"/oauth/xai/device", "")
	requireStatus(t, started, http.StatusCreated)
	startBody := decodeMap(t, started)
	for _, key := range []string{"provider", "state", "user_code", "verification_url", "expires_at", "status"} {
		if _, ok := startBody[key]; !ok {
			t.Fatalf("start response missing %q: %v", key, startBody)
		}
	}
	if len(startBody) != 6 {
		t.Fatalf("start response has non-allowlisted fields: %v", startBody)
	}
	if startBody["provider"] != "xai" || startBody["state"] != "opaque-state" {
		t.Fatalf("start response provider/state = %v", startBody)
	}

	if len(completion.resumed) != 1 || completion.resumed[0] != "opaque-state" {
		t.Fatalf("completion resumes = %v", completion.resumed)
	}
	polled := request(t, handler, http.MethodGet, basePath+"/oauth/xai/device/opaque-state", "")
	requireStatus(t, polled, http.StatusOK)
	pollBody := decodeMap(t, polled)
	if len(pollBody) != 4 || pollBody["provider"] != "xai" || pollBody["state"] != "opaque-state" || pollBody["status"] != "completed" || pollBody["account_id"] != "acct_1" {
		t.Fatalf("poll response has non-allowlisted or incorrect fields: %v", pollBody)
	}
	for _, secret := range []string{"owner@example.com", "private-subject", "private-access", "private-refresh", "private-id", "claim"} {
		if strings.Contains(polled.Body.String(), secret) {
			t.Fatalf("poll response leaked %q: %s", secret, polled.Body.String())
		}
	}
	if len(completion.ensured) != 0 {
		t.Fatalf("completed poll ensured completion: %v", completion.ensured)
	}

	accountsService.session.Status = provider.AuthorizationAuthorized
	pending := request(t, handler, http.MethodGet, basePath+"/oauth/xai/device/opaque-state", "")
	requireStatus(t, pending, http.StatusAccepted)
	if len(completion.ensured) != 1 || completion.ensured[0] != "opaque-state" {
		t.Fatalf("completion ensures = %v", completion.ensured)
	}

	cancelled := request(t, handler, http.MethodDelete, basePath+"/oauth/xai/device/opaque-state", "")
	requireStatus(t, cancelled, http.StatusNoContent)
	if accountsService.loginState != "opaque-state" {
		t.Fatalf("cancel state = %q", accountsService.loginState)
	}
}

func TestOAuthErrorsAreSanitized(t *testing.T) {
	handler := NewHandler(Services{Accounts: &fakeAccounts{session: provider.AuthorizationSession{Authorization: provider.Authorization{Ref: provider.AuthorizationRef{Provider: provider.XAI}}, Status: provider.AuthorizationFailed, SanitizedMessage: "private upstream tenant and token"}}})
	response := request(t, handler, http.MethodGet, basePath+"/oauth/xai/device/state", "")
	requireStatus(t, response, http.StatusConflict)
	if strings.Contains(response.Body.String(), "private upstream") || !strings.Contains(response.Body.String(), "device authorization failed") {
		t.Fatalf("oauth error body = %s", response.Body.String())
	}
	errorBody := decodeMap(t, response)
	if len(errorBody) != 4 || errorBody["provider"] != "xai" || errorBody["state"] != "state" || errorBody["status"] != "failed" || errorBody["error"] != "device authorization failed" {
		t.Fatalf("oauth error has non-allowlisted fields: %v", errorBody)
	}
	handler = NewHandler(Services{Accounts: &fakeAccounts{loginErr: errors.New("sqlite path /private/db")}})
	response = request(t, handler, http.MethodDelete, basePath+"/oauth/xai/device/state", "")
	requireStatus(t, response, http.StatusInternalServerError)
	cancelBody := decodeMap(t, response)
	if len(cancelBody) != 4 || cancelBody["provider"] != "xai" || cancelBody["state"] != "state" || cancelBody["status"] != "failed" || strings.Contains(response.Body.String(), "/private/db") {
		t.Fatalf("cancel error leaked or has non-allowlisted fields: %v", cancelBody)
	}
}

func TestAccountMutationDeleteRefreshAndSafeProjection(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	stored := store.Account{ID: "acct_1", Provider: provider.XAI, Label: "old", Enabled: true, Status: "ready", Credentials: store.AccountCredentials{Email: "owner@example.com", Subject: "subject-secret", AccessToken: "token-secret", RawIdentity: json.RawMessage(`{"raw":"secret"}`)}, CreatedAt: now, UpdatedAt: now}
	accountsService := &fakeAccounts{values: []store.Account{stored}, completed: stored}
	cooldownUntil := now.Add(15 * time.Minute)
	modelService := &fakeModels{values: map[string][]models.Capability{"acct_1": {{Model: models.Model{ID: "grok-4"}}}}, status: map[string]models.RefreshStatus{"acct_1": {LastSuccess: now.Add(-time.Minute), Stale: true}}}
	usageService := &fakeUsage{status: map[string]usage.RefreshStatus{"acct_1": {LastAttempt: now, Refreshing: true}}}
	handler := NewHandler(Services{Accounts: accountsService, Models: modelService, ModelsRefresh: modelService, UsageRefresh: usageService, Cooldowns: &fakeCooldowns{values: map[string]store.Cooldown{"acct_1/grok-4": {Until: &cooldownUntil}}}, Capabilities: xaiCapabilityRegistry()})
	listed := request(t, handler, http.MethodGet, basePath+"/accounts", "")
	requireStatus(t, listed, http.StatusOK)

	for _, secret := range []string{"owner@example.com", "subject-secret", "token-secret", `\"raw\"`} {
		if strings.Contains(listed.Body.String(), secret) {
			t.Fatalf("account list leaked %q: %s", secret, listed.Body.String())
		}
	}
	for _, field := range []string{`"cooldown_until":`, `"capability_freshness":`, `"usage_freshness":`, `"stale":true`, `"refreshing":true`} {
		if !strings.Contains(listed.Body.String(), field) {
			t.Fatalf("account list missing status %s: %s", field, listed.Body.String())
		}
	}

	patched := request(t, handler, http.MethodPatch, basePath+"/accounts/acct_1", `{"label":" renamed ","enabled":false}`)
	requireStatus(t, patched, http.StatusOK)
	if accountsService.updatedID != "acct_1" || accountsService.updatedLabel != "renamed" || accountsService.updatedOn {
		t.Fatalf("update = %q %q %v", accountsService.updatedID, accountsService.updatedLabel, accountsService.updatedOn)
	}

	rejected := request(t, handler, http.MethodPatch, basePath+"/accounts/acct_1", `{"label":"x","access_token":"injected"}`)
	requireStatus(t, rejected, http.StatusBadRequest)
	if strings.Contains(rejected.Body.String(), "injected") {
		t.Fatalf("invalid patch echoed input: %s", rejected.Body.String())
	}

	deleted := request(t, handler, http.MethodDelete, basePath+"/accounts/acct_1", "")
	requireStatus(t, deleted, http.StatusNoContent)
	if accountsService.deletedID != "acct_1" {
		t.Fatalf("deleted ID = %q", accountsService.deletedID)
	}

	refreshed := request(t, handler, http.MethodPost, basePath+"/accounts/acct_1/refresh", "")
	requireStatus(t, refreshed, http.StatusOK)
	if accountsService.refreshedID != "acct_1" || strings.Contains(refreshed.Body.String(), "token-secret") {
		t.Fatalf("refresh result = %s, id=%q", refreshed.Body.String(), accountsService.refreshedID)
	}

	accountsService.refreshErr = errors.New("refresh token token-secret rejected by private issuer")
	failed := request(t, handler, http.MethodPost, basePath+"/accounts/acct_1/refresh", "")
	requireStatus(t, failed, http.StatusBadGateway)
	if strings.Contains(failed.Body.String(), "token-secret") || !strings.Contains(failed.Body.String(), "account refresh failed") {
		t.Fatalf("refresh error body = %s", failed.Body.String())
	}
}

func TestUsageEndpointsReturnStaleNormalizedDataWithoutRawBilling(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	accountsService := &fakeAccounts{values: []store.Account{{ID: "acct_1", Provider: provider.XAI, Enabled: true, Credentials: store.AccountCredentials{AccessToken: "usage-refresh-secret"}}}}
	usageService := &fakeUsage{
		values: map[string]usage.Snapshot{"acct_1": {AccountID: "acct_1", Monthly: &usage.Monthly{Remaining: 42}, FetchedAt: now, Error: "upstream raw billing detail"}},
		errors: map[string]error{}, refresh: map[string]error{"acct_1": errors.New("private billing endpoint")},
	}
	handler := NewHandler(Services{Accounts: accountsService, Usage: usageService, UsageRefresh: usageService, Capabilities: xaiCapabilityRegistry()})

	response := request(t, handler, http.MethodGet, basePath+"/accounts/acct_1/usage", "")
	requireStatus(t, response, http.StatusOK)
	body := response.Body.String()
	if !strings.Contains(body, `"provider":"xai"`) || !strings.Contains(body, `"remaining":42`) || !strings.Contains(body, `"quota_available":true`) || !strings.Contains(body, `"upstream_usage_available":true`) || !strings.Contains(body, `"error":"usage data may be stale"`) || strings.Contains(body, "raw-billing-secret") || strings.Contains(body, "upstream raw") {
		t.Fatalf("usage body = %s", body)
	}

	refreshed := request(t, handler, http.MethodPost, basePath+"/accounts/acct_1/usage/refresh", "")
	requireStatus(t, refreshed, http.StatusOK)
	if !strings.Contains(refreshed.Body.String(), `"stale":true`) || strings.Contains(refreshed.Body.String(), "private billing") || strings.Contains(refreshed.Body.String(), "usage-refresh-secret") {
		t.Fatalf("stale refresh body = %s", refreshed.Body.String())
	}
	if len(usageService.calls) != 1 || usageService.calls[0] != (usage.Account{ID: "acct_1", Provider: provider.XAI, Enabled: true}) {
		t.Fatalf("usage worker calls = %v", usageService.calls)
	}

	missing := request(t, handler, http.MethodGet, basePath+"/accounts/missing/usage", "")
	requireStatus(t, missing, http.StatusNotFound)
	if strings.Contains(missing.Body.String(), "usage-refresh-secret") {
		t.Fatalf("missing account leaked token: %s", missing.Body.String())
	}

	all := request(t, handler, http.MethodGet, basePath+"/usage", "")
	requireStatus(t, all, http.StatusOK)
	if strings.Contains(all.Body.String(), "raw-billing-secret") || !strings.Contains(all.Body.String(), `"account_id":"acct_1"`) {
		t.Fatalf("all usage body = %s", all.Body.String())
	}
}

func TestModelsListPreservesStaleStateAndRefreshesEnabledAccounts(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	accountsService := &fakeAccounts{values: []store.Account{{ID: "enabled", Provider: provider.XAI, Enabled: true, Credentials: store.AccountCredentials{AccessToken: "model-refresh-secret"}}, {ID: "disabled", Provider: provider.XAI, Enabled: false}}}
	search := true
	modelService := &fakeModels{values: map[string][]models.Capability{
		"enabled":  {{Model: models.Model{ID: "grok-4", DisplayName: "Grok 4", SupportsBackendSearch: &search, ReasoningEfforts: []string{"high"}}, DiscoveredAt: now, Stale: true}},
		"disabled": {},
	}, refresh: map[string]error{}}
	handler := NewHandler(Services{Accounts: accountsService, Models: modelService, ModelsRefresh: modelService, Capabilities: xaiCapabilityRegistry()})

	listed := request(t, handler, http.MethodGet, basePath+"/models", "")
	requireStatus(t, listed, http.StatusOK)
	if !strings.Contains(listed.Body.String(), `"id":"grok-4"`) || !strings.Contains(listed.Body.String(), `"stale":true`) {
		t.Fatalf("models body = %s", listed.Body.String())
	}

	refreshed := request(t, handler, http.MethodPost, basePath+"/models/refresh", "")
	requireStatus(t, refreshed, http.StatusOK)
	if len(modelService.calls) != 1 || modelService.calls[0] != (models.Account{ID: "enabled", Provider: provider.XAI, Enabled: true}) {
		t.Fatalf("refresh calls = %v", modelService.calls)
	}
	if strings.Contains(refreshed.Body.String(), "model-refresh-secret") {
		t.Fatalf("model refresh leaked token: %s", refreshed.Body.String())
	}
	modelService.refresh["enabled"] = errors.New("private model upstream and token")
	stale := request(t, handler, http.MethodPost, basePath+"/models/refresh", "")
	requireStatus(t, stale, http.StatusOK)
	if !strings.Contains(stale.Body.String(), `"stale":true`) || !strings.Contains(stale.Body.String(), `"refresh_error":`) || strings.Contains(stale.Body.String(), "private model") {
		t.Fatalf("stale model refresh body = %s", stale.Body.String())
	}
}

func TestAPIKeyPlaintextIsReturnedOnceAndRevocationWorks(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	key := store.APIKey{ID: "key_1", Prefix: "byos_visible", Label: "automation", CreatedAt: now}
	keys := &fakeKeys{values: []store.APIKey{key}, created: accounts.CreatedAPIKey{Key: key, Plaintext: "byos_one_time_private"}}
	handler := NewHandler(Services{APIKeys: keys})

	created := request(t, handler, http.MethodPost, basePath+"/api-keys", `{"label":" automation "}`)
	requireStatus(t, created, http.StatusCreated)
	if keys.label != "automation" || !strings.Contains(created.Body.String(), `"plaintext":"byos_one_time_private"`) {
		t.Fatalf("create body = %s, label=%q", created.Body.String(), keys.label)
	}

	listed := request(t, handler, http.MethodGet, basePath+"/api-keys", "")
	requireStatus(t, listed, http.StatusOK)
	if strings.Contains(listed.Body.String(), "byos_one_time_private") || !strings.Contains(listed.Body.String(), `"prefix":"byos_visible"`) {
		t.Fatalf("list body = %s", listed.Body.String())
	}

	revoked := request(t, handler, http.MethodDelete, basePath+"/api-keys/key_1", "")
	requireStatus(t, revoked, http.StatusNoContent)
	if keys.revoked != "key_1" {
		t.Fatalf("revoked ID = %q", keys.revoked)
	}
}

func TestInternalErrorsNeverExposeCause(t *testing.T) {
	keys := &fakeKeys{err: errors.New("UNIQUE constraint at /private/database with secret hash")}
	handler := NewHandler(Services{APIKeys: keys})
	response := request(t, handler, http.MethodGet, basePath+"/api-keys", "")
	requireStatus(t, response, http.StatusInternalServerError)
	body := response.Body.String()
	if strings.Contains(body, "UNIQUE") || strings.Contains(body, "/private") || strings.Contains(body, "secret hash") {
		t.Fatalf("internal error leaked: %s", body)
	}
	if decodeMap(t, response)["error"] == nil {
		t.Fatalf("missing structured error: %s", body)
	}
}

func TestOAuthPollProjectsPersistedStatusesWithoutBlocking(t *testing.T) {
	expires := time.Now().Add(time.Minute)
	for _, test := range []struct {
		status string
		want   int
	}{{"pending", http.StatusAccepted}, {"authorized", http.StatusAccepted}, {"completed", http.StatusOK}, {"cancelled", http.StatusConflict}, {"failed", http.StatusConflict}, {"expired", http.StatusGone}} {
		t.Run(test.status, func(t *testing.T) {
			session := provider.AuthorizationSession{Authorization: provider.Authorization{Ref: provider.AuthorizationRef{Provider: provider.XAI}, UserCode: "CODE", VerificationURL: "https://auth.x.ai/device", ExpiresAt: expires}, Status: provider.AuthorizationStatus(test.status), AccountID: "acct"}
			response := request(t, NewHandler(Services{Accounts: &fakeAccounts{session: session}}), http.MethodGet, basePath+"/oauth/xai/device/state", "")
			requireStatus(t, response, test.want)
			body := decodeMap(t, response)
			if body["status"] == nil {
				t.Fatalf("body=%v", body)
			}
			if strings.Contains(response.Body.String(), "device-secret") {
				t.Fatalf("secret leaked: %s", response.Body.String())
			}
		})
	}
}

func TestDevinAuthorizationUsesSessionIDNotState(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	account := store.Account{ID: "devin_1", Provider: provider.Devin, Label: "dev", Enabled: true, Status: "ready", CreatedAt: now, UpdatedAt: now}
	accountsService := &fakeAccounts{
		flow:      provider.Authorization{Ref: provider.AuthorizationRef{Provider: provider.Devin, State: "raw-callback-state"}, SessionID: provider.SessionID("safe-session-id"), VerificationURL: "https://devin.example.com/auth", ExpiresAt: now.Add(10 * time.Minute)},
		completed: account,
		session:   provider.AuthorizationSession{Authorization: provider.Authorization{Ref: provider.AuthorizationRef{Provider: provider.Devin}, SessionID: provider.SessionID("safe-session-id")}, Status: provider.AuthorizationCompleted, AccountID: "devin_1"},
	}
	handler := NewHandler(Services{Accounts: accountsService})

	started := request(t, handler, http.MethodPost, basePath+"/oauth/devin/start", "")
	requireStatus(t, started, http.StatusCreated)
	startBody := decodeMap(t, started)
	if startBody["session_id"] != "safe-session-id" {
		t.Fatalf("Devin start session_id = %v", startBody)
	}
	if _, hasState := startBody["state"]; hasState {
		t.Fatalf("Devin start must not expose state field: %v", startBody)
	}
	if strings.Contains(started.Body.String(), "raw-callback-state") {
		t.Fatalf("Devin start leaked raw callback state: %s", started.Body.String())
	}

	polled := request(t, handler, http.MethodGet, basePath+"/oauth/devin/status/safe-session-id", "")
	requireStatus(t, polled, http.StatusOK)
	pollBody := decodeMap(t, polled)
	if pollBody["session_id"] != "safe-session-id" || pollBody["provider"] != "devin" {
		t.Fatalf("Devin poll = %v", pollBody)
	}
	if _, hasState := pollBody["state"]; hasState {
		t.Fatalf("Devin poll must not expose state field: %v", pollBody)
	}

	cancelled := request(t, handler, http.MethodPost, basePath+"/oauth/devin/cancel/safe-session-id", "")
	requireStatus(t, cancelled, http.StatusNoContent)
	if accountsService.loginState != "safe-session-id" {
		t.Fatalf("Devin cancel state = %q", accountsService.loginState)
	}
}

func TestDevinManualCallbackCompletionIsAuthenticatedManagementFlow(t *testing.T) {
	completion := &fakeCompletion{devinAccountID: "devin_1"}
	handler := NewHandler(Services{Completion: completion})
	const callbackURL = "http://127.0.0.1:59653/callback?code=manual-code-secret&state=manual-state-secret"
	response := request(t, handler, http.MethodPost, basePath+"/oauth/devin/complete/safe-session-id", `{"callback_url":"`+callbackURL+`"}`)
	requireStatus(t, response, http.StatusOK)
	if completion.devinSessionID != "safe-session-id" || completion.devinCallbackURL != callbackURL {
		t.Fatalf("completion session=%q callback=%q", completion.devinSessionID, completion.devinCallbackURL)
	}
	body := response.Body.String()
	if strings.Contains(body, "manual-code-secret") || strings.Contains(body, "manual-state-secret") || strings.Contains(body, callbackURL) {
		t.Fatalf("manual callback leaked: %s", body)
	}
	view := decodeMap(t, response)
	if view["status"] != "completed" || view["account_id"] != "devin_1" || view["session_id"] != "safe-session-id" {
		t.Fatalf("completion view=%v", view)
	}
}

func TestDevinUsageSuppressesUpstreamQuotaEvenWithLegacyXAISnapshot(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	accountsService := &fakeAccounts{values: []store.Account{{ID: "devin_1", Provider: provider.Devin, Enabled: true}}}
	// Corrupt/legacy xAI-shaped quota persisted for a Devin account.
	usageService := &fakeUsage{
		values: map[string]usage.Snapshot{"devin_1": {AccountID: "devin_1", Monthly: &usage.Monthly{Remaining: 99}, Weekly: &usage.Weekly{UsedPercent: 50}, FetchedAt: now}},
	}
	handler := NewHandler(Services{Accounts: accountsService, Usage: usageService})

	response := request(t, handler, http.MethodGet, basePath+"/accounts/devin_1/usage", "")
	requireStatus(t, response, http.StatusOK)
	body := response.Body.String()
	if !strings.Contains(body, `"provider":"devin"`) {
		t.Fatalf("Devin usage missing provider: %s", body)
	}
	if strings.Contains(body, `"remaining":99`) || strings.Contains(body, `"used_percent":50`) {
		t.Fatalf("Devin usage must suppress upstream quota values: %s", body)
	}
	if !strings.Contains(body, `"monthly":null`) || !strings.Contains(body, `"weekly":null`) {
		t.Fatalf("Devin usage must explicitly project null monthly/weekly: %s", body)
	}
	if !strings.Contains(body, `"quota_available":false`) || !strings.Contains(body, `"upstream_usage_available":false`) {
		t.Fatalf("Devin usage must report quota unavailable: %s", body)
	}
	// Local counters remain available.
	if !strings.Contains(body, `"local"`) {
		t.Fatalf("Devin usage missing local counters: %s", body)
	}
}

func TestUsageProjectionIncludesCacheReadTokens(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	accountsService := &fakeAccounts{values: []store.Account{{ID: "acct_cache", Provider: provider.XAI, Enabled: true}}}
	usageService := &fakeUsage{
		values: map[string]usage.Snapshot{"acct_cache": {AccountID: "acct_cache", Monthly: &usage.Monthly{Remaining: 42}, Local: usage.Counters{Requests: 1, InputTokens: 17, OutputTokens: 23, CacheReadTokens: 9}, FetchedAt: now}},
	}
	handler := NewHandler(Services{Accounts: accountsService, Usage: usageService})

	response := request(t, handler, http.MethodGet, basePath+"/accounts/acct_cache/usage", "")
	requireStatus(t, response, http.StatusOK)
	body := response.Body.String()
	// Cache-read is projected as a local counter alongside the upstream quota,
	// not conflated with billing quota.
	if !strings.Contains(body, `"cache_read_tokens":9`) {
		t.Fatalf("usage missing cache_read_tokens local counter: %s", body)
	}
	if !strings.Contains(body, `"remaining":42`) {
		t.Fatalf("usage missing upstream monthly quota: %s", body)
	}
}

func TestModelsProjectProviderFromOwningAccount(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	accountsService := &fakeAccounts{values: []store.Account{
		{ID: "xai_acct", Provider: provider.XAI, Enabled: true},
		{ID: "devin_acct", Provider: provider.Devin, Enabled: true},
	}}
	modelService := &fakeModels{values: map[string][]models.Capability{
		"xai_acct":   {{Model: models.Model{ID: "grok-4"}, DiscoveredAt: now}},
		"devin_acct": {{Model: models.Model{ID: "kimi-k2"}, DiscoveredAt: now}},
	}}
	handler := NewHandler(Services{Accounts: accountsService, Models: modelService})

	listed := request(t, handler, http.MethodGet, basePath+"/models", "")
	requireStatus(t, listed, http.StatusOK)
	body := listed.Body.String()
	if !strings.Contains(body, `"provider":"xai"`) || !strings.Contains(body, `"provider":"devin"`) {
		t.Fatalf("models missing provider from owning account: %s", body)
	}
}

type fakeCallbackCompleter struct {
	called     bool
	ref        provider.AuthorizationRef
	completion provider.AuthorizationCompletion
	err        error
}

func (f *fakeCallbackCompleter) CompleteLogin(_ context.Context, _ provider.Kind, ref provider.AuthorizationRef, completion provider.AuthorizationCompletion) (store.Account, error) {
	f.called = true
	f.ref = ref
	f.completion = completion
	return store.Account{ID: "devin_1", Provider: provider.Devin}, f.err
}

func TestCallbackHandlerCompletesWithRawState(t *testing.T) {
	completer := &fakeCallbackCompleter{}
	handler := CallbackHandler(completer)

	response := request(t, handler, http.MethodGet, "/admin/api/v1/oauth/devin/callback?state=raw-oauth-state&code=auth-code", "")
	requireStatus(t, response, http.StatusNoContent)
	if !completer.called {
		t.Fatalf("completer was not called")
	}
	if completer.ref.Provider != provider.Devin || completer.ref.State != "raw-oauth-state" {
		t.Fatalf("completer ref = %+v", completer.ref)
	}
	if completer.completion.Code != "auth-code" {
		t.Fatalf("completer code = %q", completer.completion.Code)
	}
	// Response must never echo state, code, or tokens.
	if strings.Contains(response.Body.String(), "raw-oauth-state") || strings.Contains(response.Body.String(), "auth-code") {
		t.Fatalf("callback response echoed inputs: %s", response.Body.String())
	}
}

func TestCallbackHandlerRejectsMethodAndBadParams(t *testing.T) {
	completer := &fakeCallbackCompleter{}
	handler := CallbackHandler(completer)

	// POST to exact callback path must be rejected (handled by outer dispatch,
	// but the handler itself also guards method).
	post := request(t, handler, http.MethodPost, "/admin/api/v1/oauth/devin/callback?state=s&code=c", "")
	requireStatus(t, post, http.StatusMethodNotAllowed)
	if completer.called {
		t.Fatalf("completer called on POST")
	}

	// Missing state.
	missingState := request(t, handler, http.MethodGet, "/admin/api/v1/oauth/devin/callback?code=c", "")
	requireStatus(t, missingState, http.StatusBadRequest)

	// Missing code.
	missingCode := request(t, handler, http.MethodGet, "/admin/api/v1/oauth/devin/callback?state=s", "")
	requireStatus(t, missingCode, http.StatusBadRequest)

	// Duplicate state.
	dupState := request(t, handler, http.MethodGet, "/admin/api/v1/oauth/devin/callback?state=s&state=s2&code=c", "")
	requireStatus(t, dupState, http.StatusBadRequest)

	// Empty state value.
	emptyState := request(t, handler, http.MethodGet, "/admin/api/v1/oauth/devin/callback?state=&code=c", "")
	requireStatus(t, emptyState, http.StatusBadRequest)
}

func TestCallbackHandlerRejectsProviderErrorByKeyPresence(t *testing.T) {
	completer := &fakeCallbackCompleter{}
	handler := CallbackHandler(completer)

	// error key present (even with empty value) must be rejected.
	errResponse := request(t, handler, http.MethodGet, "/admin/api/v1/oauth/devin/callback?error=&state=s&code=c", "")
	requireStatus(t, errResponse, http.StatusBadRequest)
	if completer.called {
		t.Fatalf("completer called on provider error")
	}
	if !strings.Contains(errResponse.Body.String(), "callback_error") {
		t.Fatalf("error body = %s", errResponse.Body.String())
	}

	// error_description key present must be rejected.
	errDescResponse := request(t, handler, http.MethodGet, "/admin/api/v1/oauth/devin/callback?error_description=denied&state=s&code=c", "")
	requireStatus(t, errDescResponse, http.StatusBadRequest)
}

func TestCallbackHandlerFailureIsSanitized(t *testing.T) {
	completer := &fakeCallbackCompleter{err: errors.New("upstream token exchange failed with secret-token")}
	handler := CallbackHandler(completer)

	response := request(t, handler, http.MethodGet, "/admin/api/v1/oauth/devin/callback?state=raw-state&code=auth-code", "")
	requireStatus(t, response, http.StatusBadGateway)
	if strings.Contains(response.Body.String(), "secret-token") || strings.Contains(response.Body.String(), "raw-state") || strings.Contains(response.Body.String(), "auth-code") {
		t.Fatalf("callback failure leaked: %s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "callback_failed") {
		t.Fatalf("callback failure missing code: %s", response.Body.String())
	}
}

func TestAccountViewProjectsProviderCapabilityBooleans(t *testing.T) {
	accountsService := &fakeAccounts{values: []store.Account{
		{ID: "xai_acct", Provider: provider.XAI, Enabled: true, Status: "ready"},
		{ID: "devin_acct", Provider: provider.Devin, Enabled: true, Status: "ready"},
	}}
	handler := NewHandler(Services{Accounts: accountsService, Capabilities: fakeCapabilityRegistry{xai: true, devin: true}})

	listed := request(t, handler, http.MethodGet, basePath+"/accounts", "")
	requireStatus(t, listed, http.StatusOK)
	body := listed.Body.String()
	// xAI registers the full capability set.
	if !strings.Contains(body, `"can_refresh_credentials":true`) || !strings.Contains(body, `"can_relogin":true`) || !strings.Contains(body, `"can_refresh_usage":true`) || !strings.Contains(body, `"can_refresh_models":true`) {
		t.Fatalf("xAI capability booleans missing: %s", body)
	}
	// Devin registers only Lifecycle; refresh/usage/model capabilities are false.
	if !strings.Contains(body, `"can_relogin":true`) {
		t.Fatalf("Devin can_relogin missing: %s", body)
	}
	devinSegment := substringAfter(t, body, `"id":"devin_acct"`)
	if strings.Contains(devinSegment, `"can_refresh_credentials":true`) || strings.Contains(devinSegment, `"can_refresh_usage":true`) || strings.Contains(devinSegment, `"can_refresh_models":true`) {
		t.Fatalf("Devin must not project unsupported refresh capabilities: %s", devinSegment)
	}
	if !strings.Contains(devinSegment, `"can_refresh_credentials":false`) || !strings.Contains(devinSegment, `"can_refresh_usage":false`) || !strings.Contains(devinSegment, `"can_refresh_models":false`) {
		t.Fatalf("Devin must explicitly project false refresh capabilities: %s", devinSegment)
	}
}

func TestDevinCredentialRefreshReturnsActionUnavailable(t *testing.T) {
	accountsService := &fakeAccounts{values: []store.Account{{ID: "devin_1", Provider: provider.Devin, Enabled: true, Status: "ready"}}, completed: store.Account{ID: "devin_1", Provider: provider.Devin, Status: "ready"}}
	handler := NewHandler(Services{Accounts: accountsService, Capabilities: fakeCapabilityRegistry{xai: true, devin: true}})

	refreshed := request(t, handler, http.MethodPost, basePath+"/accounts/devin_1/refresh", "")
	requireStatus(t, refreshed, http.StatusConflict)
	if !strings.Contains(refreshed.Body.String(), `"code":"action_unavailable"`) {
		t.Fatalf("Devin credential refresh must return action_unavailable: %s", refreshed.Body.String())
	}
	if accountsService.refreshedID != "" {
		t.Fatalf("Devin credential refresh must not invoke Accounts.Refresh: id=%q", accountsService.refreshedID)
	}
}

func TestReloginRequiredCredentialRefreshReturnsReloginRequired(t *testing.T) {
	accountsService := &fakeAccounts{values: []store.Account{{ID: "xai_1", Provider: provider.XAI, Enabled: true, Status: "relogin_required"}}, completed: store.Account{ID: "xai_1", Provider: provider.XAI, Status: "relogin_required"}}
	handler := NewHandler(Services{Accounts: accountsService, Capabilities: xaiCapabilityRegistry()})

	refreshed := request(t, handler, http.MethodPost, basePath+"/accounts/xai_1/refresh", "")
	requireStatus(t, refreshed, http.StatusConflict)
	if !strings.Contains(refreshed.Body.String(), `"code":"relogin_required"`) {
		t.Fatalf("relogin_required account must return relogin_required code: %s", refreshed.Body.String())
	}
	if accountsService.refreshedID != "" {
		t.Fatalf("relogin_required account must not invoke Accounts.Refresh: id=%q", accountsService.refreshedID)
	}
}

func TestDevinUsageRefreshReturnsActionUnavailable(t *testing.T) {
	accountsService := &fakeAccounts{values: []store.Account{{ID: "devin_1", Provider: provider.Devin, Enabled: true, Status: "ready"}}}
	usageService := &fakeUsage{values: map[string]usage.Snapshot{"devin_1": {AccountID: "devin_1"}}}
	handler := NewHandler(Services{Accounts: accountsService, Usage: usageService, UsageRefresh: usageService, Capabilities: fakeCapabilityRegistry{xai: true, devin: true}})

	refreshed := request(t, handler, http.MethodPost, basePath+"/accounts/devin_1/usage/refresh", "")
	requireStatus(t, refreshed, http.StatusConflict)
	if !strings.Contains(refreshed.Body.String(), `"code":"action_unavailable"`) {
		t.Fatalf("Devin usage refresh must return action_unavailable: %s", refreshed.Body.String())
	}
	if len(usageService.calls) != 0 {
		t.Fatalf("Devin usage refresh must not invoke UsageRefresh.RefreshAccount: calls=%v", usageService.calls)
	}
}

func TestGlobalModelRefreshSkipsProvidersWithoutDiscoverer(t *testing.T) {
	accountsService := &fakeAccounts{values: []store.Account{
		{ID: "xai_1", Provider: provider.XAI, Enabled: true, Status: "ready"},
		{ID: "devin_1", Provider: provider.Devin, Enabled: true, Status: "ready"},
	}}
	modelService := &fakeModels{values: map[string][]models.Capability{"xai_1": {{Model: models.Model{ID: "grok-4"}}}}, refresh: map[string]error{}}
	handler := NewHandler(Services{Accounts: accountsService, Models: modelService, ModelsRefresh: modelService, Capabilities: fakeCapabilityRegistry{xai: true, devin: true}})

	refreshed := request(t, handler, http.MethodPost, basePath+"/models/refresh", "")
	requireStatus(t, refreshed, http.StatusOK)
	// Only the xAI account (with a ModelDiscoverer) is refreshed.
	if len(modelService.calls) != 1 || modelService.calls[0] != (models.Account{ID: "xai_1", Provider: provider.XAI, Enabled: true}) {
		t.Fatalf("global model refresh must skip non-discoverer providers: calls=%v", modelService.calls)
	}
	if strings.Contains(refreshed.Body.String(), `"refresh_error"`) {
		t.Fatalf("skipping non-discoverer providers must not surface a refresh_error: %s", refreshed.Body.String())
	}
}

func TestCapabilityBooleansAreFalseWithoutRegistry(t *testing.T) {
	accountsService := &fakeAccounts{values: []store.Account{{ID: "xai_1", Provider: provider.XAI, Enabled: true, Status: "ready"}}}
	handler := NewHandler(Services{Accounts: accountsService})

	listed := request(t, handler, http.MethodGet, basePath+"/accounts", "")
	requireStatus(t, listed, http.StatusOK)
	body := listed.Body.String()
	if !strings.Contains(body, `"can_refresh_credentials":false`) || !strings.Contains(body, `"can_relogin":false`) || !strings.Contains(body, `"can_refresh_usage":false`) || !strings.Contains(body, `"can_refresh_models":false`) {
		t.Fatalf("nil registry must project all capability booleans false: %s", body)
	}
}

func substringAfter(t *testing.T, body, marker string) string {
	t.Helper()
	idx := strings.Index(body, marker)
	if idx < 0 {
		t.Fatalf("marker %q not found in body: %s", marker, body)
	}
	return body[idx:]
}

// TestOAuthCancelMatrixExactUnknownVsConflict verifies the exact HTTP
// semantics for cancel across both providers: unknown/wrong-provider
// SessionID -> 404 Not Found; known-but-terminal (consumed, completed,
// failed, already cancelled) -> 409 Conflict; genuine internal error -> 500.
// No unsanitized error text is ever echoed, and the response body carries
// only allowlisted authorizationView fields.
func TestOAuthCancelMatrixExactUnknownVsConflict(t *testing.T) {
	for _, tc := range []struct {
		name     string
		provider provider.Kind
		path     string
		method   string
		err      error
		want     int
		wantErr  string
	}{
		// xAI device cancel matrix.
		{"xai unknown", provider.XAI, basePath + "/oauth/xai/device/unknown", http.MethodDelete, sql.ErrNoRows, http.StatusNotFound, "device authorization not found"},
		{"xai conflict completed", provider.XAI, basePath + "/oauth/xai/device/sess", http.MethodDelete, provider.ErrOAuthConflict, http.StatusConflict, "device authorization is no longer cancellable"},
		{"xai internal", provider.XAI, basePath + "/oauth/xai/device/sess", http.MethodDelete, errors.New("sqlite path /private/db"), http.StatusInternalServerError, "device authorization cancellation failed"},
		// Devin callback cancel matrix.
		{"devin unknown", provider.Devin, basePath + "/oauth/devin/cancel/unknown", http.MethodPost, sql.ErrNoRows, http.StatusNotFound, "Devin authorization not found"},
		{"devin conflict completed", provider.Devin, basePath + "/oauth/devin/cancel/sess", http.MethodPost, provider.ErrOAuthConflict, http.StatusConflict, "Devin authorization is no longer cancellable"},
		{"devin internal", provider.Devin, basePath + "/oauth/devin/cancel/sess", http.MethodPost, errors.New("sqlite path /private/db"), http.StatusInternalServerError, "Devin authorization cancellation failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := NewHandler(Services{Accounts: &fakeAccounts{loginErr: tc.err}})
			response := request(t, handler, tc.method, tc.path, "")
			requireStatus(t, response, tc.want)
			body := decodeMap(t, response)
			if body["error"] != tc.wantErr {
				t.Fatalf("error = %v, want %q; body=%v", body["error"], tc.wantErr, body)
			}
			if strings.Contains(response.Body.String(), "/private/db") {
				t.Fatalf("internal error leaked: %s", response.Body.String())
			}
			// Allowlisted fields only: provider, state-or-session_id, status, error.
			for key := range body {
				if key != "provider" && key != "state" && key != "session_id" && key != "status" && key != "error" {
					t.Fatalf("unexpected field %q in cancel error body: %v", key, body)
				}
			}
		})
	}
}

// TestOAuthCancelMatrixAllTerminalStatesConflict verifies that every
// known-but-terminal authorization state (consumed, completed, failed,
// expired, already cancelled) surfaces 409 Conflict with a sanitized
// message for both providers, while unknown/wrong-provider returns 404.
// The admin layer sees only the stable provider.ErrOAuthConflict sentinel
// (the lifecycle collapses every terminal sub-state into it), so this
// matrix documents that no terminal sub-state leaks through as 500 or 404
// and that the response body carries only allowlisted fields with no
// unsanitized storage detail.
func TestOAuthCancelMatrixAllTerminalStatesConflict(t *testing.T) {
	terminalStates := []string{"consumed", "completed", "failed", "expired", "cancelled"}
	for _, state := range terminalStates {
		t.Run("xai-"+state, func(t *testing.T) {
			handler := NewHandler(Services{Accounts: &fakeAccounts{loginErr: provider.ErrOAuthConflict}})
			response := request(t, handler, http.MethodDelete, basePath+"/oauth/xai/device/sess", "")
			requireStatus(t, response, http.StatusConflict)
			body := decodeMap(t, response)
			if body["error"] != "device authorization is no longer cancellable" {
				t.Fatalf("error = %v, want conflict message; body=%v", body["error"], body)
			}
			if body["provider"] != "xai" || body["state"] != "sess" || body["status"] != "failed" {
				t.Fatalf("body = %v, want provider=xai state=sess status=failed", body)
			}
			for key := range body {
				if key != "provider" && key != "state" && key != "status" && key != "error" {
					t.Fatalf("unexpected field %q in xai cancel conflict body: %v", key, body)
				}
			}
		})
		t.Run("devin-"+state, func(t *testing.T) {
			handler := NewHandler(Services{Accounts: &fakeAccounts{loginErr: provider.ErrOAuthConflict}})
			response := request(t, handler, http.MethodPost, basePath+"/oauth/devin/cancel/sess", "")
			requireStatus(t, response, http.StatusConflict)
			body := decodeMap(t, response)
			if body["error"] != "Devin authorization is no longer cancellable" {
				t.Fatalf("error = %v, want conflict message; body=%v", body["error"], body)
			}
			if body["provider"] != "devin" || body["session_id"] != "sess" || body["status"] != "failed" {
				t.Fatalf("body = %v, want provider=devin session_id=sess status=failed", body)
			}
			for key := range body {
				if key != "provider" && key != "session_id" && key != "status" && key != "error" {
					t.Fatalf("unexpected field %q in devin cancel conflict body: %v", key, body)
				}
			}
		})
	}
	// Unknown/wrong-provider: 404 for both providers, never 409.
	t.Run("xai-unknown-404", func(t *testing.T) {
		handler := NewHandler(Services{Accounts: &fakeAccounts{loginErr: sql.ErrNoRows}})
		response := request(t, handler, http.MethodDelete, basePath+"/oauth/xai/device/unknown", "")
		requireStatus(t, response, http.StatusNotFound)
		if strings.Contains(response.Body.String(), "is no longer cancellable") {
			t.Fatalf("unknown leaked conflict wording: %s", response.Body.String())
		}
	})
	t.Run("devin-unknown-404", func(t *testing.T) {
		handler := NewHandler(Services{Accounts: &fakeAccounts{loginErr: sql.ErrNoRows}})
		response := request(t, handler, http.MethodPost, basePath+"/oauth/devin/cancel/unknown", "")
		requireStatus(t, response, http.StatusNotFound)
		if strings.Contains(response.Body.String(), "is no longer cancellable") {
			t.Fatalf("unknown leaked conflict wording: %s", response.Body.String())
		}
	})
}
