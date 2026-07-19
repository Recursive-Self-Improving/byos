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

func (f *fakeAccounts) StartLogin(context.Context) (provider.Authorization, error) {
	return f.flow, f.startErr
}
func (f *fakeAccounts) CompleteLogin(context.Context, string) (store.Account, error) {
	return f.completed, f.completeErr
}
func (f *fakeAccounts) LoginStatus(_ context.Context, state string) (provider.AuthorizationSession, error) {
	if f.loginErr != nil {
		return provider.AuthorizationSession{}, f.loginErr
	}
	value := f.session
	value.Ref.State = state
	return value, nil
}
func (f *fakeAccounts) CancelLogin(_ context.Context, state string) error {
	f.loginState = state
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
	resumed []string
	ensured []string
}

func (f *fakeCompletion) Resume(state string) { f.resumed = append(f.resumed, state) }
func (f *fakeCompletion) EnsureCompletion(state string) {
	f.ensured = append(f.ensured, state)
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
		flow:      provider.Authorization{Ref: provider.AuthorizationRef{Provider: provider.XAI, State: "opaque-state"}, UserCode: "ABCD-EFGH", VerificationURL: "https://accounts.x.ai/device", VerificationURLComplete: "https://accounts.x.ai/device?user_code=ABCD-EFGH", ExpiresAt: now.Add(10 * time.Minute), PollInterval: 5 * time.Second},
		completed: account,
		session:   provider.AuthorizationSession{Authorization: provider.Authorization{Ref: provider.AuthorizationRef{Provider: provider.XAI}}, Status: provider.AuthorizationCompleted, AccountID: "acct_1"},
	}
	completion := &fakeCompletion{}
	handler := NewHandler(Services{Accounts: accountsService, Completion: completion})

	started := request(t, handler, http.MethodPost, basePath+"/oauth/xai/device", "")
	requireStatus(t, started, http.StatusCreated)
	startBody := decodeMap(t, started)
	for _, key := range []string{"state", "user_code", "verification_url", "expires_at", "status"} {
		if _, ok := startBody[key]; !ok {
			t.Fatalf("start response missing %q: %v", key, startBody)
		}
	}
	if len(startBody) != 5 {
		t.Fatalf("start response has non-allowlisted fields: %v", startBody)
	}

	if len(completion.resumed) != 1 || completion.resumed[0] != "opaque-state" {
		t.Fatalf("completion resumes = %v", completion.resumed)
	}
	polled := request(t, handler, http.MethodGet, basePath+"/oauth/xai/device/opaque-state", "")
	requireStatus(t, polled, http.StatusOK)
	pollBody := decodeMap(t, polled)
	if len(pollBody) != 3 || pollBody["state"] != "opaque-state" || pollBody["status"] != "completed" || pollBody["account_id"] != "acct_1" {
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
	if len(errorBody) != 3 || errorBody["state"] != "state" || errorBody["status"] != "failed" || errorBody["error"] != "device authorization failed" {
		t.Fatalf("oauth error has non-allowlisted fields: %v", errorBody)
	}
	handler = NewHandler(Services{Accounts: &fakeAccounts{loginErr: errors.New("sqlite path /private/db")}})
	response = request(t, handler, http.MethodDelete, basePath+"/oauth/xai/device/state", "")
	requireStatus(t, response, http.StatusInternalServerError)
	cancelBody := decodeMap(t, response)
	if len(cancelBody) != 3 || cancelBody["state"] != "state" || cancelBody["status"] != "failed" || strings.Contains(response.Body.String(), "/private/db") {
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
	handler := NewHandler(Services{Accounts: accountsService, Models: modelService, ModelsRefresh: modelService, UsageRefresh: usageService, Cooldowns: &fakeCooldowns{values: map[string]store.Cooldown{"acct_1/grok-4": {Until: &cooldownUntil}}}})
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
	handler := NewHandler(Services{Accounts: accountsService, Usage: usageService, UsageRefresh: usageService})

	response := request(t, handler, http.MethodGet, basePath+"/accounts/acct_1/usage", "")
	requireStatus(t, response, http.StatusOK)
	body := response.Body.String()
	if !strings.Contains(body, `"remaining":42`) || !strings.Contains(body, `"error":"usage data may be stale"`) || strings.Contains(body, "raw-billing-secret") || strings.Contains(body, "upstream raw") {
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
	handler := NewHandler(Services{Accounts: accountsService, Models: modelService, ModelsRefresh: modelService})

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
