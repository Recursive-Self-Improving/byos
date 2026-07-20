package web

import (
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"byos/internal/auththrottle"
	appcrypto "byos/internal/crypto"
	"byos/internal/requestsource"
	"byos/internal/store"
)

type testClock struct{ value time.Time }

func (c *testClock) Now() time.Time { return c.value }

type fakeReadinessService struct {
	ready bool
	err   error
}

func (s fakeReadinessService) Ready(context.Context) (bool, error) { return s.ready, s.err }

type fakeAccountService struct {
	summaries    []AccountSummary
	detail       AccountDetail
	listErr      error
	getErr       error
	updateErr    error
	deleteErr    error
	refreshErr   error
	updates      []AccountUpdate
	updateIDs    []string
	deletedIDs   []string
	refreshedIDs []string
}

func (s *fakeAccountService) List(context.Context) ([]AccountSummary, error) {
	return append([]AccountSummary(nil), s.summaries...), s.listErr
}
func (s *fakeAccountService) Get(_ context.Context, id string) (AccountDetail, error) {
	if s.getErr != nil {
		return AccountDetail{}, s.getErr
	}
	if id != s.detail.ID {
		return AccountDetail{}, ErrNotFound
	}
	return s.detail, nil
}
func (s *fakeAccountService) Update(_ context.Context, id string, update AccountUpdate) error {
	if s.updateErr != nil {
		return s.updateErr
	}
	s.updateIDs = append(s.updateIDs, id)
	s.updates = append(s.updates, update)
	return nil
}
func (s *fakeAccountService) Delete(_ context.Context, id string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.deletedIDs = append(s.deletedIDs, id)
	return nil
}
func (s *fakeAccountService) Refresh(_ context.Context, id string) error {
	if s.refreshErr != nil {
		return s.refreshErr
	}
	s.refreshedIDs = append(s.refreshedIDs, id)
	return nil
}

type oauthServiceCall struct {
	Provider  Provider
	SessionID string
}

type fakeOAuthService struct {
	startFlow      OAuthFlow
	flows          map[string]OAuthFlow
	startErr       error
	getErr         error
	cancelErr      error
	startCalls     int
	startProviders []Provider
	getCalls       []oauthServiceCall
	cancelled      []oauthServiceCall
}

func (s *fakeOAuthService) Start(_ context.Context, selected Provider) (OAuthFlow, error) {
	s.startCalls++
	s.startProviders = append(s.startProviders, selected)
	if s.startErr != nil {
		return OAuthFlow{}, s.startErr
	}
	flow := s.startFlow
	flow.Provider = selected
	flow.State = oauthManagementRef(selected, flow.SessionID)
	if s.flows == nil {
		s.flows = make(map[string]OAuthFlow)
	}
	s.flows[flow.State] = flow
	return flow, nil
}
func (s *fakeOAuthService) Get(_ context.Context, selected Provider, sessionID string) (OAuthFlow, error) {
	s.getCalls = append(s.getCalls, oauthServiceCall{Provider: selected, SessionID: sessionID})
	if s.getErr != nil {
		return OAuthFlow{}, s.getErr
	}
	flow, ok := s.flows[oauthManagementRef(selected, sessionID)]
	if !ok {
		return OAuthFlow{}, ErrNotFound
	}
	return flow, nil
}
func (s *fakeOAuthService) Cancel(_ context.Context, selected Provider, sessionID string) error {
	if s.cancelErr != nil {
		return s.cancelErr
	}
	call := oauthServiceCall{Provider: selected, SessionID: sessionID}
	s.cancelled = append(s.cancelled, call)
	key := oauthManagementRef(selected, sessionID)
	flow, ok := s.flows[key]
	if !ok {
		return ErrNotFound
	}
	flow.Status = "cancelled"
	s.flows[key] = flow
	return nil
}

type fakeUsageService struct {
	values       []AccountUsage
	listErr      error
	refreshErr   error
	refreshedIDs []string
}

func (s *fakeUsageService) List(context.Context) ([]AccountUsage, error) {
	return append([]AccountUsage(nil), s.values...), s.listErr
}
func (s *fakeUsageService) Refresh(_ context.Context, id string) error {
	if s.refreshErr != nil {
		return s.refreshErr
	}
	s.refreshedIDs = append(s.refreshedIDs, id)
	return nil
}

type fakeModelService struct {
	values       []ModelSupport
	listErr      error
	refreshErr   error
	refreshedIDs []string
}

func (s *fakeModelService) List(context.Context) ([]ModelSupport, error) {
	return append([]ModelSupport(nil), s.values...), s.listErr
}
func (s *fakeModelService) Refresh(_ context.Context, id string) error {
	if s.refreshErr != nil {
		return s.refreshErr
	}
	s.refreshedIDs = append(s.refreshedIDs, id)
	return nil
}

type fakeAPIKeyService struct {
	keys         []APIKey
	created      CreatedAPIKey
	listErr      error
	createErr    error
	revokeErr    error
	createLabels []string
	revokedIDs   []string
}

func (s *fakeAPIKeyService) List(context.Context) ([]APIKey, error) {
	return append([]APIKey(nil), s.keys...), s.listErr
}
func (s *fakeAPIKeyService) Create(_ context.Context, label string) (CreatedAPIKey, error) {
	s.createLabels = append(s.createLabels, label)
	if s.createErr != nil {
		return CreatedAPIKey{}, s.createErr
	}
	if s.created.Key.ID != "" {
		s.keys = append(s.keys, s.created.Key)
	}
	return s.created, nil
}
func (s *fakeAPIKeyService) Revoke(_ context.Context, id string) error {
	if s.revokeErr != nil {
		return s.revokeErr
	}
	s.revokedIDs = append(s.revokedIDs, id)
	return nil
}

type webFixture struct {
	clock      *testClock
	database   *store.SQLite
	sessions   *store.AdminSessionRepository
	attempts   *store.AdminAuthThrottleRepository
	handler    *Handler
	accounts   *fakeAccountService
	oauth      *fakeOAuthService
	usage      *fakeUsageService
	models     *fakeModelService
	apiKeys    *fakeAPIKeyService
	derivedKey appcrypto.Keys
}

func newWebFixture(t *testing.T, configure ...func(*Options)) *webFixture {
	t.Helper()
	clock := &testClock{value: time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)}
	database, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	master := sha256.Sum256([]byte("web test master key"))
	keys, err := appcrypto.DeriveKeys(master[:])
	if err != nil {
		t.Fatal(err)
	}
	sessions := store.NewAdminSessionRepository(database.DB, keys)
	attempts := store.NewAdminAuthThrottleRepository(database.DB)
	guard, err := auththrottle.NewGuard(attempts, keys.AdminAuthSourceFingerprint, auththrottle.DefaultPolicy(), slog.New(slog.NewTextHandler(io.Discard, nil)), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	search := true
	limit := 100.0
	monthly := 25.0
	weekly := 40.0
	expires := clock.value.Add(2 * time.Hour)
	fetched := clock.value.Add(-5 * time.Minute)
	accounts := &fakeAccountService{
		summaries: []AccountSummary{{Provider: ProviderXAI, ID: "acct_test", Label: "Primary account", Enabled: true, Status: "ready", StatusLabel: "Ready", CanRefresh: true, CanRefreshModels: true, CanRefreshUsage: true, ExpiresAt: &expires, ModelCount: 1, UsageFetchedAt: &fetched}},
		detail: AccountDetail{
			AccountSummary: AccountSummary{Provider: ProviderXAI, ID: "acct_test", Label: "Primary account", Enabled: true, Status: "ready", StatusLabel: "Ready", CanRefresh: true, CanRefreshModels: true, CanRefreshUsage: true, ExpiresAt: &expires, ModelCount: 1, UsageFetchedAt: &fetched},
			LastRefreshAt:  &fetched,
			Models:         []AccountModel{{Provider: ProviderXAI, Name: "grok-4.5", UpstreamName: "grok-4.5", OwnedBy: "xai", DisplayName: "Grok 4.5", Supported: true, CapabilityKnown: true, DiscoveryAvailable: true, SupportsBackendSearch: &search, ContextWindow: 131072, MaxOutputTokens: 8192, DiscoveredAt: fetched}},
		},
	}
	oauthFlow := OAuthFlow{Provider: ProviderXAI, SessionID: "state_test", State: "xai/state_test", Status: "pending", UserCode: "ABCD-EFGH", AuthorizationURL: "https://accounts.x.ai/device", ExpiresAt: clock.value.Add(10 * time.Minute), PollAfter: 5 * time.Second}
	oauth := &fakeOAuthService{startFlow: oauthFlow, flows: map[string]OAuthFlow{"xai/state_test": oauthFlow}}
	usage := &fakeUsageService{values: []AccountUsage{{Provider: ProviderXAI, AccountID: "acct_test", AccountLabel: "Primary account", QuotaAvailable: true, CanRefresh: true, Monthly: UsagePeriod{Used: 25, Limit: &limit, Percent: &monthly, Unit: "credits"}, Weekly: UsagePeriod{Used: 40, Limit: &limit, Percent: &weekly, Unit: "credits"}, Local: LocalUsage{Requests: 10, InputTokens: 200, OutputTokens: 80}, FetchedAt: &fetched}}}
	models := &fakeModelService{values: []ModelSupport{{Provider: ProviderXAI, OwnedBy: "xai", AccountID: "acct_test", AccountLabel: "Primary account", Name: "grok-4.5", UpstreamName: "grok-4.5", DisplayName: "Grok 4.5", Supported: true, CapabilityKnown: true, DiscoveryAvailable: true, SupportsBackendSearch: &search, Allowlisted: true, CanRefresh: true, ContextWindow: 131072, MaxOutputTokens: 8192, DiscoveredAt: fetched}}}
	apiKeys := &fakeAPIKeyService{keys: []APIKey{{ID: "key_test", Prefix: "byos_example", Label: "Test client", CreatedAt: fetched}}, created: CreatedAPIKey{Key: APIKey{ID: "key_new", Prefix: "byos_new", Label: "New key", CreatedAt: clock.value}, Plaintext: "byos_one_time_plaintext"}}
	options := Options{
		AdminPassword: "correct horse battery staple",
		SessionStore:  sessions,
		LoginAttempts: guard,
		TrustedProxy:  requestsource.TrustedProxies{},
		CSRFKey:       keys.WebSession(),
		Services:      Services{Accounts: accounts, OAuth: oauth, Usage: usage, Models: models, APIKeys: apiKeys, Readiness: fakeReadinessService{ready: true}},
		SessionTTL:    30 * time.Minute,
		Now:           clock.Now,
	}
	for _, apply := range configure {
		apply(&options)
	}
	handler, err := NewHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	return &webFixture{clock: clock, database: database, sessions: sessions, attempts: attempts, handler: handler, accounts: accounts, oauth: oauth, usage: usage, models: models, apiKeys: apiKeys, derivedKey: keys}
}

type testBrowser struct {
	client *http.Client
	server *httptest.Server
	base   string
}

func newTestBrowser(t *testing.T, handler http.Handler) *testBrowser {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	return &testBrowser{client: client, server: server, base: server.URL}
}

func (b *testBrowser) request(t *testing.T, method, path string, form url.Values) (*http.Response, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	request, err := http.NewRequest(method, b.base+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response, err := b.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response, string(contents)
}

var csrfFieldPattern = regexp.MustCompile(`name="gorilla\.csrf\.Token" value="([^"]+)"`)

func csrfToken(t *testing.T, body string) string {
	t.Helper()
	match := csrfFieldPattern.FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("CSRF field missing from response body: %s", body)
	}
	return match[1]
}

func loginBrowser(t *testing.T, fixture *webFixture) (*testBrowser, string) {
	t.Helper()
	browser := newTestBrowser(t, fixture.handler.Routes())
	response, body := browser.request(t, http.MethodGet, "/admin/login", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login page status = %d", response.StatusCode)
	}
	token := csrfToken(t, body)
	response, _ = browser.request(t, http.MethodPost, "/admin/login", url.Values{"password": {"correct horse battery staple"}, "gorilla.csrf.Token": {token}})
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/admin/" {
		t.Fatalf("login response = %d %q", response.StatusCode, response.Header.Get("Location"))
	}
	response, body = browser.request(t, http.MethodGet, "/admin/", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("dashboard response = %d", response.StatusCode)
	}
	return browser, csrfToken(t, body)
}
