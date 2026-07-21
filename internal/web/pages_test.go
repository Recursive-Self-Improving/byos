package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAuthenticatedNavigationAndPageInventory(t *testing.T) {
	fixture := newWebFixture(t)
	browser, _ := loginBrowser(t, fixture)
	pages := []struct {
		path string
		want string
	}{
		{path: "/admin/", want: "Ready for requests"},
		{path: "/admin/accounts", want: "Primary account"},
		{path: "/admin/accounts/acct_test", want: "Provider models"},
		{path: "/admin/oauth/new", want: "Start a secure provider flow"},
		{path: "/admin/usage", want: "Local proxy counters"},
		{path: "/admin/models", want: "Static ownership"},
		{path: "/admin/api-keys", want: "Existing keys"},
	}
	for _, page := range pages {
		t.Run(page.path, func(t *testing.T) {
			response, body := browser.request(t, http.MethodGet, page.path, nil)
			if response.StatusCode != http.StatusOK || !strings.Contains(body, page.want) {
				t.Fatalf("GET %s = %d, missing %q", page.path, response.StatusCode, page.want)
			}
			if !strings.Contains(body, "BYOS") || strings.Contains(body, "SuperGrok administration") {
				t.Fatalf("GET %s has stale or missing brand", page.path)
			}
			for _, link := range []string{"/admin/accounts", "/admin/usage", "/admin/models", "/admin/api-keys"} {
				if !strings.Contains(body, `href="`+link+`"`) {
					t.Fatalf("GET %s missing navigation link %s", page.path, link)
				}
			}
			if response.Header.Get("Content-Security-Policy") == "" || response.Header.Get("X-Frame-Options") != "DENY" || response.Header.Get("Referrer-Policy") != "same-origin" {
				t.Fatalf("GET %s missing security headers", page.path)
			}
		})
	}

	anonymous := newTestBrowser(t, fixture.handler.Routes())
	for _, asset := range []struct{ path, contentType, marker string }{{"/admin/static/admin.css", "text/css", "--color-canvas"}, {"/admin/static/admin.js", "text/javascript", "data-oauth-flow"}} {
		response, body := anonymous.request(t, http.MethodGet, asset.path, nil)
		if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), asset.contentType) || !strings.Contains(body, asset.marker) {
			t.Fatalf("asset %s = %d %q", asset.path, response.StatusCode, response.Header.Get("Content-Type"))
		}
	}
}

func TestModelsPageShowsAliasBesideCanonicalModel(t *testing.T) {
	fixture := newWebFixture(t)
	alias := fixture.models.values[0]
	alias.Name = "grok"
	alias.OwnedBy = "byos"
	fixture.models.values = append(fixture.models.values, alias)

	browser, _ := loginBrowser(t, fixture)
	response, body := browser.request(t, http.MethodGet, "/admin/models", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/models = %d", response.StatusCode)
	}
	if !strings.Contains(body, `<code>grok-4.5</code> <span class="model-aliases">(Alias: <code>grok</code>)</span>`) {
		t.Fatalf("model alias was not shown inline beside the canonical model: %s", body)
	}
	if strings.Contains(body, "upstream <code>grok-4.5</code>") {
		t.Fatalf("canonical upstream name was shown redundantly: %s", body)
	}
	if !strings.Contains(body, `<th class="model-refresh" scope="col">Refresh</th>`) || !strings.Contains(body, `<td class="model-refresh">`) {
		t.Fatalf("refresh column is missing aligned presentation hooks: %s", body)
	}
	if strings.Count(body, "<tr>") != 2 {
		t.Fatalf("model alias rendered as a separate row: %s", body)
	}
}

func TestDashboardUsesProductionReadiness(t *testing.T) {
	fixture := newWebFixture(t, func(options *Options) { options.Services.Readiness = fakeReadinessService{ready: false} })
	browser, _ := loginBrowser(t, fixture)
	response, body := browser.request(t, http.MethodGet, "/admin/", nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, "Account setup required") || strings.Contains(body, "Ready for requests") {
		t.Fatalf("dashboard=%d %s", response.StatusCode, body)
	}
}
func TestUsagePageDisclosesSnapshotAuthority(t *testing.T) {
	fixture := newWebFixture(t)
	browser, _ := loginBrowser(t, fixture)
	response, body := browser.request(t, http.MethodGet, "/admin/usage", nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, "never influence routing") || !strings.Contains(body, "Local proxy counters") {
		t.Fatalf("usage disclosure missing: %d %s", response.StatusCode, body)
	}
}

func TestUsagePageRendersCacheReadTokens(t *testing.T) {
	fixture := newWebFixture(t)
	fixture.usage.values = []AccountUsage{{Provider: ProviderXAI, AccountID: "acct_cache", AccountLabel: "Cache account", QuotaAvailable: true, CanRefresh: true, Monthly: UsagePeriod{Used: 25, Unit: "credits"}, Local: LocalUsage{Requests: 3, InputTokens: 11, OutputTokens: 13, CacheReadTokens: 7}, FetchedAt: &time.Time{}}}
	browser, _ := loginBrowser(t, fixture)
	response, body := browser.request(t, http.MethodGet, "/admin/usage", nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, "Cache read tokens") || !strings.Contains(body, ">7<") {
		t.Fatalf("cache-read projection missing: %d %s", response.StatusCode, body)
	}
}

func TestUsagePageRendersPeriodResetTime(t *testing.T) {
	fixture := newWebFixture(t)
	monthlyReset := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	weeklyReset := time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC)
	fixture.usage.values = []AccountUsage{{Provider: ProviderXAI, AccountID: "acct_reset", AccountLabel: "Reset account", QuotaAvailable: true, CanRefresh: true, Monthly: UsagePeriod{Used: 25, Unit: "credits", ResetAt: &monthlyReset}, Weekly: UsagePeriod{Used: 40, Unit: "percent", ResetAt: &weeklyReset}, FetchedAt: &time.Time{}}}
	browser, _ := loginBrowser(t, fixture)
	response, body := browser.request(t, http.MethodGet, "/admin/usage", nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, "Resets 2030-01-01 00:00 UTC") || !strings.Contains(body, "Resets 2030-01-02 00:00 UTC") {
		t.Fatalf("reset time missing: status=%d body=%s", response.StatusCode, body)
	}
}

func TestOAuthFlowStartsResumesPollsCancelsAndRedirects(t *testing.T) {
	fixture := newWebFixture(t)
	browser, token := loginBrowser(t, fixture)
	response, _ := browser.request(t, http.MethodPost, "/admin/oauth/new", url.Values{"provider": {"xai"}, "gorilla.csrf.Token": {token}})
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/admin/oauth/new?provider=xai&session_id=state_test" || fixture.oauth.startCalls != 1 || fixture.oauth.startProviders[0] != ProviderXAI {
		t.Fatalf("OAuth start = %d %q calls=%d providers=%v", response.StatusCode, response.Header.Get("Location"), fixture.oauth.startCalls, fixture.oauth.startProviders)
	}

	for range 2 {
		response, body := browser.request(t, http.MethodGet, "/admin/oauth/new?provider=xai&session_id=state_test", nil)
		if response.StatusCode != http.StatusOK || !strings.Contains(body, "ABCD-EFGH") || !strings.Contains(body, `data-status-url="/admin/oauth/xai/status/state_test"`) {
			t.Fatalf("resumed OAuth page = %d body=%s", response.StatusCode, body)
		}
	}
	if fixture.oauth.startCalls != 1 || len(fixture.oauth.getCalls) != 2 {
		t.Fatalf("refresh restarted flow: starts=%d gets=%d", fixture.oauth.startCalls, len(fixture.oauth.getCalls))
	}

	response, body := browser.request(t, http.MethodGet, "/admin/oauth/xai/status/state_test", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("pending OAuth status = %d", response.StatusCode)
	}
	var pending map[string]any
	if err := json.Unmarshal([]byte(body), &pending); err != nil {
		t.Fatal(err)
	}
	if pending["status"] != "pending" || pending["poll_after_ms"].(float64) != 5000 {
		t.Fatalf("pending OAuth payload = %#v", pending)
	}
	for _, forbidden := range []string{"device_code", "access_token", "refresh_token"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("OAuth status exposed %q", forbidden)
		}
	}

	completed := fixture.oauth.flows["xai/state_test"]
	completed.Status = "completed"
	completed.AccountID = "acct_test"
	fixture.oauth.flows["xai/state_test"] = completed
	response, body = browser.request(t, http.MethodGet, "/admin/oauth/xai/status/state_test", nil)
	var terminal map[string]any
	if err := json.Unmarshal([]byte(body), &terminal); err != nil {
		t.Fatal(err)
	}
	if terminal["status"] != "completed" || terminal["account_url"] != "/admin/accounts/acct_test" {
		t.Fatalf("completed OAuth payload = %#v", terminal)
	}
	response, _ = browser.request(t, http.MethodGet, "/admin/oauth/new?provider=xai&session_id=state_test", nil)
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/admin/accounts/acct_test" {
		t.Fatalf("completed OAuth page = %d %q", response.StatusCode, response.Header.Get("Location"))
	}

	pendingFlow := completed
	pendingFlow.Status = "pending"
	pendingFlow.AccountID = ""
	fixture.oauth.flows["xai/state_test"] = pendingFlow
	response, _ = browser.request(t, http.MethodPost, "/admin/oauth/xai/cancel/state_test", url.Values{"gorilla.csrf.Token": {token}})
	if response.StatusCode != http.StatusSeeOther || len(fixture.oauth.cancelled) != 1 || fixture.oauth.cancelled[0] != (oauthServiceCall{Provider: ProviderXAI, SessionID: "state_test"}) {
		t.Fatalf("OAuth cancel = %d cancelled=%v", response.StatusCode, fixture.oauth.cancelled)
	}
}

func TestOAuthProviderSelectionAndDevinLifecycle(t *testing.T) {
	fixture := newWebFixture(t)
	browser, token := loginBrowser(t, fixture)

	response, body := browser.request(t, http.MethodGet, "/admin/oauth/new?provider=devin", nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, `value="devin" selected`) || !strings.Contains(body, "Devin browser callback") || !strings.Contains(body, `data-oauth-provider`) || !strings.Contains(body, `data-oauth-start>Start Devin connection`) {
		t.Fatalf("Devin selector page = %d body=%s", response.StatusCode, body)
	}
	response, body = browser.request(t, http.MethodGet, "/admin/oauth/new?provider=xai", nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, `value="xai" selected`) || !strings.Contains(body, `data-oauth-start>Start xAI connection`) {
		t.Fatalf("xAI selector page = %d body=%s", response.StatusCode, body)
	}
	response, _ = browser.request(t, http.MethodGet, "/admin/oauth/new?provider=unknown", nil)
	if response.StatusCode != http.StatusBadRequest || fixture.oauth.startCalls != 0 {
		t.Fatalf("unknown provider = %d starts=%d", response.StatusCode, fixture.oauth.startCalls)
	}

	const authorizationURL = "https://preview.devin.ai/oauth/authorize?state=raw-state-secret&code_challenge=verifier-canary&token=token-canary&identity=user-jwt-canary"
	fixture.oauth.startFlow = OAuthFlow{SessionID: "devin_session", Status: "pending", AuthorizationURL: authorizationURL, ExpiresAt: fixture.clock.Now().Add(5 * time.Minute), PollAfter: 2 * time.Second}
	response, _ = browser.request(t, http.MethodPost, "/admin/oauth/new", url.Values{"provider": {"devin"}, "gorilla.csrf.Token": {token}})
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/admin/oauth/new?provider=devin&session_id=devin_session" || len(fixture.oauth.startProviders) != 1 || fixture.oauth.startProviders[0] != ProviderDevin {
		t.Fatalf("Devin start = %d location=%q providers=%v", response.StatusCode, response.Header.Get("Location"), fixture.oauth.startProviders)
	}

	response, body = browser.request(t, http.MethodGet, "/admin/oauth/new?provider=devin&session_id=devin_session", nil)
	for _, required := range []string{"Approve the connection with Devin", "Open Devin authorization", "Localhost callback URL", `data-oauth-flow`, `data-status-url="/admin/oauth/devin/status/devin_session"`, `action="/admin/oauth/devin/complete/devin_session"`, `action="/admin/oauth/devin/cancel/devin_session"`} {
		if response.StatusCode != http.StatusOK || !strings.Contains(body, required) {
			t.Fatalf("Devin flow missing %q: status=%d body=%s", required, response.StatusCode, body)
		}
	}
	for _, forbidden := range []string{"raw-state-secret", "verifier-canary", "token-canary", "user-jwt-canary", "Device user code", "xAI verification", "ABCD-EFGH"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("Devin flow exposed or reused %q: %s", forbidden, body)
		}
	}

	response, body = browser.request(t, http.MethodGet, "/admin/oauth/devin/authorize/devin_session", nil)
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != authorizationURL || body != "" || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Devin authorize = %d location=%q cache=%q body=%q", response.StatusCode, response.Header.Get("Location"), response.Header.Get("Cache-Control"), body)
	}

	flow := fixture.oauth.flows["devin/devin_session"]
	flow.Status = "consumed"
	flow.AuthorizationURL = ""
	fixture.oauth.flows["devin/devin_session"] = flow
	response, body = browser.request(t, http.MethodGet, "/admin/oauth/devin/status/devin_session", nil)
	var pending oauthStatusResponse
	if err := json.Unmarshal([]byte(body), &pending); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || pending.Provider != ProviderDevin || pending.Status != "pending" || strings.Contains(body, "raw-state-secret") {
		t.Fatalf("consumed Devin status = %d %#v body=%s", response.StatusCode, pending, body)
	}
	response, _ = browser.request(t, http.MethodGet, "/admin/oauth/xai/status/devin_session", nil)
	if response.StatusCode != http.StatusNotFound || fixture.oauth.getCalls[len(fixture.oauth.getCalls)-1] != (oauthServiceCall{Provider: ProviderXAI, SessionID: "devin_session"}) {
		t.Fatalf("wrong-provider status = %d calls=%v", response.StatusCode, fixture.oauth.getCalls)
	}
	expired := flow
	expired.Status = "expired"
	expired.SanitizedMessage = "Devin authorization expired. Start a new connection."
	fixture.oauth.flows["devin/devin_session"] = expired
	response, body = browser.request(t, http.MethodGet, "/admin/oauth/devin/status/devin_session", nil)
	var expiredStatus oauthStatusResponse
	if err := json.Unmarshal([]byte(body), &expiredStatus); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || expiredStatus.Status != "failed" || strings.Contains(strings.ToLower(body), "device code") || !strings.Contains(body, "Devin authorization expired") {
		t.Fatalf("expired Devin status = %d %#v body=%s", response.StatusCode, expiredStatus, body)
	}
	fixture.oauth.flows["devin/devin_session"] = flow
	response, _ = browser.request(t, http.MethodPost, "/admin/oauth/devin/cancel/devin_session", url.Values{"gorilla.csrf.Token": {token}})
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/admin/oauth/new?provider=devin&notice=oauth-cancelled" || fixture.oauth.cancelled[len(fixture.oauth.cancelled)-1] != (oauthServiceCall{Provider: ProviderDevin, SessionID: "devin_session"}) {
		t.Fatalf("Devin cancel = %d location=%q calls=%v", response.StatusCode, response.Header.Get("Location"), fixture.oauth.cancelled)
	}

	flow.Status = "completed"
	flow.AccountID = "acct_test"
	fixture.oauth.flows["devin/devin_session"] = flow
	response, body = browser.request(t, http.MethodGet, "/admin/oauth/devin/status/devin_session", nil)
	var completed oauthStatusResponse
	if err := json.Unmarshal([]byte(body), &completed); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || completed.Status != "completed" || completed.AccountURL != "/admin/accounts/acct_test" {
		t.Fatalf("completed Devin status = %d %#v", response.StatusCode, completed)
	}
	response, _ = browser.request(t, http.MethodGet, "/admin/oauth/new?provider=devin&session_id=devin_session", nil)
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/admin/accounts/acct_test" {
		t.Fatalf("completed Devin page = %d location=%q", response.StatusCode, response.Header.Get("Location"))
	}
}

func TestDevinManualCallbackFormCompletesRemoteFlow(t *testing.T) {
	fixture := newWebFixture(t)
	browser, token := loginBrowser(t, fixture)
	fixture.oauth.startFlow = OAuthFlow{SessionID: "manual_session", Status: "pending", AuthorizationURL: "https://app.devin.ai/auth/cli/continue", ExpiresAt: fixture.clock.Now().Add(5 * time.Minute), PollAfter: 2 * time.Second}
	response, _ := browser.request(t, http.MethodPost, "/admin/oauth/new", url.Values{"provider": {"devin"}, "gorilla.csrf.Token": {token}})
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("start status=%d", response.StatusCode)
	}
	const callbackURL = "http://127.0.0.1:59653/callback?code=manual-code-secret&state=manual-state-secret"
	response, body := browser.request(t, http.MethodPost, "/admin/oauth/devin/complete/manual_session", url.Values{"callback_url": {callbackURL}, "gorilla.csrf.Token": {token}})
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/admin/oauth/new?provider=devin&session_id=manual_session" {
		t.Fatalf("complete status=%d location=%q body=%s", response.StatusCode, response.Header.Get("Location"), body)
	}
	if fixture.oauth.completedSession != "manual_session" || fixture.oauth.completedCallback != callbackURL {
		t.Fatalf("manual callback session=%q callback=%q", fixture.oauth.completedSession, fixture.oauth.completedCallback)
	}
	if strings.Contains(body, "manual-code-secret") || strings.Contains(body, "manual-state-secret") {
		t.Fatalf("manual callback leaked in response: %s", body)
	}
	response, _ = browser.request(t, http.MethodGet, "/admin/oauth/new?provider=devin&session_id=manual_session", nil)
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/admin/accounts/acct_test" {
		t.Fatalf("completed page status=%d location=%q", response.StatusCode, response.Header.Get("Location"))
	}
}

func TestProviderCapabilityPresentationAndUnavailableActions(t *testing.T) {
	fixture := newWebFixture(t)
	fetched := fixture.clock.Now().Add(-time.Minute)
	fixture.accounts.summaries = append(fixture.accounts.summaries, AccountSummary{Provider: ProviderDevin, ID: "acct_devin", Label: "Devin account", Status: "relogin_required", StatusLabel: "Reconnect required", NeedsRelogin: true, CanRelogin: true, ModelCount: 1})
	fixture.models.values = append(fixture.models.values, ModelSupport{Provider: ProviderDevin, OwnedBy: "devin", AccountID: "acct_devin", AccountLabel: "Devin account", Name: "kimi-k2-7", UpstreamName: "kimi-k2-7", Supported: true, DiscoveryAvailable: false, Allowlisted: true})
	fixture.usage.values = append(fixture.usage.values, AccountUsage{Provider: ProviderDevin, AccountID: "acct_devin", AccountLabel: "Devin account", QuotaAvailable: false, Monthly: UsagePeriod{Used: 987654, Unit: "raw-billing-canary"}, Local: LocalUsage{Requests: 7, InputTokens: 11, OutputTokens: 13}, FetchedAt: &fetched})
	browser, token := loginBrowser(t, fixture)
	fixture.accounts.detail = AccountDetail{AccountSummary: AccountSummary{Provider: ProviderDevin, ID: "acct_devin", Label: "Devin account", Status: "relogin_required", StatusLabel: "Reconnect required", NeedsRelogin: true, CanRelogin: true}, Models: []AccountModel{{Provider: ProviderDevin, Name: "kimi-k2-7", UpstreamName: "kimi-k2-7", OwnedBy: "devin", Supported: true, DiscoveryAvailable: false}}}
	response, body := browser.request(t, http.MethodGet, "/admin/accounts/acct_devin", nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, "Start a new Devin connection") || !strings.Contains(body, "In-place credential refresh is unavailable for Devin") || strings.Contains(body, `action="/admin/accounts/acct_devin/refresh"`) {
		t.Fatalf("Devin account detail = %d body=%s", response.StatusCode, body)
	}

	response, body = browser.request(t, http.MethodGet, "/admin/accounts", nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, "Devin account") || !strings.Contains(body, "Reconnect required") || !strings.Contains(body, "/admin/oauth/new?provider=devin") {
		t.Fatalf("provider account list = %d body=%s", response.StatusCode, body)
	}
	response, body = browser.request(t, http.MethodGet, "/admin/models", nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, "kimi-k2-7") || !strings.Contains(body, "Static support") || strings.Contains(body, `action="/admin/models/acct_devin/refresh"`) {
		t.Fatalf("provider model page = %d body=%s", response.StatusCode, body)
	}
	response, body = browser.request(t, http.MethodGet, "/admin/usage", nil)
	for _, required := range []string{"Devin account", "Upstream quota", "Unavailable", ">7<", ">11<", ">13<"} {
		if response.StatusCode != http.StatusOK || !strings.Contains(body, required) {
			t.Fatalf("Devin usage missing %q: status=%d body=%s", required, response.StatusCode, body)
		}
	}
	for _, forbidden := range []string{"987654", "raw-billing-canary", `/admin/usage/acct_devin/refresh`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("Devin usage fabricated %q: %s", forbidden, body)
		}
	}

	fixture.accounts.refreshErr = ErrActionUnavailable
	fixture.usage.refreshErr = ErrActionUnavailable
	fixture.models.refreshErr = ErrActionUnavailable
	for _, path := range []string{"/admin/accounts/acct_test/refresh", "/admin/usage/acct_test/refresh", "/admin/models/acct_test/refresh"} {
		response, body = browser.request(t, http.MethodPost, path, url.Values{"gorilla.csrf.Token": {token}})
		if response.StatusCode != http.StatusConflict || !strings.Contains(body, "unavailable for the account provider") {
			t.Fatalf("unavailable POST %s = %d body=%s", path, response.StatusCode, body)
		}
	}
}

func TestAllManagementActionsUseServices(t *testing.T) {
	fixture := newWebFixture(t)
	browser, token := loginBrowser(t, fixture)
	actions := []struct {
		path string
		form url.Values
	}{
		{path: "/admin/accounts/acct_test/label", form: url.Values{"label": {"Renamed account"}, "gorilla.csrf.Token": {token}}},
		{path: "/admin/accounts/acct_test/enabled", form: url.Values{"enabled": {"false"}, "gorilla.csrf.Token": {token}}},
		{path: "/admin/accounts/acct_test/refresh", form: url.Values{"gorilla.csrf.Token": {token}}},
		{path: "/admin/usage/acct_test/refresh", form: url.Values{"gorilla.csrf.Token": {token}}},
		{path: "/admin/models/acct_test/refresh", form: url.Values{"gorilla.csrf.Token": {token}}},
	}
	for _, action := range actions {
		response, _ := browser.request(t, http.MethodPost, action.path, action.form)
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("POST %s status = %d", action.path, response.StatusCode)
		}
	}
	if len(fixture.accounts.updates) != 2 || fixture.accounts.updates[0].Label == nil || *fixture.accounts.updates[0].Label != "Renamed account" || fixture.accounts.updates[0].Enabled != nil {
		t.Fatalf("label update = %#v", fixture.accounts.updates)
	}
	if fixture.accounts.updates[1].Enabled == nil || *fixture.accounts.updates[1].Enabled || fixture.accounts.updates[1].Label != nil {
		t.Fatalf("enabled update = %#v", fixture.accounts.updates[1])
	}
	if len(fixture.accounts.refreshedIDs) != 1 || len(fixture.usage.refreshedIDs) != 1 || len(fixture.models.refreshedIDs) != 1 {
		t.Fatalf("refresh calls: accounts=%v usage=%v models=%v", fixture.accounts.refreshedIDs, fixture.usage.refreshedIDs, fixture.models.refreshedIDs)
	}
}

func TestDestructiveActionsRequireExplicitConfirmation(t *testing.T) {
	fixture := newWebFixture(t)
	browser, token := loginBrowser(t, fixture)
	response, body := browser.request(t, http.MethodGet, "/admin/accounts/acct_test", nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, `name="confirm" value="delete" required`) {
		t.Fatal("account page lacks required deletion confirmation")
	}
	response, _ = browser.request(t, http.MethodPost, "/admin/accounts/acct_test/delete", url.Values{"gorilla.csrf.Token": {token}})
	if response.StatusCode != http.StatusBadRequest || len(fixture.accounts.deletedIDs) != 0 {
		t.Fatalf("unconfirmed account delete = %d calls=%v", response.StatusCode, fixture.accounts.deletedIDs)
	}
	response, _ = browser.request(t, http.MethodPost, "/admin/accounts/acct_test/delete", url.Values{"confirm": {"delete"}, "gorilla.csrf.Token": {token}})
	if response.StatusCode != http.StatusSeeOther || len(fixture.accounts.deletedIDs) != 1 {
		t.Fatalf("confirmed account delete = %d calls=%v", response.StatusCode, fixture.accounts.deletedIDs)
	}

	response, body = browser.request(t, http.MethodGet, "/admin/api-keys", nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, `name="confirm" value="revoke" required`) {
		t.Fatal("API-key page lacks required revocation confirmation")
	}
	response, _ = browser.request(t, http.MethodPost, "/admin/api-keys/key_test/revoke", url.Values{"gorilla.csrf.Token": {token}})
	if response.StatusCode != http.StatusBadRequest || len(fixture.apiKeys.revokedIDs) != 0 {
		t.Fatalf("unconfirmed key revoke = %d calls=%v", response.StatusCode, fixture.apiKeys.revokedIDs)
	}
	response, _ = browser.request(t, http.MethodPost, "/admin/api-keys/key_test/revoke", url.Values{"confirm": {"revoke"}, "gorilla.csrf.Token": {token}})
	if response.StatusCode != http.StatusSeeOther || len(fixture.apiKeys.revokedIDs) != 1 {
		t.Fatalf("confirmed key revoke = %d calls=%v", response.StatusCode, fixture.apiKeys.revokedIDs)
	}
}

func TestAPIKeyPlaintextIsDisplayedOnlyOnCreateResponse(t *testing.T) {
	fixture := newWebFixture(t)
	browser, token := loginBrowser(t, fixture)
	plaintext := fixture.apiKeys.created.Plaintext
	response, body := browser.request(t, http.MethodPost, "/admin/api-keys", url.Values{"label": {"Production"}, "gorilla.csrf.Token": {token}})
	if response.StatusCode != http.StatusCreated || !strings.Contains(body, plaintext) || !strings.Contains(body, "Shown once") {
		t.Fatalf("create key response = %d body=%s", response.StatusCode, body)
	}
	if len(fixture.apiKeys.createLabels) != 1 || fixture.apiKeys.createLabels[0] != "Production" {
		t.Fatalf("create labels = %v", fixture.apiKeys.createLabels)
	}
	for name, values := range response.Header {
		if strings.Contains(strings.Join(values, "\n"), plaintext) {
			t.Fatalf("plaintext API key leaked through response header %s", name)
		}
	}
	response, body = browser.request(t, http.MethodGet, "/admin/api-keys", nil)
	if response.StatusCode != http.StatusOK || strings.Contains(body, plaintext) {
		t.Fatal("previously issued plaintext API key appeared on list page")
	}
	response, script := browser.request(t, http.MethodGet, "/admin/static/admin.js", nil)
	if response.StatusCode != http.StatusOK || strings.Contains(strings.ToLower(script), "localstorage") {
		t.Fatal("Web UI script uses browser localStorage")
	}
}

func TestSafeRenderingEscapesServiceValuesAndRejectsUnsafeOAuthLinks(t *testing.T) {
	fixture := newWebFixture(t)
	malicious := `<script>alert("owned")</script>`
	fixture.accounts.detail.Label = malicious
	fixture.accounts.detail.SanitizedError = `<img src=x onerror=alert(1)>`
	fixture.accounts.summaries[0].Label = malicious
	fixture.accounts.summaries[0].SanitizedError = `<b>bad</b>`
	fixture.apiKeys.keys[0].Label = malicious
	fixture.models.values[0].DisplayName = malicious
	flow := fixture.oauth.flows["xai/state_test"]
	flow.AuthorizationURL = "javascript:alert(1)"
	flow.SanitizedMessage = `<svg onload=alert(1)>`
	fixture.oauth.flows["xai/state_test"] = flow
	browser, _ := loginBrowser(t, fixture)

	for _, path := range []string{"/admin/accounts", "/admin/accounts/acct_test", "/admin/models", "/admin/api-keys", "/admin/oauth/new?provider=xai&session_id=state_test"} {
		response, body := browser.request(t, http.MethodGet, path, nil)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d", path, response.StatusCode)
		}
		if strings.Contains(body, malicious) || strings.Contains(body, `<img src=x`) || strings.Contains(body, `<svg onload`) {
			t.Fatalf("GET %s rendered executable service value", path)
		}
		if !strings.Contains(path, "/admin/oauth/new") && !strings.Contains(body, "&lt;") {
			t.Fatalf("GET %s did not contain escaped malicious value", path)
		}
		if strings.Contains(strings.ToLower(body), "localstorage") || strings.Contains(body, fixture.apiKeys.created.Plaintext) {
			t.Fatalf("GET %s leaked browser storage or key plaintext", path)
		}
	}
	_, oauthBody := browser.request(t, http.MethodGet, "/admin/oauth/new?provider=xai&session_id=state_test", nil)
	if strings.Contains(oauthBody, "javascript:alert") || !strings.Contains(oauthBody, "verification link is unavailable") {
		t.Fatal("unsafe OAuth authorization URL was rendered")
	}
	fixture.accounts.getErr = errors.New("upstream access_token=secret-canary")
	response, errorBody := browser.request(t, http.MethodGet, "/admin/accounts/acct_test", nil)
	if response.StatusCode != http.StatusServiceUnavailable || strings.Contains(errorBody, "secret-canary") || strings.Contains(errorBody, "access_token") {
		t.Fatal("operational service error leaked into rendered response")
	}
}

func TestUsageKeepsWeeklyPercentagesPerAccount(t *testing.T) {
	fixture := newWebFixture(t)
	firstPercent := 60.0
	secondPercent := 70.0
	fixture.usage.values = []AccountUsage{
		{Provider: ProviderXAI, AccountID: "acct_one", AccountLabel: "First", QuotaAvailable: true, Weekly: UsagePeriod{Used: 60, Percent: &firstPercent, Unit: "percent"}},
		{Provider: ProviderXAI, AccountID: "acct_two", AccountLabel: "Second", QuotaAvailable: true, Weekly: UsagePeriod{Used: 70, Percent: &secondPercent, Unit: "percent"}},
	}
	browser, _ := loginBrowser(t, fixture)
	response, body := browser.request(t, http.MethodGet, "/admin/usage", nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, "60.0%") || !strings.Contains(body, "70.0%") {
		t.Fatalf("per-account weekly percentages missing: status=%d body=%s", response.StatusCode, body)
	}
	if strings.Contains(body, "130.0%") {
		t.Fatal("weekly percentages were incorrectly aggregated")
	}
}

func TestOAuthPollingStopsAtExpiryServerSide(t *testing.T) {
	fixture := newWebFixture(t)
	flow := fixture.oauth.flows["xai/state_test"]
	flow.ExpiresAt = fixture.clock.Now().Add(-time.Second)
	fixture.oauth.flows["xai/state_test"] = flow
	browser, _ := loginBrowser(t, fixture)
	response, body := browser.request(t, http.MethodGet, "/admin/oauth/xai/status/state_test", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expired OAuth status = %d", response.StatusCode)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["status"] != "expired" {
		t.Fatalf("expired OAuth payload = %#v", payload)
	}
}
