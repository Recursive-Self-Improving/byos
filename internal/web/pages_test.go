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
		{path: "/admin/accounts/acct_test", want: "Discovered models"},
		{path: "/admin/oauth/new", want: "Start a secure device flow"},
		{path: "/admin/usage", want: "Monthly and weekly provider limits"},
		{path: "/admin/models", want: "Downstream exposure"},
		{path: "/admin/api-keys", want: "Existing keys"},
	}
	for _, page := range pages {
		t.Run(page.path, func(t *testing.T) {
			response, body := browser.request(t, http.MethodGet, page.path, nil)
			if response.StatusCode != http.StatusOK || !strings.Contains(body, page.want) {
				t.Fatalf("GET %s = %d, missing %q", page.path, response.StatusCode, page.want)
			}
			for _, link := range []string{"/admin/accounts", "/admin/usage", "/admin/models", "/admin/api-keys"} {
				if !strings.Contains(body, `href="`+link+`"`) {
					t.Fatalf("GET %s missing navigation link %s", page.path, link)
				}
			}
			if response.Header.Get("Content-Security-Policy") == "" || response.Header.Get("X-Frame-Options") != "DENY" {
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
	if response.StatusCode != http.StatusOK || !strings.Contains(body, "not official API-key billing") || !strings.Contains(body, "never influence routing") {
		t.Fatalf("usage disclosure missing: %d %s", response.StatusCode, body)
	}
}

func TestOAuthFlowStartsResumesPollsCancelsAndRedirects(t *testing.T) {
	fixture := newWebFixture(t)
	browser, token := loginBrowser(t, fixture)
	response, _ := browser.request(t, http.MethodPost, "/admin/oauth/new", url.Values{"gorilla.csrf.Token": {token}})
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/admin/oauth/new?state=state_test" || fixture.oauth.startCalls != 1 {
		t.Fatalf("OAuth start = %d %q calls=%d", response.StatusCode, response.Header.Get("Location"), fixture.oauth.startCalls)
	}

	for range 2 {
		response, body := browser.request(t, http.MethodGet, "/admin/oauth/new?state=state_test", nil)
		if response.StatusCode != http.StatusOK || !strings.Contains(body, "ABCD-EFGH") || !strings.Contains(body, `data-status-url="/admin/oauth/status/state_test"`) {
			t.Fatalf("resumed OAuth page = %d body=%s", response.StatusCode, body)
		}
	}
	if fixture.oauth.startCalls != 1 || len(fixture.oauth.getCalls) != 2 {
		t.Fatalf("refresh restarted flow: starts=%d gets=%d", fixture.oauth.startCalls, len(fixture.oauth.getCalls))
	}

	response, body := browser.request(t, http.MethodGet, "/admin/oauth/status/state_test", nil)
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

	completed := fixture.oauth.flows["state_test"]
	completed.Status = "completed"
	completed.AccountID = "acct_test"
	fixture.oauth.flows["state_test"] = completed
	response, body = browser.request(t, http.MethodGet, "/admin/oauth/status/state_test", nil)
	var terminal map[string]any
	if err := json.Unmarshal([]byte(body), &terminal); err != nil {
		t.Fatal(err)
	}
	if terminal["status"] != "completed" || terminal["account_url"] != "/admin/accounts/acct_test" {
		t.Fatalf("completed OAuth payload = %#v", terminal)
	}
	response, _ = browser.request(t, http.MethodGet, "/admin/oauth/new?state=state_test", nil)
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/admin/accounts/acct_test" {
		t.Fatalf("completed OAuth page = %d %q", response.StatusCode, response.Header.Get("Location"))
	}

	pendingFlow := completed
	pendingFlow.Status = "pending"
	pendingFlow.AccountID = ""
	fixture.oauth.flows["state_test"] = pendingFlow
	response, _ = browser.request(t, http.MethodPost, "/admin/oauth/state_test/cancel", url.Values{"gorilla.csrf.Token": {token}})
	if response.StatusCode != http.StatusSeeOther || len(fixture.oauth.cancelled) != 1 || fixture.oauth.cancelled[0] != "state_test" {
		t.Fatalf("OAuth cancel = %d cancelled=%v", response.StatusCode, fixture.oauth.cancelled)
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
	flow := fixture.oauth.flows["state_test"]
	flow.VerificationURL = "javascript:alert(1)"
	flow.SanitizedMessage = `<svg onload=alert(1)>`
	fixture.oauth.flows["state_test"] = flow
	browser, _ := loginBrowser(t, fixture)

	for _, path := range []string{"/admin/accounts", "/admin/accounts/acct_test", "/admin/models", "/admin/api-keys", "/admin/oauth/new?state=state_test"} {
		response, body := browser.request(t, http.MethodGet, path, nil)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d", path, response.StatusCode)
		}
		if strings.Contains(body, malicious) || strings.Contains(body, `<img src=x`) || strings.Contains(body, `<svg onload`) {
			t.Fatalf("GET %s rendered executable service value", path)
		}
		if path != "/admin/oauth/new?state=state_test" && !strings.Contains(body, "&lt;") {
			t.Fatalf("GET %s did not contain escaped malicious value", path)
		}
		if strings.Contains(strings.ToLower(body), "localstorage") || strings.Contains(body, fixture.apiKeys.created.Plaintext) {
			t.Fatalf("GET %s leaked browser storage or key plaintext", path)
		}
	}
	_, oauthBody := browser.request(t, http.MethodGet, "/admin/oauth/new?state=state_test", nil)
	if strings.Contains(oauthBody, "javascript:alert") || !strings.Contains(oauthBody, "verification link was invalid") {
		t.Fatal("unsafe OAuth verification URL was rendered")
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
		{AccountID: "acct_one", AccountLabel: "First", Weekly: UsagePeriod{Used: 60, Percent: &firstPercent, Unit: "percent"}},
		{AccountID: "acct_two", AccountLabel: "Second", Weekly: UsagePeriod{Used: 70, Percent: &secondPercent, Unit: "percent"}},
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
	flow := fixture.oauth.flows["state_test"]
	flow.ExpiresAt = fixture.clock.Now().Add(-time.Second)
	fixture.oauth.flows["state_test"] = flow
	browser, _ := loginBrowser(t, fixture)
	response, body := browser.request(t, http.MethodGet, "/admin/oauth/status/state_test", nil)
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
