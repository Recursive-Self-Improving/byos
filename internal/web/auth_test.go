package web

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAdminSessionRepositoryLifecycleAndEncryptedState(t *testing.T) {
	fixture := newWebFixture(t)
	createdAt := fixture.clock.Now()
	expiresAt := createdAt.Add(20 * time.Minute)
	created, err := fixture.sessions.Create(context.Background(), createdAt, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(created.Token)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("session token has invalid entropy: len=%d err=%v", len(decoded), err)
	}
	lookup, err := fixture.sessions.Get(context.Background(), created.Token, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	if lookup.CSRFSecret != created.Session.CSRFSecret || !lookup.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("stored session mismatch: %#v", lookup)
	}

	hash := sha256.Sum256([]byte(created.Token))
	var storedHash []byte
	var encrypted string
	if err := fixture.database.DB.QueryRow(`SELECT id_hash,csrf_secret_encrypted FROM admin_sessions WHERE id_hash=?`, hash[:]).Scan(&storedHash, &encrypted); err != nil {
		t.Fatal(err)
	}
	if string(storedHash) == created.Token || strings.Contains(encrypted, created.Token) {
		t.Fatal("plaintext session token reached the database")
	}
	encodedSecret := base64.RawStdEncoding.EncodeToString(created.Session.CSRFSecret[:])
	if strings.Contains(encrypted, encodedSecret) || encrypted == string(created.Session.CSRFSecret[:]) {
		t.Fatal("plaintext CSRF secret reached the database")
	}

	if err := fixture.sessions.Revoke(context.Background(), created.Token, createdAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.sessions.Get(context.Background(), created.Token, createdAt.Add(2*time.Minute)); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("revoked session lookup error = %v", err)
	}
	if _, err := fixture.sessions.Create(context.Background(), createdAt, createdAt); err == nil {
		t.Fatal("non-positive session lifetime was accepted")
	}

	expired, err := fixture.sessions.Create(context.Background(), createdAt, createdAt.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.sessions.Get(context.Background(), expired.Token, createdAt.Add(5*time.Minute)); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expired session lookup error = %v", err)
	}
	removed, err := fixture.sessions.Cleanup(context.Background(), createdAt.Add(6*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if removed < 2 {
		t.Fatalf("cleanup removed %d sessions, want at least 2", removed)
	}
}

func TestLoginLogoutExpiryAndServerSideRevocation(t *testing.T) {
	t.Run("login and logout", func(t *testing.T) {
		fixture := newWebFixture(t)
		browser := newTestBrowser(t, fixture.handler.Routes())
		response, _ := browser.request(t, http.MethodGet, "/admin/", nil)
		if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/admin/login" {
			t.Fatalf("unauthenticated response = %d %q", response.StatusCode, response.Header.Get("Location"))
		}

		response, body := browser.request(t, http.MethodGet, "/admin/login", nil)
		token := csrfToken(t, body)
		response, body = browser.request(t, http.MethodPost, "/admin/login", url.Values{"password": {"wrong password"}, "gorilla.csrf.Token": {token}})
		if response.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "password was not accepted") {
			t.Fatalf("failed login response = %d %s", response.StatusCode, body)
		}
		var count int
		if err := fixture.database.DB.QueryRow(`SELECT count(*) FROM admin_sessions`).Scan(&count); err != nil || count != 0 {
			t.Fatalf("failed login session count = %d, %v", count, err)
		}

		browser, token = loginBrowser(t, fixture)
		sessionToken := browserCookieValue(t, browser, SessionCookieName)
		if _, err := fixture.sessions.Get(context.Background(), sessionToken, fixture.clock.Now()); err != nil {
			t.Fatalf("created session unavailable: %v", err)
		}
		response, _ = browser.request(t, http.MethodPost, "/admin/logout", url.Values{"gorilla.csrf.Token": {token}})
		if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/admin/login" {
			t.Fatalf("logout response = %d %q", response.StatusCode, response.Header.Get("Location"))
		}
		if _, err := fixture.sessions.Get(context.Background(), sessionToken, fixture.clock.Now()); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("logged-out session lookup error = %v", err)
		}
		response, _ = browser.request(t, http.MethodGet, "/admin/", nil)
		if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/admin/login" {
			t.Fatalf("post-logout access = %d %q", response.StatusCode, response.Header.Get("Location"))
		}
	})

	t.Run("expiry", func(t *testing.T) {
		fixture := newWebFixture(t)
		browser, _ := loginBrowser(t, fixture)
		fixture.clock.value = fixture.clock.value.Add(31 * time.Minute)
		response, body := browser.request(t, http.MethodGet, "/admin/", nil)
		if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/admin/login?expired=1" {
			t.Fatalf("expired session response = %d %q body=%s", response.StatusCode, response.Header.Get("Location"), body)
		}
		if !responseDeletesCookie(response, SessionCookieName) {
			t.Fatal("expired session cookie was not cleared")
		}
	})

	t.Run("server-side revocation", func(t *testing.T) {
		fixture := newWebFixture(t)
		browser, _ := loginBrowser(t, fixture)
		sessionToken := browserCookieValue(t, browser, SessionCookieName)
		if err := fixture.sessions.Revoke(context.Background(), sessionToken, fixture.clock.Now()); err != nil {
			t.Fatal(err)
		}
		response, _ := browser.request(t, http.MethodGet, "/admin/accounts", nil)
		if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/admin/login?expired=1" {
			t.Fatalf("revoked session response = %d %q", response.StatusCode, response.Header.Get("Location"))
		}
	})
}

func TestCSRFMiddlewareProtectsLoginAndManagementMutations(t *testing.T) {
	fixture := newWebFixture(t)
	browser := newTestBrowser(t, fixture.handler.Routes())
	response, _ := browser.request(t, http.MethodPost, "/admin/login", url.Values{"password": {"correct horse battery staple"}})
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("login without CSRF status = %d", response.StatusCode)
	}
	var count int
	if err := fixture.database.DB.QueryRow(`SELECT count(*) FROM admin_sessions`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("CSRF-rejected login session count = %d, %v", count, err)
	}

	browser, token := loginBrowser(t, fixture)
	response, _ = browser.request(t, http.MethodPost, "/admin/accounts/acct_test/enabled", url.Values{"enabled": {"false"}})
	if response.StatusCode != http.StatusForbidden || len(fixture.accounts.updates) != 0 {
		t.Fatalf("mutation without CSRF = status %d updates %d", response.StatusCode, len(fixture.accounts.updates))
	}
	response, _ = browser.request(t, http.MethodPost, "/admin/accounts/acct_test/enabled", url.Values{"enabled": {"false"}, "gorilla.csrf.Token": {token}})
	if response.StatusCode != http.StatusSeeOther || len(fixture.accounts.updates) != 1 {
		t.Fatalf("mutation with CSRF = status %d updates %d", response.StatusCode, len(fixture.accounts.updates))
	}
}

func TestCookieSecurityAndTrustedProxyHandling(t *testing.T) {
	trusted, err := ParseTrustedProxies([]string{"10.0.0.0/8", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTrustedProxies([]string{"not-a-network"}); err == nil {
		t.Fatal("invalid trusted proxy was accepted")
	}
	for _, test := range []struct {
		name       string
		remote     string
		forwarded  string
		tls        bool
		wantSecure bool
	}{
		{name: "untrusted spoof", remote: "198.51.100.10:443", forwarded: "https", wantSecure: false},
		{name: "trusted https", remote: "10.2.3.4:443", forwarded: "https", wantSecure: true},
		{name: "trusted rightmost http fails closed", remote: "10.2.3.4:443", forwarded: "https, http", wantSecure: false},
		{name: "direct TLS", remote: "198.51.100.10:443", forwarded: "http", tls: true, wantSecure: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://admin.test/admin/login", nil)
			request.RemoteAddr = test.remote
			request.Header.Set("X-Forwarded-Proto", test.forwarded)
			if test.tls {
				request.TLS = &tls.ConnectionState{}
			}
			if got := trusted.RequestIsHTTPS(request); got != test.wantSecure {
				t.Fatalf("RequestIsHTTPS = %v, want %v", got, test.wantSecure)
			}
		})
	}

	fixture := newWebFixture(t, func(options *Options) { options.TrustedProxy = trusted })
	routes := fixture.handler.Routes()
	get := httptest.NewRequest(http.MethodGet, "http://admin.test/admin/login", nil)
	get.RemoteAddr = "10.1.2.3:1234"
	get.Header.Set("X-Forwarded-Proto", "https")
	getRecorder := httptest.NewRecorder()
	routes.ServeHTTP(getRecorder, get)
	csrfCookie := namedCookie(t, getRecorder.Result().Cookies(), CSRFCookieName, true)
	if !csrfCookie.Secure || !csrfCookie.HttpOnly || csrfCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("CSRF cookie flags = Secure:%v HttpOnly:%v SameSite:%v", csrfCookie.Secure, csrfCookie.HttpOnly, csrfCookie.SameSite)
	}
	token := csrfToken(t, getRecorder.Body.String())

	post := httptest.NewRequest(http.MethodPost, "http://admin.test/admin/login", strings.NewReader(url.Values{"password": {"correct horse battery staple"}, "gorilla.csrf.Token": {token}}.Encode()))
	post.RemoteAddr = "10.1.2.3:1234"
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("X-Forwarded-Proto", "https")
	post.Header.Set("Origin", "https://admin.test")
	post.AddCookie(csrfCookie)
	postRecorder := httptest.NewRecorder()
	routes.ServeHTTP(postRecorder, post)
	if postRecorder.Code != http.StatusSeeOther {
		t.Fatalf("trusted proxy login status = %d body=%s", postRecorder.Code, postRecorder.Body.String())
	}
	sessionCookie := namedCookie(t, postRecorder.Result().Cookies(), SessionCookieName, true)
	if !sessionCookie.Secure || !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteStrictMode || sessionCookie.Path != "/admin" {
		t.Fatalf("session cookie flags = %#v", sessionCookie)
	}

	untrustedFixture := newWebFixture(t, func(options *Options) { options.TrustedProxy = trusted })
	untrustedGet := httptest.NewRequest(http.MethodGet, "http://admin.test/admin/login", nil)
	untrustedGet.RemoteAddr = "198.51.100.10:1234"
	untrustedGet.Header.Set("X-Forwarded-Proto", "https")
	untrustedRecorder := httptest.NewRecorder()
	untrustedFixture.handler.Routes().ServeHTTP(untrustedRecorder, untrustedGet)
	untrustedCookie := namedCookie(t, untrustedRecorder.Result().Cookies(), CSRFCookieName, true)
	if untrustedCookie.Secure {
		t.Fatal("untrusted forwarded header enabled Secure cookie behavior")
	}
	untrustedToken := csrfToken(t, untrustedRecorder.Body.String())
	untrustedPost := httptest.NewRequest(http.MethodPost, "http://admin.test/admin/login", strings.NewReader(url.Values{"password": {"correct horse battery staple"}, "gorilla.csrf.Token": {untrustedToken}}.Encode()))
	untrustedPost.RemoteAddr = "198.51.100.10:1234"
	untrustedPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	untrustedPost.Header.Set("X-Forwarded-Proto", "https")
	untrustedPost.AddCookie(untrustedCookie)
	untrustedPostRecorder := httptest.NewRecorder()
	untrustedFixture.handler.Routes().ServeHTTP(untrustedPostRecorder, untrustedPost)
	if untrustedPostRecorder.Code != http.StatusSeeOther {
		t.Fatalf("untrusted proxy login status = %d body=%s", untrustedPostRecorder.Code, untrustedPostRecorder.Body.String())
	}
	untrustedSessionCookie := namedCookie(t, untrustedPostRecorder.Result().Cookies(), SessionCookieName, true)
	if untrustedSessionCookie.Secure {
		t.Fatal("untrusted forwarded header enabled Secure session cookie")
	}
	if untrustedRecorder.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("untrusted forwarded header enabled HSTS")
	}
}

func browserCookieValue(t *testing.T, browser *testBrowser, name string) string {
	t.Helper()
	parsed, err := url.Parse(browser.base + "/admin/")
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range browser.client.Jar.Cookies(parsed) {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	t.Fatalf("cookie %s not found", name)
	return ""
}

func responseDeletesCookie(response *http.Response, name string) bool {
	for _, cookie := range response.Cookies() {
		if cookie.Name == name && cookie.MaxAge < 0 {
			return true
		}
	}
	return false
}

func namedCookie(t *testing.T, cookies []*http.Cookie, name string, nonempty bool) *http.Cookie {
	t.Helper()
	for index := len(cookies) - 1; index >= 0; index-- {
		if cookies[index].Name == name && (!nonempty || cookies[index].Value != "") {
			return cookies[index]
		}
	}
	t.Fatalf("cookie %s not found", name)
	return nil
}
