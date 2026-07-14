package xai

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"

	appcrypto "supergrok-api/internal/crypto"
	"supergrok-api/internal/store"
)

type issuerTransport struct{ target *url.URL }

func (t issuerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	copyURL := *request.URL
	copyURL.Scheme = t.target.Scheme
	copyURL.Host = t.target.Host
	clone.URL = &copyURL
	return http.DefaultTransport.RoundTrip(clone)
}

type completeFakeIssuer struct {
	t               *testing.T
	server          *httptest.Server
	key             *ecdsa.PrivateKey
	kid             string
	jwks            *jwksFixture
	mu              sync.Mutex
	deviceResponses []string
	refreshResponse string
	malformed       bool
}

func newCompleteFakeIssuer(t *testing.T) *completeFakeIssuer {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &completeFakeIssuer{t: t, key: key, kid: "one"}
	issuer.jwks = &jwksFixture{keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: issuer.kid, Algorithm: string(jose.ES256), Use: "sig"}}}
	issuer.server = httptest.NewServer(http.HandlerFunc(issuer.handle))
	t.Cleanup(issuer.server.Close)
	return issuer
}
func (f *completeFakeIssuer) client() *http.Client {
	target, _ := url.Parse(f.server.URL)
	return &http.Client{Transport: issuerTransport{target: target}, Timeout: time.Second}
}
func (f *completeFakeIssuer) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		token := Issuer + "/token"
		if f.malformed {
			token = "https://evil.example/token"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": Issuer, "authorization_endpoint": Issuer + "/authorize", "device_authorization_endpoint": Issuer + "/device", "token_endpoint": token, "jwks_uri": Issuer + "/jwks", "id_token_signing_alg_values_supported": []string{oidc.ES256}})
	case "/device":
		_ = json.NewEncoder(w).Encode(map[string]any{"device_code": "device-secret", "user_code": "CODE-1234", "verification_uri": Issuer + "/device/verify", "expires_in": 600, "interval": 1})
	case "/jwks":
		f.jwks.handler(w, r)
	case "/token":
		_ = r.ParseForm()
		if r.Form.Get("grant_type") == "refresh_token" {
			payload := f.refreshResponse
			if payload == "" {
				payload = `{"access_token":"refreshed","expires_in":3600}`
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, payload)
			return
		}
		f.mu.Lock()
		payload := `{"error":"authorization_pending"}`
		if len(f.deviceResponses) > 0 {
			payload = f.deviceResponses[0]
			f.deviceResponses = f.deviceResponses[1:]
		}
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, payload)
	default:
		http.NotFound(w, r)
	}
}
func fakeOAuthRepositories(t *testing.T) (*store.SQLite, appcrypto.Keys, *store.AccountRepository, *store.OAuthSessionRepository) {
	database, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{21}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return database, keys, store.NewAccountRepository(database.DB, keys), store.NewOAuthSessionRepository(database.DB, keys)
}
func newIssuerOAuthService(t *testing.T, issuer *completeFakeIssuer, sessions *store.OAuthSessionRepository) *Service {
	discovery := NewDiscoveryClient(issuer.client(), DiscoveryURL)
	service := NewService(discovery, issuer.client(), sessions, DefaultOptions())
	service.wait = func(context.Context, time.Duration) error { return nil }
	return service
}
func TestCompleteFakeIssuerEndToEnd(t *testing.T) {
	t.Run("discovery device identity rotation refresh and account", func(t *testing.T) {
		issuer := newCompleteFakeIssuer(t)
		database, _, accounts, sessions := fakeOAuthRepositories(t)
		defer database.Close()
		idToken := signIdentityTokenWithAlgorithm(t, issuer.key, jose.ES256, issuer.kid, Issuer, DefaultClientID, "subject", time.Now().Add(time.Hour))
		issuer.deviceResponses = []string{`{"error":"slow_down"}`, `{"access_token":"access","refresh_token":"refresh","id_token":` + string(mustJSON(t, idToken)) + `,"expires_in":3600}`}
		service := newIssuerOAuthService(t, issuer, sessions)
		document, err := service.discovery.Discover(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		flow, err := service.StartDevice(context.Background())
		if err != nil || flow.VerificationURI == "" {
			t.Fatalf("flow=%+v err=%v", flow, err)
		}
		token, err := service.Poll(context.Background(), flow.State)
		if err != nil {
			t.Fatal(err)
		}
		verifyCtx := oidc.ClientContext(context.Background(), issuer.client())
		verifier := NewIdentityVerifier(verifyCtx, document.Issuer, document.JWKSURI, DefaultClientID, document.IDTokenSigningAlgs)
		identity, err := verifier.Verify(verifyCtx, token.IDToken)
		if err != nil {
			t.Fatal(err)
		}
		expires := token.ExpiresAt
		account, err := accounts.UpsertLogin(context.Background(), store.Account{Status: "ready", ExpiresAt: &expires, Credentials: store.AccountCredentials{Issuer: identity.Issuer, Subject: identity.Subject, Email: identity.Email, AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, IDToken: token.IDToken, TokenEndpoint: token.TokenEndpoint}})
		if err != nil {
			t.Fatal(err)
		}
		rotatedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		issuer.jwks.mu.Lock()
		issuer.jwks.keys = []jose.JSONWebKey{{Key: &rotatedKey.PublicKey, KeyID: "two", Algorithm: string(jose.ES256), Use: "sig"}}
		issuer.jwks.mu.Unlock()
		rotated := signIdentityTokenWithAlgorithm(t, rotatedKey, jose.ES256, "two", Issuer, DefaultClientID, "subject", time.Now().Add(time.Hour))
		if _, err := verifier.Verify(verifyCtx, rotated); err != nil {
			t.Fatalf("rotated JWKS rejected: %v", err)
		}
		issuer.refreshResponse = `{"access_token":"new-access","expires_in":3600}`
		refreshed, err := NewRefreshService(issuer.client(), accounts, DefaultOptions()).Refresh(context.Background(), account.ID)
		if err != nil || refreshed.Credentials.AccessToken != "new-access" || refreshed.Credentials.RefreshToken != "refresh" {
			t.Fatalf("refresh=%+v err=%v", refreshed, err)
		}
	})
	for _, terminal := range []struct{ name, payload, code, status string }{{"denial", `{"error":"access_denied","error_description":"denied"}`, "access_denied", "failed"}, {"expiry", `{"error":"expired_token"}`, "expired_token", "expired"}} {
		t.Run(terminal.name, func(t *testing.T) {
			issuer := newCompleteFakeIssuer(t)
			issuer.deviceResponses = []string{terminal.payload}
			database, _, _, sessions := fakeOAuthRepositories(t)
			defer database.Close()
			service := newIssuerOAuthService(t, issuer, sessions)
			flow, err := service.StartDevice(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.Poll(context.Background(), flow.State)
			var oauthErr *OAuthError
			if !errors.As(err, &oauthErr) || oauthErr.Code != terminal.code {
				t.Fatalf("error=%v", err)
			}
			stored, err := sessions.Get(context.Background(), flow.State)
			if err != nil || stored.Status != terminal.status {
				t.Fatalf("session=%+v err=%v", stored, err)
			}
		})
	}
	t.Run("malformed discovery endpoint", func(t *testing.T) {
		issuer := newCompleteFakeIssuer(t)
		issuer.malformed = true
		database, _, _, sessions := fakeOAuthRepositories(t)
		defer database.Close()
		if _, err := newIssuerOAuthService(t, issuer, sessions).StartDevice(context.Background()); err == nil {
			t.Fatal("foreign endpoint accepted")
		}
	})
	t.Run("invalid grant projects relogin", func(t *testing.T) {
		issuer := newCompleteFakeIssuer(t)
		issuer.refreshResponse = `{"error":"invalid_grant","error_description":"expired"}`
		database, _, accounts, _ := fakeOAuthRepositories(t)
		defer database.Close()
		expires := time.Now().Add(-time.Hour)
		account, err := accounts.UpsertLogin(context.Background(), store.Account{ExpiresAt: &expires, Credentials: store.AccountCredentials{Issuer: Issuer, Subject: "invalid", AccessToken: "old", RefreshToken: "refresh", TokenEndpoint: Issuer + "/token"}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = NewRefreshService(issuer.client(), accounts, DefaultOptions()).Refresh(context.Background(), account.ID)
		var oauthErr *OAuthError
		if !errors.As(err, &oauthErr) || oauthErr.Code != "invalid_grant" {
			t.Fatalf("error=%v", err)
		}
		updated, err := accounts.Get(context.Background(), account.ID)
		if err != nil || updated.Enabled || updated.Status != "relogin_required" {
			t.Fatalf("updated=%+v err=%v", updated, err)
		}
	})
}
func mustJSON(t *testing.T, value string) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
