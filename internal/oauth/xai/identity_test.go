package xai

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type jwksFixture struct {
	mu           sync.RWMutex
	keys         []jose.JSONWebKey
	requestCount int
}

func (f *jwksFixture) handler(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	f.requestCount++
	keys := f.keys
	f.mu.Unlock()
	_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: keys})
}

func (f *jwksFixture) requests() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.requestCount
}
func signIdentityTokenWithAlgorithm(t *testing.T, key any, algorithm jose.SignatureAlgorithm, kid, issuer, audience, subject string, expiry time.Time) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: string(algorithm), Use: "sig"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"iss": issuer, "aud": audience, "sub": subject, "exp": expiry.Unix(), "iat": time.Now().Add(-time.Minute).Unix(), "email": "user@example.com"}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func signIdentityToken(t *testing.T, key *rsa.PrivateKey, kid, issuer, audience, subject string, expiry time.Time) string {
	return signIdentityTokenWithAlgorithm(t, key, jose.RS256, kid, issuer, audience, subject, expiry)
}
func TestIdentityVerifierAcceptsDiscoveredES256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &jwksFixture{keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "xai-es256", Algorithm: string(jose.ES256), Use: "sig"}}}
	server := httptest.NewServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	verifier := NewIdentityVerifier(context.Background(), Issuer, server.URL, DefaultClientID, []string{string(jose.ES256)})
	token := signIdentityTokenWithAlgorithm(t, key, jose.ES256, "xai-es256", Issuer, DefaultClientID, "subject", time.Now().Add(time.Hour))
	identity, err := verifier.Verify(context.Background(), token)
	if err != nil || identity.Subject != "subject" || identity.Email != "user@example.com" {
		t.Fatalf("identity=%+v err=%v", identity, err)
	}
}

func TestIdentityVerifierAndKeyRotation(t *testing.T) {
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)
	fixture := &jwksFixture{keys: []jose.JSONWebKey{{Key: &key1.PublicKey, KeyID: "one", Algorithm: string(jose.RS256), Use: "sig"}}}
	server := httptest.NewServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	verifier := NewIdentityVerifier(context.Background(), Issuer, server.URL, DefaultClientID, []string{string(jose.RS256)})
	token := signIdentityToken(t, key1, "one", Issuer, DefaultClientID, "subject", time.Now().Add(time.Hour))
	identity, err := verifier.Verify(context.Background(), token)
	if err != nil || identity.Subject != "subject" || identity.Email != "user@example.com" {
		t.Fatalf("identity=%+v err=%v", identity, err)
	}
	fixture.mu.Lock()
	fixture.keys = []jose.JSONWebKey{{Key: &key2.PublicKey, KeyID: "two", Algorithm: string(jose.RS256), Use: "sig"}}
	fixture.mu.Unlock()
	rotated := signIdentityToken(t, key2, "two", Issuer, DefaultClientID, "subject", time.Now().Add(time.Hour))
	// go-oidc's RemoteKeySet updates its JWKS cache asynchronously: the first
	// Verify returns as soon as the fetch completes (inflight.done), but a
	// background goroutine still needs to nil the inflight marker afterwards.
	// A second Verify that races ahead of that goroutine reuses the stale
	// inflight — which holds the pre-rotation keys — and rejects the rotated
	// token. In production key rotation never occurs between consecutive
	// verifications nanoseconds apart, so this is a test-synchronization issue.
	// Retry with runtime.Gosched until the keyset performs a fresh post-rotation
	// fetch (observed via the fixture request counter), proving the rotated
	// keys were retrieved and the token accepted on their merits — not from a
	// stale cache.
	before := fixture.requests()
	var lastErr error
	for range 100 {
		if _, err := verifier.Verify(context.Background(), rotated); err == nil {
			lastErr = nil
			break
		}
		lastErr = err
		runtime.Gosched()
	}
	if lastErr != nil {
		t.Fatalf("rotated key rejected: %v", lastErr)
	}
	if fixture.requests() <= before {
		t.Fatal("rotated key accepted without fetching rotated JWKS")
	}
}
func TestIdentityVerifierRejectsInvalidClaims(t *testing.T) {
	trusted, _ := rsa.GenerateKey(rand.Reader, 2048)
	forged, _ := rsa.GenerateKey(rand.Reader, 2048)
	fixture := &jwksFixture{keys: []jose.JSONWebKey{{Key: &trusted.PublicKey, KeyID: "trusted", Algorithm: string(jose.RS256), Use: "sig"}}}
	server := httptest.NewServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	verifier := NewIdentityVerifier(context.Background(), Issuer, server.URL, DefaultClientID, []string{string(jose.RS256)})
	tests := []struct{ name, token string }{{"forged", signIdentityToken(t, forged, "forged", Issuer, DefaultClientID, "subject", time.Now().Add(time.Hour))}, {"wrong issuer", signIdentityToken(t, trusted, "trusted", "https://other.x.ai", DefaultClientID, "subject", time.Now().Add(time.Hour))}, {"wrong audience", signIdentityToken(t, trusted, "trusted", Issuer, "other-client", "subject", time.Now().Add(time.Hour))}, {"expired", signIdentityToken(t, trusted, "trusted", Issuer, DefaultClientID, "subject", time.Now().Add(-time.Hour))}, {"missing subject", signIdentityToken(t, trusted, "trusted", Issuer, DefaultClientID, "", time.Now().Add(time.Hour))}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := verifier.Verify(context.Background(), test.token); err == nil {
				t.Fatal("invalid token accepted")
			}
		})
	}
}
