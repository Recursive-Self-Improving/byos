package xai

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type jwksFixture struct {
	mu   sync.RWMutex
	keys []jose.JSONWebKey
}

func (f *jwksFixture) handler(w http.ResponseWriter, _ *http.Request) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: f.keys})
}
func signIdentityToken(t *testing.T, key *rsa.PrivateKey, kid, issuer, audience, subject string, expiry time.Time) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}}, nil)
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
func TestIdentityVerifierAndKeyRotation(t *testing.T) {
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)
	fixture := &jwksFixture{keys: []jose.JSONWebKey{{Key: &key1.PublicKey, KeyID: "one", Algorithm: string(jose.RS256), Use: "sig"}}}
	server := httptest.NewServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	verifier := NewIdentityVerifier(context.Background(), Issuer, server.URL, DefaultClientID)
	token := signIdentityToken(t, key1, "one", Issuer, DefaultClientID, "subject", time.Now().Add(time.Hour))
	identity, err := verifier.Verify(context.Background(), token)
	if err != nil || identity.Subject != "subject" || identity.Email != "user@example.com" {
		t.Fatalf("identity=%+v err=%v", identity, err)
	}
	fixture.mu.Lock()
	fixture.keys = []jose.JSONWebKey{{Key: &key2.PublicKey, KeyID: "two", Algorithm: string(jose.RS256), Use: "sig"}}
	fixture.mu.Unlock()
	rotated := signIdentityToken(t, key2, "two", Issuer, DefaultClientID, "subject", time.Now().Add(time.Hour))
	if _, err := verifier.Verify(context.Background(), rotated); err != nil {
		t.Fatalf("rotated key rejected: %v", err)
	}
}
func TestIdentityVerifierRejectsInvalidClaims(t *testing.T) {
	trusted, _ := rsa.GenerateKey(rand.Reader, 2048)
	forged, _ := rsa.GenerateKey(rand.Reader, 2048)
	fixture := &jwksFixture{keys: []jose.JSONWebKey{{Key: &trusted.PublicKey, KeyID: "trusted", Algorithm: string(jose.RS256), Use: "sig"}}}
	server := httptest.NewServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	verifier := NewIdentityVerifier(context.Background(), Issuer, server.URL, DefaultClientID)
	tests := []struct{ name, token string }{{"forged", signIdentityToken(t, forged, "forged", Issuer, DefaultClientID, "subject", time.Now().Add(time.Hour))}, {"wrong issuer", signIdentityToken(t, trusted, "trusted", "https://other.x.ai", DefaultClientID, "subject", time.Now().Add(time.Hour))}, {"wrong audience", signIdentityToken(t, trusted, "trusted", Issuer, "other-client", "subject", time.Now().Add(time.Hour))}, {"expired", signIdentityToken(t, trusted, "trusted", Issuer, DefaultClientID, "subject", time.Now().Add(-time.Hour))}, {"missing subject", signIdentityToken(t, trusted, "trusted", Issuer, DefaultClientID, "", time.Now().Add(time.Hour))}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := verifier.Verify(context.Background(), test.token); err == nil {
				t.Fatal("invalid token accepted")
			}
		})
	}
}
