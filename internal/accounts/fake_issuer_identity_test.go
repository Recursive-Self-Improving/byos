package accounts

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	appcrypto "supergrok-api/internal/crypto"
	oauthxai "supergrok-api/internal/oauth/xai"
	"supergrok-api/internal/store"
)

type issuerRewriteTransport struct{ target *url.URL }

func (t issuerRewriteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	value := *request.URL
	value.Scheme = t.target.Scheme
	value.Host = t.target.Host
	clone.URL = &value
	return http.DefaultTransport.RoundTrip(clone)
}
func TestCompleteLoginRejectsUnverifiedIdentityBeforePersistence(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "key", Algorithm: string(jose.RS256), Use: "sig"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(map[string]any{"iss": oauthxai.Issuer, "aud": "wrong-audience", "sub": "subject", "exp": time.Now().Add(time.Hour).Unix()}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": oauthxai.Issuer, "authorization_endpoint": oauthxai.Issuer + "/authorize", "device_authorization_endpoint": oauthxai.Issuer + "/device", "token_endpoint": oauthxai.Issuer + "/token", "jwks_uri": oauthxai.Issuer + "/jwks"})
		case "/device":
			_ = json.NewEncoder(w).Encode(map[string]any{"device_code": "device-secret", "user_code": "CODE", "verification_uri": oauthxai.Issuer + "/verify", "expires_in": 600, "interval": 5})
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-secret", "refresh_token": "refresh-secret", "id_token": token, "expires_in": 3600})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "key", Algorithm: string(jose.RS256), Use: "sig"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	target, _ := url.Parse(server.URL)
	client := &http.Client{Transport: issuerRewriteTransport{target: target}, Timeout: time.Second}
	ctx := oidc.ClientContext(context.Background(), client)
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{23}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accountsRepo := store.NewAccountRepository(database.DB, keys)
	oauthRepo := store.NewOAuthSessionRepository(database.DB, keys)
	oauthService := oauthxai.NewService(oauthxai.NewDiscoveryClient(client, oauthxai.DiscoveryURL), client, oauthRepo, oauthxai.DefaultOptions())
	identity := oauthxai.NewIdentityVerifier(ctx, oauthxai.Issuer, oauthxai.Issuer+"/jwks", oauthxai.DefaultClientID)
	service := NewService(accountsRepo, oauthService, identity, oauthxai.NewRefreshService(client, accountsRepo, oauthxai.DefaultOptions()), nil, nil)
	flow, err := service.StartLogin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CompleteLogin(ctx, flow.State); err == nil {
		t.Fatal("wrong-audience identity persisted")
	}
	accounts, err := accountsRepo.List(ctx)
	if err != nil || len(accounts) != 0 {
		t.Fatalf("accounts=%+v err=%v", accounts, err)
	}
	session, err := oauthService.Session(ctx, flow.State)
	if err != nil || session.Status != "failed" || session.SanitizedError != "The identity token could not be verified." {
		t.Fatalf("session=%+v err=%v", session, err)
	}
	raw, _ := json.Marshal(session)
	for _, secret := range []string{"access-secret", "refresh-secret", "wrong-audience"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("session leaked %q", secret)
		}
	}
}
