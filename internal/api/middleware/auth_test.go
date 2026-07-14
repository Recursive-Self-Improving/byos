package middleware

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"supergrok-api/internal/accounts"
	"supergrok-api/internal/auththrottle"
	appcrypto "supergrok-api/internal/crypto"
	"supergrok-api/internal/store"
)

func TestClientAuth(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	service := accounts.NewAPIKeyService(store.NewAPIKeyRepository(database.DB))
	created, err := service.Create(ctx, "agent")
	if err != nil {
		t.Fatal(err)
	}
	handler := ClientAuth(service)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, label, ok := ClientIdentity(r.Context())
		if !ok || id != created.Key.ID || label != "agent" {
			t.Fatalf("identity = %q %q %v", id, label, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, test := range []struct {
		name, header string
		status       int
	}{{"missing", "", 401}, {"malformed", "Basic x", 401}, {"unknown", "Bearer sgk_unknown", 401}, {"valid", "Bearer " + created.Plaintext, 204}} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
			request.Header.Set("Authorization", test.header)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
		})
	}
	if err := service.Revoke(ctx, created.Key.ID); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	request.Header.Set("Authorization", "Bearer "+created.Plaintext)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 401 {
		t.Fatalf("revoked status = %d", response.Code)
	}
}

func TestAnthropicUnauthorizedShape(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	handler := ClientAuth(accounts.NewAPIKeyService(store.NewAPIKeyRepository(database.DB)))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	request := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["type"] != "error" {
		t.Fatalf("body = %v", body)
	}
}

type directAdminAttempts struct{}

func (directAdminAttempts) Evaluate(_ context.Context, _ netip.Addr, _ auththrottle.Surface, verify func() bool) (auththrottle.Outcome, error) {
	if verify() {
		return auththrottle.Outcome{Disposition: auththrottle.Authenticated}, nil
	}
	return auththrottle.Outcome{Disposition: auththrottle.Rejected}, nil
}

type fixedAdminSource struct{}

func (fixedAdminSource) ClientIP(*http.Request) (netip.Addr, error) {
	return netip.MustParseAddr("192.0.2.10"), nil
}

func TestAdminAuthIsSeparate(t *testing.T) {
	handler := AdminAuth("admin-secret", directAdminAttempts{}, fixedAdminSource{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for _, header := range []string{"Bearer sgk_client", "Bearer wrong", ""} {
		request := httptest.NewRequest(http.MethodGet, "/admin/api/v1/accounts", nil)
		request.Header.Set("Authorization", header)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != 401 {
			t.Fatalf("header %q status=%d", header, response.Code)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/admin/api/v1/accounts", nil)
	request.Header.Set("Authorization", "Bearer admin-secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 204 {
		t.Fatalf("admin status=%d", response.Code)
	}
}

func TestAdminAuthThrottleReturns429WithoutEvaluatingValidToken(t *testing.T) {
	database, err := store.Open(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	guard, err := auththrottle.NewGuard(store.NewAdminAuthThrottleRepository(database.DB), keys.AdminAuthSourceFingerprint, auththrottle.DefaultPolicy(), slog.New(slog.NewTextHandler(io.Discard, nil)), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	handler := AdminAuth("admin-secret", guard, fixedAdminSource{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for failure := range 3 {
		request := httptest.NewRequest(http.MethodGet, "/admin/api/v1/accounts", nil)
		request.Header.Set("Authorization", "Bearer wrong")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d status=%d body=%s", failure+1, response.Code, response.Body.String())
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/admin/api/v1/accounts", nil)
	request.Header.Set("Authorization", "Bearer admin-secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "5" || response.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("blocked status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	clock = clock.Add(5 * time.Second)
	request = httptest.NewRequest(http.MethodGet, "/admin/api/v1/accounts", nil)
	request.Header.Set("Authorization", "Bearer admin-secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("post-throttle status=%d body=%s", response.Code, response.Body.String())
	}
}
