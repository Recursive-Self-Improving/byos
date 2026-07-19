package api

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"byos/internal/accounts"
	"byos/internal/auththrottle"
	"byos/internal/store"
)

func statusHandler(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
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

func TestServerRouteInventoryAndAuthScopes(t *testing.T) {
	database, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys := accounts.NewAPIKeyService(store.NewAPIKeyRepository(database.DB))
	created, err := keys.Create(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}
	handlers := ServerHandlers{Health: statusHandler(200), Ready: statusHandler(200), Models: statusHandler(204), Chat: statusHandler(204), Responses: statusHandler(204), Messages: statusHandler(204), CountTokens: statusHandler(204), Admin: statusHandler(204), Web: statusHandler(200)}
	server := NewServer(ServerConfig{Handlers: handlers, ClientKeys: keys, AdminAPIKey: "admin", AdminAttempts: directAdminAttempts{}, AdminSources: fixedAdminSource{}})
	tests := []struct {
		method, path, auth string
		want               int
	}{{"GET", "/healthz", "", 200}, {"GET", "/readyz", "", 200}, {"GET", "/v1/models", "", 401}, {"GET", "/v1/models", "Bearer " + created.Plaintext, 204}, {"POST", "/v1/chat/completions", "Bearer " + created.Plaintext, 204}, {"POST", "/v1/responses", "Bearer " + created.Plaintext, 204}, {"POST", "/v1/messages", "Bearer " + created.Plaintext, 204}, {"POST", "/v1/messages/count_tokens", "Bearer " + created.Plaintext, 204}, {"GET", "/admin/api/v1/accounts", "Bearer " + created.Plaintext, 401}, {"GET", "/admin/api/v1/accounts", "Bearer admin", 204}, {"GET", "/admin/", "", 200}, {"POST", "/v1/completions", "Bearer " + created.Plaintext, 404}, {"POST", "/v1/responses/compact", "Bearer " + created.Plaintext, 404}, {"GET", "/v1/responses/r1", "Bearer " + created.Plaintext, 404}, {"DELETE", "/v1/responses/r1", "Bearer " + created.Plaintext, 404}, {"POST", "/v1/images/generations", "Bearer " + created.Plaintext, 404}, {"GET", "/tenant/accounts", "", 404}, {"GET", "/v1/models", "Bearer " + created.Plaintext, 204}, {"POST", "/v1/models", "Bearer " + created.Plaintext, 405}}
	for _, test := range tests {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			request.Header.Set("Authorization", test.auth)
			response := httptest.NewRecorder()
			server.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if response.Header().Get("X-Content-Type-Options") != "nosniff" || response.Header().Get("X-Request-Id") == "" {
				t.Fatal("security/request headers missing")
			}
		})
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	request.Header.Set("x-api-key", created.Plaintext)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("Anthropic x-api-key status=%d", response.Code)
	}
}

func TestServerConfiguredBodyLimit(t *testing.T) {
	database, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys := accounts.NewAPIKeyService(store.NewAPIKeyRepository(database.DB))
	created, err := keys.Create(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}
	reader := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handlers := ServerHandlers{Health: statusHandler(200), Ready: statusHandler(200), Models: statusHandler(200), Chat: reader, Responses: reader, Messages: reader, CountTokens: reader}
	for _, test := range []struct {
		name  string
		limit int64
		body  string
		want  int
	}{{"exact", 8, "12345678", 204}, {"over", 8, "123456789", 413}, {"above old hard cap", DefaultMaxBody + 100, `{"value":"` + strings.Repeat("a", DefaultMaxBody) + `"}`, 204}} {
		t.Run(test.name, func(t *testing.T) {
			server := NewServer(ServerConfig{Handlers: handlers, ClientKeys: keys, MaxBodyBytes: test.limit})
			request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer "+created.Plaintext)
			response := httptest.NewRecorder()
			server.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d", response.Code)
			}
		})
	}
}

func TestRecoveryDoesNotLeakPanicValue(t *testing.T) {
	const secret = "panic-token-secret"
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	handlers := ServerHandlers{Health: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(secret) }), Ready: statusHandler(200)}
	server := NewServer(ServerConfig{Handlers: handlers, Logger: logger})
	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), secret) || strings.Contains(logs.String(), secret) {
		t.Fatalf("response=%s logs=%s", response.Body.String(), logs.String())
	}
}
