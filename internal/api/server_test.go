package api_test

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
	"byos/internal/api"
	"byos/internal/api/openai"
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
	handlers := api.ServerHandlers{Health: statusHandler(200), Ready: statusHandler(200), Models: statusHandler(204), Chat: statusHandler(204), Responses: statusHandler(204), Messages: statusHandler(204), CountTokens: statusHandler(204), Admin: statusHandler(204), Web: statusHandler(200)}
	server := api.NewServer(api.ServerConfig{Handlers: handlers, ClientKeys: keys, AdminAPIKey: "admin", AdminAttempts: directAdminAttempts{}, AdminSources: fixedAdminSource{}})
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

func TestServerModelsPreserveExplicitOwnership(t *testing.T) {
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
	models := []openai.Model{
		{ID: "grok", OwnedBy: "byos"},
		{ID: "grok-4.5", OwnedBy: "xai"},
		{ID: "kimi-k2-7", OwnedBy: "devin"},
		{ID: "glm-5-2", OwnedBy: "devin"},
		{ID: "swe-1-6-slow", OwnedBy: "devin"},
	}
	handlers := api.ServerHandlers{
		Health:      statusHandler(http.StatusNotFound),
		Ready:       statusHandler(http.StatusNotFound),
		Models:      openai.ModelsHandler(serverModelCatalog{models: models}),
		Chat:        statusHandler(http.StatusNotFound),
		Responses:   statusHandler(http.StatusNotFound),
		Messages:    statusHandler(http.StatusNotFound),
		CountTokens: statusHandler(http.StatusNotFound),
	}
	server := api.NewServer(api.ServerConfig{Handlers: handlers, ClientKeys: keys})
	request := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	request.Header.Set("Authorization", "Bearer "+created.Plaintext)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	want := `{"data":[{"created":0,"id":"grok","object":"model","owned_by":"byos"},{"created":0,"id":"grok-4.5","object":"model","owned_by":"xai"},{"created":0,"id":"kimi-k2-7","object":"model","owned_by":"devin"},{"created":0,"id":"glm-5-2","object":"model","owned_by":"devin"},{"created":0,"id":"swe-1-6-slow","object":"model","owned_by":"devin"}],"object":"list"}`
	if strings.TrimSpace(response.Body.String()) != want {
		t.Fatalf("body=%s", response.Body.String())
	}
}

type serverModelCatalog struct {
	models []openai.Model
}

func (c serverModelCatalog) PublicModels(context.Context) ([]openai.Model, error) {
	return c.models, nil
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
	handlers := api.ServerHandlers{Health: statusHandler(200), Ready: statusHandler(200), Models: statusHandler(200), Chat: reader, Responses: reader, Messages: reader, CountTokens: reader}
	for _, test := range []struct {
		name  string
		limit int64
		body  string
		want  int
	}{{"exact", 8, "12345678", 204}, {"over", 8, "123456789", 413}, {"above old hard cap", api.DefaultMaxBody + 100, `{"value":"` + strings.Repeat("a", api.DefaultMaxBody) + `"}`, 204}} {
		t.Run(test.name, func(t *testing.T) {
			server := api.NewServer(api.ServerConfig{Handlers: handlers, ClientKeys: keys, MaxBodyBytes: test.limit})
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
	handlers := api.ServerHandlers{Health: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(secret) }), Ready: statusHandler(200)}
	server := api.NewServer(api.ServerConfig{Handlers: handlers, Logger: logger})
	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), secret) || strings.Contains(logs.String(), secret) {
		t.Fatalf("response=%s logs=%s", response.Body.String(), logs.String())
	}
}
