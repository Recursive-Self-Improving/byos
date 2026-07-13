package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"supergrok-api/internal/accounts"
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

func TestAdminAuthIsSeparate(t *testing.T) {
	handler := AdminAuth("admin-secret")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
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
