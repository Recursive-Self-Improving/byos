package models

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"byos/internal/provider"
	"byos/internal/xai"
)

func TestClientRejectsProviderMismatchBeforeEndpoint(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()

	client := NewClient(xai.NewClient(xai.HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second}))
	_, err := client.Discover(context.Background(), provider.Devin, provider.Credential{Value: "devin-credential-sentinel"})
	if !errors.Is(err, provider.ErrProviderMismatch) {
		t.Fatalf("error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("endpoint calls = %d", calls.Load())
	}
}

func TestClientUsesExistingDiscoveryFallback(t *testing.T) {
	var v2Calls, legacyCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Errorf("Authorization = %q", got)
		}
		switch r.URL.Path {
		case "/models-v2":
			v2Calls.Add(1)
			w.WriteHeader(http.StatusNotFound)
		case "/models":
			legacyCalls.Add(1)
			_, _ = w.Write([]byte(`[{"id":"legacy"}]`))
		default:
			t.Errorf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewClient(xai.NewClient(xai.HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second}))
	models, err := client.Discover(context.Background(), provider.XAI, provider.Credential{Value: "token"})
	if err != nil || len(models) != 1 || models[0].ID != "legacy" {
		t.Fatalf("models = %+v, error = %v", models, err)
	}
	if v2Calls.Load() != 1 || legacyCalls.Load() != 1 {
		t.Fatalf("calls: v2=%d legacy=%d", v2Calls.Load(), legacyCalls.Load())
	}
}
