package models

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"byos/internal/provider"
	"byos/internal/xai"
)

func TestXAIProviderMapsDiscoveryMetadataAndTriStateSearch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/models-v2" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`[
			{"id":"grok-true","displayName":"Grok True","contextWindow":131072,"maxCompletionTokens":8192,"reasoningEfforts":["low","high"],"supportsBackendSearch":true},
			{"model":"grok-false","supports_backend_search":false},
			{"id":"grok-unknown"}
		]`))
	}))
	defer server.Close()

	discoverer := NewXAIProvider(NewClient(xai.NewClient(xai.HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second})))
	models, err := discoverer.Discover(context.Background(), provider.Credential{Value: "token"})
	if err != nil || len(models) != 3 {
		t.Fatalf("models = %+v, error = %v", models, err)
	}
	if models[0].UpstreamName != "grok-true" || models[0].DisplayName != "Grok True" || models[0].ContextWindow != 131072 || models[0].MaxOutputTokens != 8192 || len(models[0].ReasoningEfforts) != 2 {
		t.Fatalf("first model = %+v", models[0])
	}
	if models[0].SupportsBackendSearch == nil || !*models[0].SupportsBackendSearch {
		t.Fatalf("true search state = %v", models[0].SupportsBackendSearch)
	}
	if models[1].SupportsBackendSearch == nil || *models[1].SupportsBackendSearch {
		t.Fatalf("false search state = %v", models[1].SupportsBackendSearch)
	}
	if models[2].SupportsBackendSearch != nil {
		t.Fatalf("unknown search state = %v", models[2].SupportsBackendSearch)
	}
}

func TestXAIProviderFallbackAndCredentialEndpointCounters(t *testing.T) {
	for _, test := range []struct {
		name       string
		status     int
		body       string
		wantLegacy int32
		wantErr    error
	}{
		{name: "not found falls back", status: http.StatusNotFound, wantLegacy: 1},
		{name: "schema falls back", status: http.StatusOK, body: `{"items":[]}`, wantLegacy: 1},
		{name: "unauthorized does not fall back", status: http.StatusUnauthorized, wantErr: ErrCredential},
		{name: "forbidden does not fall back", status: http.StatusForbidden, wantErr: ErrCredential},
	} {
		t.Run(test.name, func(t *testing.T) {
			var v2Calls, legacyCalls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/models-v2":
					v2Calls.Add(1)
					w.WriteHeader(test.status)
					_, _ = w.Write([]byte(test.body))
				case "/models":
					legacyCalls.Add(1)
					_, _ = w.Write([]byte(`[{"id":"legacy"}]`))
				default:
					t.Errorf("path = %q", r.URL.Path)
				}
			}))
			defer server.Close()

			discoverer := NewXAIProvider(NewClient(xai.NewClient(xai.HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second})))
			models, err := discoverer.Discover(context.Background(), provider.Credential{Value: "token"})
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("error = %v", err)
				}
			} else if err != nil || len(models) != 1 || models[0].UpstreamName != "legacy" {
				t.Fatalf("models = %+v, error = %v", models, err)
			}
			if v2Calls.Load() != 1 || legacyCalls.Load() != test.wantLegacy {
				t.Fatalf("calls: v2=%d legacy=%d", v2Calls.Load(), legacyCalls.Load())
			}
		})
	}
}

func TestXAIProviderSanitizesTransportErrors(t *testing.T) {
	const secret = "credential-sentinel"
	discoverer := NewXAIProvider(NewClient(xai.NewClient(xai.HTTPConfig{BaseURL: "http://127.0.0.1:1/" + secret, RequestTimeout: 50 * time.Millisecond})))
	_, err := discoverer.Discover(context.Background(), provider.Credential{Value: secret})
	if err == nil || strings.Contains(err.Error(), secret) || err.Error() != "xAI model discovery failed" {
		t.Fatalf("error = %v", err)
	}
}
