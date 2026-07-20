package usage

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

func TestClientRejectsProviderMismatchBeforeBillingRequest(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()

	client := NewClient(xai.NewClient(xai.HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second}))
	_, err := client.Fetch(context.Background(), provider.Devin, provider.Credential{Value: "devin-credential-sentinel"})
	if !errors.Is(err, provider.ErrProviderMismatch) {
		t.Fatalf("error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("billing calls = %d", calls.Load())
	}
	if err != nil && contains(err.Error(), "devin-credential-sentinel") {
		t.Fatalf("credential leaked in error: %v", err)
	}
}

func TestClientPreservesBillingProjectionAndHeaders(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("X-XAI-Token-Auth") != "xai-grok-cli" || r.Header.Get("Accept") != "application/json" {
			t.Errorf("headers = %v", r.Header)
		}
		if r.URL.RawQuery == "format=credits" {
			_, _ = w.Write([]byte(weeklyFixture))
			return
		}
		_, _ = w.Write([]byte(monthlyFixture))
	}))
	defer server.Close()

	result, err := NewClient(xai.NewClient(xai.HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second})).Fetch(context.Background(), provider.XAI, provider.Credential{Value: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || result.Monthly == nil || result.Monthly.Remaining != 750 || result.Weekly == nil || result.Weekly.RemainingPercent != 75 {
		t.Fatalf("calls=%d result=%+v", calls.Load(), result)
	}
}

func contains(value, fragment string) bool {
	for i := 0; i+len(fragment) <= len(value); i++ {
		if value[i:i+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
