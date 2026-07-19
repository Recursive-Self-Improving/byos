package usage

import (
	"bytes"
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

func TestXAIProviderUsageSnapshotPreservesRawAndObservationTime(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/billing" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if r.URL.RawQuery == "format=credits" {
			_, _ = w.Write([]byte(weeklyFixture))
			return
		}
		_, _ = w.Write([]byte(monthlyFixture))
	}))
	defer server.Close()

	observed := time.Date(2026, 7, 19, 12, 30, 0, 0, time.FixedZone("offset", 3600))
	adapter := NewXAIProvider(NewClient(xai.NewClient(xai.HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second})))
	adapter.now = func() time.Time { return observed }
	snapshot, err := adapter.FetchUsage(context.Background(), provider.Credential{Value: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.FetchedAt.Equal(observed) || snapshot.FetchedAt.Location() != time.UTC {
		t.Fatalf("fetched_at = %v", snapshot.FetchedAt)
	}
	if !bytes.Contains(snapshot.Raw, []byte(`"monthly"`)) || !bytes.Contains(snapshot.Raw, []byte(monthlyFixture)) || !bytes.Contains(snapshot.Raw, []byte(`"credits"`)) || !bytes.Contains(snapshot.Raw, []byte(weeklyFixture)) {
		t.Fatalf("raw snapshot = %s", snapshot.Raw)
	}
}

func TestXAIProviderPreservesPartialBillingAndServiceProjection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/billing" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if r.URL.RawQuery == "format=credits" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(monthlyFixture))
	}))
	defer server.Close()

	adapter := NewXAIProvider(NewClient(xai.NewClient(xai.HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second})))
	result, err := adapter.FetchUsage(context.Background(), provider.Credential{Value: "secret"})
	if err != nil || result.Monthly == nil || result.Monthly.Remaining != 750 || result.Weekly != nil {
		t.Fatalf("result=%+v error=%v", result, err)
	}
}

func TestXAIProviderSanitizesErrorsAndPreservesStatusMetadata(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/billing" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		calls.Add(1)
		w.Header().Set("Retry-After", "11")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("private-billing-body-sentinel"))
	}))
	defer server.Close()

	adapter := NewXAIProvider(NewClient(xai.NewClient(xai.HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second})))
	_, err := adapter.FetchUsage(context.Background(), provider.Credential{Value: "credential-sentinel"})
	var status *HTTPError
	if !errors.As(err, &status) || status.Status != http.StatusTooManyRequests || status.RetryAfter != "11" {
		t.Fatalf("error = %#v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d", calls.Load())
	}
	if strings.Contains(err.Error(), "private-billing-body-sentinel") || strings.Contains(err.Error(), "credential-sentinel") {
		t.Fatalf("secret leaked in error: %v", err)
	}
}

func TestXAIProviderSanitizesTransportDetails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	client := xai.NewClient(xai.HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second})
	server.Close()

	_, err := NewXAIProvider(NewClient(client)).FetchUsage(context.Background(), provider.Credential{Value: "transport-secret"})
	if err == nil || err.Error() != "xAI usage refresh failed" || strings.Contains(err.Error(), "transport-secret") || strings.Contains(err.Error(), server.URL) {
		t.Fatalf("error = %v", err)
	}
}
