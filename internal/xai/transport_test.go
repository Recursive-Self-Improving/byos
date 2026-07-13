package xai

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type closeSpy struct {
	reader *io.PipeReader
	closed chan struct{}
}

func (s *closeSpy) Read(p []byte) (int, error) { return s.reader.Read(p) }
func (s *closeSpy) Close() error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	return s.reader.Close()
}

func TestSSECancellationClosesBody(t *testing.T) {
	reader, writer := io.Pipe()
	spy := &closeSpy{reader: reader, closed: make(chan struct{})}
	parser := NewSSEParser(spy, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := parser.Next(ctx); done <- err }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatalf("error=%v", err)
	}
	select {
	case <-spy.closed:
	case <-time.After(time.Second):
		t.Fatal("body was not closed")
	}
	_ = writer.Close()
}

func TestTransportProxyBypassAndCredentialLogSafety(t *testing.T) {
	proxyHits := make(chan string, 2)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits <- r.URL.Host
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"type\":\"response.completed\"}\n\n")
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "bypass.invalid")
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	client := NewClient(HTTPConfig{BaseURL: "http://proxied.invalid", RequestTimeout: time.Second, SSEIdleTimeout: time.Second})
	if _, err := client.Execute(context.Background(), "distinctive-bearer-secret", "grok-4.5", []byte(`{"tools":[{"type":"x_search"}]}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case host := <-proxyHits:
		if host != "proxied.invalid" {
			t.Fatalf("proxy host=%q", host)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy was not used")
	}
	bypass := NewClient(HTTPConfig{BaseURL: "http://bypass.invalid", RequestTimeout: 50 * time.Millisecond, SSEIdleTimeout: time.Second})
	_, _ = bypass.Execute(context.Background(), "distinctive-bearer-secret", "grok-4.5", []byte(`{"tools":[{"type":"x_search"}]}`))
	select {
	case host := <-proxyHits:
		t.Fatalf("NO_PROXY request used proxy for %q", host)
	default:
	}
	if strings.Contains(logs.String(), "distinctive-bearer-secret") {
		t.Fatal("credential appeared in logs")
	}
}

func TestExecutorLargeEventAndUpstreamError(t *testing.T) {
	t.Run("large event", func(t *testing.T) {
		large := strings.Repeat("x", 70<<10)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprintf(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":%q}\n\n", large)
			fmt.Fprint(w, "data: {\"type\":\"response.completed\"}\n\n")
		}))
		defer server.Close()
		client := NewClient(HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second, SSEIdleTimeout: time.Second})
		events, err := client.Execute(context.Background(), "token", "grok-4.5", []byte(`{"tools":[{"type":"x_search"}]}`))
		if err != nil || len(events) != 2 || len(events[0].Data) < 70<<10 {
			t.Fatalf("events=%d first=%d err=%v", len(events), len(events[0].Data), err)
		}
	})
	t.Run("upstream error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "120")
			http.Error(w, "private-upstream-detail", http.StatusTooManyRequests)
		}))
		defer server.Close()
		client := NewClient(HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second})
		_, err := client.Execute(context.Background(), "token", "grok-4.5", []byte(`{"tools":[{"type":"x_search"}]}`))
		var upstream *UpstreamError
		if !errors.As(err, &upstream) || upstream.Status != http.StatusTooManyRequests || upstream.Headers.Get("Retry-After") != "120" || !strings.Contains(upstream.Body, "private-upstream-detail") {
			t.Fatalf("error=%#v", err)
		}
		if strings.Contains(err.Error(), "private-upstream-detail") {
			t.Fatal("public error string leaked upstream body")
		}
	})
}

func TestStreamFirstEventTypeValidation(t *testing.T) {
	tests := []struct {
		name, payload string
		valid         bool
	}{{"leading whitespace", `  {"type":"response.created"}`, true}, {"numeric type", `{"type":1}`, false}, {"boolean type", `{"type":true}`, false}, {"object type", `{"type":{}}`, false}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintf(w, "data: %s\n\n", test.payload) }))
			defer server.Close()
			client := NewClient(HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second, SSEIdleTimeout: time.Second})
			stream, err := client.Stream(context.Background(), "token", "grok-4.5", []byte(`{"tools":[{"type":"x_search"}]}`))
			if test.valid {
				if err != nil {
					t.Fatal(err)
				}
				_ = stream.Close()
			} else if err == nil {
				_ = stream.Close()
				t.Fatal("invalid type accepted")
			}
		})
	}
}
