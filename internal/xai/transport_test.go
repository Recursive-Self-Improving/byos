package xai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"byos/internal/provider"
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
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	newClient := func(baseURL string, timeout time.Duration) *ProviderClient {
		transportClient := NewClient(HTTPConfig{BaseURL: baseURL, RequestTimeout: timeout, SSEIdleTimeout: time.Second})
		transportClient.http.Transport.(*http.Transport).Proxy = func(request *http.Request) (*url.URL, error) {
			if request.URL.Hostname() == "bypass.invalid" {
				return nil, nil
			}
			return proxyURL, nil
		}
		return NewProviderClient(transportClient)
	}
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	request := generationRequest(provider.CanonicalRequest{"tools": []any{map[string]any{"type": "x_search"}}})
	request.Credential.Value = "distinctive-bearer-secret"
	client := newClient("http://proxied.invalid", time.Second)
	if _, err := client.Execute(context.Background(), request); err != nil {
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
	bypass := newClient("http://bypass.invalid", 50*time.Millisecond)
	_, _ = bypass.Execute(context.Background(), request)
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
		client := NewProviderClient(NewClient(HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second, SSEIdleTimeout: time.Second}))
		events, err := client.Execute(context.Background(), generationRequest(provider.CanonicalRequest{"tools": []any{map[string]any{"type": "x_search"}}}))
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
		client := NewProviderClient(NewClient(HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second}))
		_, err := client.Execute(context.Background(), generationRequest(provider.CanonicalRequest{"tools": []any{map[string]any{"type": "x_search"}}}))
		var upstream *provider.UpstreamError
		if !errors.As(err, &upstream) || upstream.Status != http.StatusTooManyRequests || upstream.Classification.Class != provider.ClassRateLimit || !upstream.Classification.ExplicitRetryAfter || upstream.Classification.Cooldown != 2*time.Minute {
			t.Fatalf("error=%#v", err)
		}
		if strings.Contains(err.Error(), "private-upstream-detail") {
			t.Fatal("public error string leaked upstream body")
		}
	})
}

func TestProviderClientTransientStatusMatrixIsSanitized(t *testing.T) {
	for _, status := range []int{
		http.StatusRequestTimeout,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", "120")
				http.Error(w, `private-upstream-body token=secret`, status)
			}))
			defer server.Close()

			client := NewProviderClient(NewClient(HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second}))
			_, err := client.Execute(context.Background(), generationRequest(provider.CanonicalRequest{"tools": []any{map[string]any{"type": "x_search"}}}))
			var upstream *provider.UpstreamError
			if !errors.As(err, &upstream) {
				t.Fatalf("status=%d error=%#v", status, err)
			}
			got := upstream.Classification
			if upstream.Status != status || got.Class != provider.ClassTransient || !got.RetryNext {
				t.Fatalf("status=%d upstream=%+v", status, upstream)
			}
			if got.CooldownScope != provider.CooldownModel || got.Cooldown != time.Minute || got.ExplicitRetryAfter || !got.RetryAfter.IsZero() {
				t.Fatalf("status=%d cooldown classification=%+v", status, got)
			}
			if got.PublicStatus != http.StatusServiceUnavailable || got.PublicCode != "provider_unavailable" || got.PublicMessage != "upstream provider error" {
				t.Fatalf("status=%d public classification=%+v", status, got)
			}
			if strings.Contains(err.Error(), "private-upstream-body") || strings.Contains(err.Error(), "secret") {
				t.Fatalf("status=%d leaked upstream body: %v", status, err)
			}
		})
	}
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
			client := NewProviderClient(NewClient(HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second, SSEIdleTimeout: time.Second}))
			stream, err := client.Stream(context.Background(), generationRequest(provider.CanonicalRequest{"tools": []any{map[string]any{"type": "x_search"}}}))
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

func TestProviderStreamDeliversBufferedFirstEventOnce(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "data: {\"type\":\"response.created\",\"sequence_number\":0}\n\n")
		fmt.Fprint(w, "data: {\"type\":\"response.completed\",\"sequence_number\":1}\n\n")
	}))
	defer server.Close()
	client := NewProviderClient(NewClient(HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second, SSEIdleTimeout: time.Second}))
	stream, err := client.Stream(context.Background(), generationRequest(provider.CanonicalRequest{"tools": []any{map[string]any{"type": "x_search"}}}))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	first, err := stream.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := stream.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Data) != `{"type":"response.created","sequence_number":0}` || string(second.Data) != `{"type":"response.completed","sequence_number":1}` {
		t.Fatalf("events replayed or reordered: first=%s second=%s", first.Data, second.Data)
	}
}

func TestWirePreparationUsesInjectedEncoderOnceAndPreservesStructuredFidelity(t *testing.T) {
	functionTool := map[string]any{
		"type": "function", "name": "lookup",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"mode":  map[string]any{"type": "string", "enum": []any{"<fast>", "exact"}, "default": "<fast>"},
				"limit": map[string]any{"type": "integer", "default": json.Number("9007199254740993")},
			},
		},
	}
	searchTool := map[string]any{
		"type": "x_search", "allowed_x_handles": []any{"xai"},
		"from_date": "2026-01-02", "to_date": "2026-07-19",
	}
	canonical := map[string]any{
		"model": "grok-4.5", "input": "<tag>", "large": json.Number("9007199254740993"),
		"stream": false, "store": true, "tools": []any{functionTool, searchTool},
	}
	count := 0
	prepared, err := (&Client{}).prepare(canonical, func(destination io.Writer, value any) error {
		count++
		return encodeWireJSON(destination, value)
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("encoder invocations=%d want=1", count)
	}
	if strings.Contains(string(prepared), `\u003c`) {
		t.Fatalf("HTML escaped on wire: %s", prepared)
	}

	var wire map[string]any
	decoder := json.NewDecoder(bytes.NewReader(prepared))
	decoder.UseNumber()
	if err := decoder.Decode(&wire); err != nil {
		t.Fatal(err)
	}
	if wire["model"] != "grok-4.5" || wire["input"] != "<tag>" || wire["large"] != json.Number("9007199254740993") || wire["stream"] != true || wire["store"] != false {
		t.Fatalf("wire scalar fidelity=%#v", wire)
	}
	tools := wire["tools"].([]any)
	function := tools[0].(map[string]any)
	properties := function["parameters"].(map[string]any)["properties"].(map[string]any)
	mode := properties["mode"].(map[string]any)
	limit := properties["limit"].(map[string]any)
	if mode["default"] != "<fast>" || fmt.Sprint(mode["enum"]) != "[<fast> exact]" || limit["default"] != json.Number("9007199254740993") {
		t.Fatalf("nested function schema lost fidelity: %#v", function)
	}
	search := tools[1].(map[string]any)
	if fmt.Sprint(search["allowed_x_handles"]) != "[xai]" || search["from_date"] != "2026-01-02" || search["to_date"] != "2026-07-19" {
		t.Fatalf("x_search filters lost fidelity: %#v", search)
	}
	if canonical["stream"] != false || canonical["store"] != true || canonical["model"] != "grok-4.5" || canonical["large"] != json.Number("9007199254740993") {
		t.Fatalf("canonical mutated during wire preparation: %#v", canonical)
	}
	canonicalTools := canonical["tools"].([]any)
	if len(canonicalTools) != 2 || !reflect.DeepEqual(canonicalTools[0], functionTool) || !reflect.DeepEqual(canonicalTools[1], searchTool) {
		t.Fatalf("canonical tools mutated: %#v", canonicalTools)
	}
}
