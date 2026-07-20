package xai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"byos/internal/provider"
)

func TestProviderClientPreservesGenerationWireContract(t *testing.T) {
	var captured string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/responses" || r.Method != http.MethodPost {
			t.Errorf("request=%s %s", r.Method, r.URL.Path)
		}
		for key, want := range map[string]string{"Authorization": "Bearer secret", "Accept": "text/event-stream", "X-XAI-Token-Auth": "xai-grok-cli", "x-grok-client-version": "version", "User-Agent": "agent", "x-grok-model-override": "grok-4.5"} {
			if got := r.Header.Get(key); got != want {
				t.Errorf("%s=%q want %q", key, got, want)
			}
		}
		body, _ := io.ReadAll(r.Body)
		captured = string(body)
		fmt.Fprint(w, "event: response\ndata: {\"type\":\"response.completed\"}\n\n")
	}))
	defer server.Close()
	client := NewProviderClient(NewClient(HTTPConfig{BaseURL: server.URL, ClientVersion: "version", UserAgent: "agent", RequestTimeout: time.Second, SSEIdleTimeout: time.Second}))
	request := provider.GenerationRequest{Model: provider.ResolvedModel{UpstreamName: "grok-4.5", Provider: provider.XAI}, Canonical: provider.CanonicalRequest{"input": "<tag>", "tools": []any{map[string]any{"type": "x_search"}}}, Credential: provider.Credential{Value: "secret"}}
	events, err := client.Execute(context.Background(), request)
	if err != nil || len(events) != 1 || events[0].Event != "response" || string(events[0].Data) != `{"type":"response.completed"}` {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	if strings.Contains(captured, `\u003c`) || strings.Count(captured, `"stream":true`) != 1 || strings.Count(captured, `"store":false`) != 1 {
		t.Fatalf("wire body=%s", captured)
	}
}

func TestProviderClientSanitizesAndClassifiesUpstreamErrors(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "120")
		http.Error(w, `{"error":{"code":"private"},"token":"secret"}`, http.StatusTooManyRequests)
	}))
	defer server.Close()
	client := NewProviderClient(NewClient(HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second}))
	client.now = func() time.Time { return now }
	_, err := client.Execute(context.Background(), provider.GenerationRequest{Model: provider.ResolvedModel{UpstreamName: "grok-4.5"}, Canonical: provider.CanonicalRequest{"tools": []any{map[string]any{"type": "x_search"}}}, Credential: provider.Credential{Value: "secret"}})
	var upstream *provider.UpstreamError
	if !errors.As(err, &upstream) {
		t.Fatalf("error=%#v", err)
	}
	got := upstream.Classification
	if got.Class != provider.ClassRateLimit || !got.RetryNext || !got.ExplicitRetryAfter || got.Cooldown != 2*time.Minute || !got.RetryAfter.Equal(now.Add(2*time.Minute)) || got.CooldownScope != provider.CooldownModel {
		t.Fatalf("classification=%+v", got)
	}
	if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsanitized error=%v", err)
	}
}

func TestClassifyUpstreamTransientStatusMatrix(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	for _, status := range []int{
		http.StatusRequestTimeout,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			got := classifyUpstream(status, http.Header{"Retry-After": []string{"120"}}, []byte(`private-upstream-body`), now)
			if got.Class != provider.ClassTransient || !got.RetryNext {
				t.Fatalf("status=%d class=%q retry_next=%t", status, got.Class, got.RetryNext)
			}
			if got.CooldownScope != provider.CooldownModel || got.Cooldown != time.Minute || !got.RetryAfter.IsZero() || got.ExplicitRetryAfter {
				t.Fatalf("status=%d cooldown classification=%+v", status, got)
			}
			if got.PublicStatus != http.StatusServiceUnavailable || got.PublicCode != "provider_unavailable" || got.PublicMessage != "upstream provider error" {
				t.Fatalf("status=%d public classification=%+v", status, got)
			}
		})
	}
}

func TestProviderClientPreservesCancellationAndNetworkDistinction(t *testing.T) {
	client := NewProviderClient(NewClient(HTTPConfig{}))
	if err := client.adaptError(context.Canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation adapted to %T: %v", err, err)
	}

	err := client.adaptError(context.DeadlineExceeded)
	var upstream *provider.UpstreamError
	if !errors.As(err, &upstream) {
		t.Fatalf("network error=%#v", err)
	}
	got := upstream.Classification
	if got.Class != provider.ClassConnection || !got.RetryNext || got.CooldownScope != provider.CooldownNone || got.Cooldown != 0 {
		t.Fatalf("network classification=%+v", got)
	}
	if got.PublicStatus != http.StatusServiceUnavailable || got.PublicCode != "provider_unavailable" || got.PublicMessage != "upstream provider error" {
		t.Fatalf("network public classification=%+v", got)
	}
}

func TestXAIPolicyInjectsOnceAndPreservesSelectedChoice(t *testing.T) {
	request := provider.CanonicalRequest{"model": "grok", "tools": []any{map[string]any{"type": "function", "name": "lookup"}}, "tool_choice": map[string]any{"type": "function", "name": "lookup"}}
	if err := (RequestPolicy{}).Prepare(context.Background(), provider.ResolvedModel{PublicName: "grok", Provider: provider.XAI}, request); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(encoded), `"type":"x_search"`) != 1 || !strings.Contains(string(encoded), `"name":"lookup"`) {
		t.Fatalf("prepared=%s", encoded)
	}
}

func TestClassifyUpstreamExactFreeUsageAndRetryAfterPast(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	free := classifyUpstream(429, nil, []byte(`{"error":{"code":"subscription:free-usage-exhausted"}}`), now)
	if free.Class != provider.ClassFreeUsageExhausted || free.Cooldown != 24*time.Hour {
		t.Fatalf("free=%+v", free)
	}
	near := classifyUpstream(429, nil, []byte(`{"message":"subscription:free-usage-exhausted"}`), now)
	if near.Class != provider.ClassRateLimit {
		t.Fatalf("near=%+v", near)
	}
	past := classifyUpstream(429, http.Header{"Retry-After": []string{now.Add(-time.Hour).Format(http.TimeFormat)}}, nil, now)
	if !past.ExplicitRetryAfter || past.Cooldown != 0 || !past.RetryAfter.Equal(now) {
		t.Fatalf("past=%+v", past)
	}
}

func TestProviderClientCanonicalPolicyModelOverwriteAndSingleEncodeFidelity(t *testing.T) {
	var wireBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		wireBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprint(w, "data: {\"type\":\"response.completed\"}\n\n")
	}))
	defer server.Close()

	functionTool := map[string]any{
		"type":        "function",
		"name":        "lookup",
		"description": "lookup <tag>",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{"type": "string", "enum": []any{"<raw>", "exact"}, "default": "<raw>"},
				"options": map[string]any{
					"type":       "object",
					"properties": map[string]any{"limit": map[string]any{"type": "integer", "default": json.Number("9007199254740993")}},
				},
			},
			"required": []any{"query"},
		},
	}
	searchTool := map[string]any{
		"type": "x_search", "allowed_x_handles": []any{"xai", "grok"},
		"from_date": "2026-01-02", "to_date": "2026-07-19",
	}
	canonical := provider.CanonicalRequest{
		"model": "public-grok", "input": "raw <tag>", "large": json.Number("9007199254740993"),
		"stream": false, "store": true, "tools": []any{functionTool, searchTool},
	}
	resolved := provider.ResolvedModel{PublicName: "public-grok", UpstreamName: "grok-4.5", Provider: provider.XAI, OwnedBy: "byos", PolicyKey: "xai"}
	if err := (RequestPolicy{}).Prepare(context.Background(), resolved, canonical); err != nil {
		t.Fatal(err)
	}
	canonical["model"] = resolved.UpstreamName

	client := NewProviderClient(NewClient(HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second, SSEIdleTimeout: time.Second}))
	encodeCount := 0
	actualEncoder := client.encoder
	client.encoder = func(destination io.Writer, value any) error {
		encodeCount++
		return actualEncoder(destination, value)
	}
	events, err := client.Execute(context.Background(), provider.GenerationRequest{Model: resolved, Canonical: canonical, Credential: provider.Credential{Value: "secret"}})
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	if encodeCount != 1 {
		t.Fatalf("encoder invocations=%d want=1", encodeCount)
	}
	if strings.Contains(string(wireBody), `\u003c`) {
		t.Fatalf("HTML escaped on wire: %s", wireBody)
	}

	var wire provider.CanonicalRequest
	decoder := json.NewDecoder(strings.NewReader(string(wireBody)))
	decoder.UseNumber()
	if err := decoder.Decode(&wire); err != nil {
		t.Fatal(err)
	}
	if wire["model"] != resolved.UpstreamName || wire["stream"] != true || wire["store"] != false || wire["large"] != json.Number("9007199254740993") || wire["input"] != "raw <tag>" {
		t.Fatalf("wire scalar fidelity=%#v", wire)
	}
	tools, ok := wire["tools"].([]any)
	if !ok || len(tools) != 2 {
		t.Fatalf("wire tools=%#v", wire["tools"])
	}
	function, ok := tools[0].(map[string]any)
	if !ok {
		t.Fatalf("function tool=%#v", tools[0])
	}
	parameters := function["parameters"].(map[string]any)
	properties := parameters["properties"].(map[string]any)
	query := properties["query"].(map[string]any)
	options := properties["options"].(map[string]any)
	limit := options["properties"].(map[string]any)["limit"].(map[string]any)
	if query["default"] != "<raw>" || fmt.Sprint(query["enum"]) != "[<raw> exact]" || limit["default"] != json.Number("9007199254740993") || fmt.Sprint(parameters["required"]) != "[query]" {
		t.Fatalf("nested function schema lost fidelity: %#v", function)
	}
	search := tools[1].(map[string]any)
	if fmt.Sprint(search["allowed_x_handles"]) != "[xai grok]" || search["from_date"] != "2026-01-02" || search["to_date"] != "2026-07-19" {
		t.Fatalf("x_search filters lost fidelity: %#v", search)
	}

	if canonical["model"] != resolved.UpstreamName || canonical["stream"] != false || canonical["store"] != true || canonical["large"] != json.Number("9007199254740993") || canonical["input"] != "raw <tag>" {
		t.Fatalf("canonical mutated outside policy/model ownership: %#v", canonical)
	}
	canonicalTools := canonical["tools"].([]any)
	if len(canonicalTools) != 2 || !reflect.DeepEqual(canonicalTools[0], functionTool) || !reflect.DeepEqual(canonicalTools[1], searchTool) {
		t.Fatalf("canonical tool identity/content mutated: %#v", canonicalTools)
	}
}
