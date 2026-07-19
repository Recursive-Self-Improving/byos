package xai

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"byos/internal/provider"
)

// TestPrepareSerializesToolChoiceAtWireBoundary asserts tool_choice none/auto/
// selected reaches the serialized JSON wire body unchanged through the sole
// encodeWireJSON call site in Client.prepare. RequestPolicy.Prepare runs
// search.Inject (which rewrites "none" to "auto" when an x_search tool is
// present, the xAI invariant) before the sole encode, so the test exercises
// the full policy+encode path and asserts the serialized boundary.
func TestPrepareSerializesToolChoiceAtWireBoundary(t *testing.T) {
	functionTool := map[string]any{"type": "function", "name": "lookup", "parameters": map[string]any{"type": "object"}}
	searchTool := map[string]any{"type": "x_search"}
	cases := []struct {
		name       string
		tools      []any
		choice     any
		wantChoice any
	}{
		{"auto with search", []any{searchTool}, "auto", "auto"},
		{"none rewritten to auto with search", []any{searchTool}, "none", "auto"},
		{"required preserved with search", []any{searchTool}, "required", "required"},
		{"selected function preserved alongside search", []any{functionTool, searchTool}, map[string]any{"type": "function", "name": "lookup"}, map[string]any{"type": "function", "name": "lookup"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			canonical := map[string]any{"model": "grok-4.5", "tools": test.tools, "tool_choice": test.choice}
			if err := (RequestPolicy{}).Prepare(context.Background(), provider.ResolvedModel{PublicName: "grok", Provider: provider.XAI}, canonical); err != nil {
				t.Fatalf("RequestPolicy.Prepare: %v", err)
			}
			prepared, err := (&Client{}).prepare(canonical, encodeWireJSON)
			if err != nil {
				t.Fatalf("prepare: %v", err)
			}
			decoder := json.NewDecoder(bytes.NewReader(prepared))
			decoder.UseNumber()
			var wire map[string]any
			if err := decoder.Decode(&wire); err != nil {
				t.Fatalf("decode: %v", err)
			}
			actual, _ := json.Marshal(wire["tool_choice"])
			expected, _ := json.Marshal(test.wantChoice)
			if string(actual) != string(expected) {
				t.Fatalf("serialized tool_choice = %s, want %s (wire=%s)", actual, expected, prepared)
			}
			if wire["stream"] != true || wire["store"] != false {
				t.Fatalf("stream/store not forced: %#v", wire)
			}
		})
	}
}

// TestProviderClientExecuteEncodesWireExactlyOnceViaPrivateEncoder proves the
// xAI ProviderClient is the sole wire serializer at the private package
// boundary: the injected encoder (private ProviderClient.encoder field, set to
// encodeWireJSON by NewProviderClient) is invoked exactly once per Execute,
// counted dynamically by wrapping the encoder, and the wire body the upstream
// receives is the JSON from that single encode.
func TestProviderClientExecuteEncodesWireExactlyOnceViaPrivateEncoder(t *testing.T) {
	var wireBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wireBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"response.completed\"}\n\n"))
	}))
	defer server.Close()

	client := NewProviderClient(NewClient(HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second, SSEIdleTimeout: time.Second}))
	encodeCount := 0
	actualEncoder := client.encoder
	client.encoder = func(destination io.Writer, value any) error {
		encodeCount++
		return actualEncoder(destination, value)
	}
	canonical := provider.CanonicalRequest{
		"model":       "grok-4.5",
		"input":       "raw <tag>",
		"tools":       []any{map[string]any{"type": "x_search"}},
		"tool_choice": "auto",
	}
	events, err := client.Execute(context.Background(), provider.GenerationRequest{
		Model:      provider.ResolvedModel{UpstreamName: "grok-4.5", Provider: provider.XAI},
		Canonical:  canonical,
		Credential: provider.Credential{Value: "secret"},
	})
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	if encodeCount != 1 {
		t.Fatalf("encoder invocations=%d want=1 (sole serializer)", encodeCount)
	}
	if strings.Contains(string(wireBody), `\u003c`) {
		t.Fatalf("HTML escaped on wire: %s", wireBody)
	}
	var wire map[string]any
	decoder := json.NewDecoder(bytes.NewReader(wireBody))
	decoder.UseNumber()
	if err := decoder.Decode(&wire); err != nil {
		t.Fatalf("decode wire: %v", err)
	}
	if wire["tool_choice"] != "auto" || wire["stream"] != true || wire["store"] != false || wire["input"] != "raw <tag>" {
		t.Fatalf("wire fidelity lost: %#v", wire)
	}
	if canonical["tool_choice"] != "auto" || canonical["stream"] != nil || canonical["store"] != nil {
		t.Fatalf("canonical mutated: %#v", canonical)
	}
}

var _ provider.GenerationClient = (*ProviderClient)(nil)
