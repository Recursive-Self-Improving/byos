package devin

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	devinproto "byos/internal/devin/proto"
	"byos/internal/provider"
	"google.golang.org/protobuf/encoding/protowire"
)

func generationTestClient(t *testing.T, connectBody []byte, connectStatus int, calls *atomic.Int32) *Client {
	t.Helper()
	client := directClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL.Path == devinproto.AuthServiceGetUserJWTPath {
			return response(http.StatusOK, jwtPayload(t, "jwt", "https://chat.example.com"), ""), nil
		}
		if r.URL.Path != devinproto.APIServiceGetChatMessagePath {
			t.Fatalf("unexpected request path %q", r.URL.Path)
		}
		return response(connectStatus, connectBody, ""), nil
	}))
	client.streamIdleTimeout = time.Second
	client.maxFrameCompressedBytes = 1 << 20
	client.maxFrameDecompressedBytes = 1 << 20
	client.maxStreamBytes = 1 << 20
	client.maxToolArgumentBytes = 1 << 20
	client.maxNonStreamBytes = 1 << 20
	return client
}

func generationFrames(t *testing.T) []byte {
	t.Helper()
	usage, err := (&devinproto.ModelUsageStats{InputTokens: 7, OutputTokens: 3, CacheReadTokens: 2}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	text := protowire.AppendTag(nil, 3, protowire.BytesType)
	text = protowire.AppendString(text, "answer")
	terminal := protowire.AppendTag(nil, 23, protowire.BytesType)
	terminal = protowire.AppendString(terminal, "devin-model")
	terminal = protowire.AppendTag(terminal, 7, protowire.BytesType)
	terminal = protowire.AppendBytes(terminal, usage)
	body := append(connectFrame(0, text), connectFrame(0, terminal)...)
	return append(body, connectFrame(2, []byte(`{}`))...)
}

func generationRequest() provider.GenerationRequest {
	return provider.GenerationRequest{
		Model:      provider.ResolvedModel{UpstreamName: "devin-model", Provider: provider.Devin},
		Canonical:  provider.CanonicalRequest{"model": "devin-model", "input": []any{map[string]any{"type": "message", "role": "user", "content": []any{map[string]any{"type": "input_text", "text": "hello"}}}}},
		Credential: provider.Credential{Value: "session-secret"},
	}
}

func TestProviderClientExecuteBuffersOneStreamAndCarriesUsage(t *testing.T) {
	var calls atomic.Int32
	client := generationTestClient(t, generationFrames(t), http.StatusOK, &calls)
	adapter := NewProviderClient(client)
	adapter.newResponseID = func() (string, error) { return "resp_test", nil }

	events, err := adapter.Execute(context.Background(), generationRequest())
	if err != nil {
		t.Fatalf("Execute error after %d calls: %v", calls.Load(), err)
	}
	if calls.Load() != 2 {
		t.Fatalf("HTTP calls = %d; want one bootstrap plus one stream", calls.Load())
	}
	if len(events) == 0 {
		t.Fatal("no events")
	}
	terminal := events[len(events)-1]
	if terminal.Event != "response.completed" || terminal.Usage != (provider.Usage{InputTokens: 7, OutputTokens: 3, TotalTokens: 10, CacheReadTokens: 2}) {
		t.Fatalf("terminal = %+v", terminal)
	}
}

func TestProviderClientExecuteBoundClosesWithoutSecondCall(t *testing.T) {
	var calls atomic.Int32
	client := generationTestClient(t, generationFrames(t), http.StatusOK, &calls)
	client.maxNonStreamBytes = 1
	adapter := NewProviderClient(client)
	adapter.newResponseID = func() (string, error) { return "resp_test", nil }

	_, err := adapter.Execute(context.Background(), generationRequest())
	var upstream *provider.UpstreamError
	if !errors.As(err, &upstream) || upstream.Classification.Class != provider.ClassUpstream {
		t.Fatalf("error = %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("HTTP calls = %d; Execute replayed upstream", calls.Load())
	}
}

func TestProviderClientClassifiesAuthenticationAndPreFirstFailure(t *testing.T) {
	var calls atomic.Int32
	client := generationTestClient(t, nil, http.StatusUnauthorized, &calls)
	adapter := NewProviderClient(client)
	adapter.newResponseID = func() (string, error) { return "resp_test", nil }

	_, err := adapter.Stream(context.Background(), generationRequest())
	var upstream *provider.UpstreamError
	if !errors.As(err, &upstream) || upstream.Provider != provider.Devin || upstream.Classification.Class != provider.ClassUnauthorized || !upstream.Classification.RetryNext || !upstream.Classification.ReloginRequired || !upstream.Classification.DisableAccount {
		t.Fatalf("authentication error = %+v (%v)", upstream, err)
	}
}

func TestGenerationStreamAdaptsCancellationAndIncompleteEOF(t *testing.T) {
	cancelled := &generationStream{stream: &testProviderStream{next: func(context.Context) (provider.Event, error) { return provider.Event{}, context.Canceled }}}
	if _, err := cancelled.Next(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel = %v", err)
	}

	var calls atomic.Int32
	client := generationTestClient(t, connectFrame(2, []byte(`{}`)), http.StatusOK, &calls)
	adapter := NewProviderClient(client)
	adapter.newResponseID = func() (string, error) { return "resp_test", nil }
	events, err := adapter.Execute(context.Background(), generationRequest())
	if err != nil {
		t.Fatalf("Execute error after %d calls: %v", calls.Load(), err)
	}
	if len(events) != 2 || events[len(events)-1].Event != "response.completed" {
		t.Fatalf("events = %+v", events)
	}
}

// TestProviderClientClassifiesConnectEndStreamErrorBeforeFirstEvent proves a
// Connect EndStream error arriving before any data event surfaces through the
// real transport as a typed provider.UpstreamError whose classification
// metadata (RetryNext, ReloginRequired, DisableAccount, CooldownScope) is what
// routing consumes to fail over, cool down, and persist relogin — without ever
// emitting a partial response. This is the routing-facing contract: the
// EndStream error path must produce the same typed classification as the HTTP
// status path.
func TestProviderClientClassifiesConnectEndStreamErrorBeforeFirstEvent(t *testing.T) {
	cases := []struct {
		code      string
		class     provider.ErrorClass
		retryNext bool
		relogin   bool
		disable   bool
		scope     provider.CooldownScope
	}{
		{"unavailable", provider.ClassTransient, true, false, false, provider.CooldownModel},
		{"internal", provider.ClassTransient, true, false, false, provider.CooldownModel},
		{"resource_exhausted", provider.ClassRateLimit, true, false, false, provider.CooldownModel},
		{"unauthenticated", provider.ClassUnauthorized, true, true, true, provider.CooldownAccount},
		{"permission_denied", provider.ClassPermission, false, false, false, provider.CooldownAccount},
		{"invalid_argument", provider.ClassValidation, false, false, false, provider.CooldownNone},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			var calls atomic.Int32
			// The stream body is a single EndStream error frame: the error
			// arrives before any data event, so Execute must return the typed
			// classification without emitting events.
			body := connectFrame(2, []byte(`{"error":{"code":"`+tc.code+`","message":"upstream detail"}}`))
			client := generationTestClient(t, body, http.StatusOK, &calls)
			adapter := NewProviderClient(client)
			adapter.newResponseID = func() (string, error) { return "resp_test", nil }

			events, err := adapter.Execute(context.Background(), generationRequest())
			if len(events) != 0 {
				t.Fatalf("expected no events before first-event error; got %d", len(events))
			}
			var upstream *provider.UpstreamError
			if !errors.As(err, &upstream) {
				t.Fatalf("err = %v; want typed UpstreamError", err)
			}
			c := upstream.Classification
			if upstream.Provider != provider.Devin || c.Class != tc.class || c.RetryNext != tc.retryNext || c.ReloginRequired != tc.relogin || c.DisableAccount != tc.disable || c.CooldownScope != tc.scope {
				t.Fatalf("%s: upstream=%+v", tc.code, upstream)
			}
			// The upstream detail must not leak into the sanitized public
			// message that routing surfaces to callers.
			if c.PublicMessage == "upstream detail" {
				t.Fatalf("%s: upstream detail leaked into public message %q", tc.code, c.PublicMessage)
			}
		})
	}

	// A structurally invalid Connect error (null error object) surfaces as a
	// generic upstream error via adaptGenerationError, never as a partial
	// response, and does not carry failover metadata.
	var calls atomic.Int32
	client := generationTestClient(t, connectFrame(2, []byte(`{"error":null}`)), http.StatusOK, &calls)
	adapter := NewProviderClient(client)
	adapter.newResponseID = func() (string, error) { return "resp_test", nil }
	events, err := adapter.Execute(context.Background(), generationRequest())
	if len(events) != 0 {
		t.Fatalf("expected no events for malformed error; got %d", len(events))
	}
	var upstream *provider.UpstreamError
	if !errors.As(err, &upstream) || upstream.Classification.Class != provider.ClassUpstream {
		t.Fatalf("malformed error = %v; want typed ClassUpstream", err)
	}

	// A present-but-null message is structurally invalid even when the code
	// would otherwise classify (here "unavailable" -> ClassTransient with a
	// model-scoped cooldown). The malformed message must be rejected before
	// the code is classified, so routing never sees the code-specific
	// failover/cooldown metadata: the error surfaces as the same generic
	// ClassUpstream that a wholly-null error object produces, never as
	// ClassTransient, and no partial response is emitted. This is the routing
	// no-classification contract for the optional message field.
	var nullMsgCalls atomic.Int32
	nullMsgClient := generationTestClient(t, connectFrame(2, []byte(`{"error":{"code":"unavailable","message":null}}`)), http.StatusOK, &nullMsgCalls)
	nullMsgAdapter := NewProviderClient(nullMsgClient)
	nullMsgAdapter.newResponseID = func() (string, error) { return "resp_test", nil }
	nullMsgEvents, nullMsgErr := nullMsgAdapter.Execute(context.Background(), generationRequest())
	if len(nullMsgEvents) != 0 {
		t.Fatalf("expected no events for null-message error; got %d", len(nullMsgEvents))
	}
	var nullMsgUpstream *provider.UpstreamError
	if !errors.As(nullMsgErr, &nullMsgUpstream) {
		t.Fatalf("null-message error = %v; want typed UpstreamError", nullMsgErr)
	}
	// The code "unavailable" would classify as ClassTransient; rejecting the
	// null message before classification means the generic ClassUpstream
	// (same as a wholly-null error object) is surfaced instead.
	if nullMsgUpstream.Classification.Class != provider.ClassUpstream {
		t.Fatalf("null-message class = %s; want ClassUpstream (no code classification)", nullMsgUpstream.Classification.Class)
	}
	if nullMsgUpstream.Classification.Class == provider.ClassTransient {
		t.Fatalf("null-message error must not be classified as the code's ClassTransient; got %+v", nullMsgUpstream.Classification)
	}
	// The null-message path must match the wholly-null error object path:
	// both are malformed terminations and produce identical generic
	// classifications, so routing treats them identically.
	if nullMsgUpstream.Classification != upstream.Classification {
		t.Fatalf("null-message classification = %+v; want identical to null-error %+v", nullMsgUpstream.Classification, upstream.Classification)
	}
}

type testProviderStream struct {
	next   func(context.Context) (provider.Event, error)
	closed atomic.Bool
}

func (s *testProviderStream) Next(ctx context.Context) (provider.Event, error) { return s.next(ctx) }
func (s *testProviderStream) Close() error                                     { s.closed.Store(true); return nil }

var _ provider.GenerationClient = (*ProviderClient)(nil)
var _ provider.Stream = (*generationStream)(nil)
var _ io.Reader = (*bytes.Reader)(nil)
