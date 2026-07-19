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

type testProviderStream struct {
	next   func(context.Context) (provider.Event, error)
	closed atomic.Bool
}

func (s *testProviderStream) Next(ctx context.Context) (provider.Event, error) { return s.next(ctx) }
func (s *testProviderStream) Close() error                                     { s.closed.Store(true); return nil }

var _ provider.GenerationClient = (*ProviderClient)(nil)
var _ provider.Stream = (*generationStream)(nil)
var _ io.Reader = (*bytes.Reader)(nil)
