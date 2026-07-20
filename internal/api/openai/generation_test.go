package openai

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"byos/internal/api"
	appcrypto "byos/internal/crypto"
	"byos/internal/provider"
	"byos/internal/routing"
	"byos/internal/sessions"
	"byos/internal/store"
	"byos/internal/translate"
	"byos/internal/translate/registry"
)

type fakeStream struct {
	events         []provider.Event
	index          int
	model, account string
	closed         bool
}

func (s *fakeStream) Next(context.Context) (provider.Event, error) {
	if s.index >= len(s.events) {
		return provider.Event{}, io.EOF
	}
	event := s.events[s.index]
	s.index++
	return event, nil
}
func (s *fakeStream) Close() error      { s.closed = true; return nil }
func (s *fakeStream) Model() string     { return s.model }
func (s *fakeStream) AccountID() string { return s.account }

type cancellingStream struct {
	calls          int
	second, closed chan struct{}
}

func (s *cancellingStream) Next(ctx context.Context) (provider.Event, error) {
	s.calls++
	if s.calls == 1 {
		return provider.Event{Data: []byte(`{"type":"response.output_text.delta","delta":"hi"}`)}, nil
	}
	close(s.second)
	<-ctx.Done()
	return provider.Event{}, ctx.Err()
}
func (s *cancellingStream) Close() error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	return nil
}
func (s *cancellingStream) Model() string     { return "grok-4.5" }
func (s *cancellingStream) AccountID() string { return "acct" }
func completedEvent() provider.Event {
	return provider.Event{Data: []byte(`{"type":"response.completed","response":{"id":"resp_1","model":"grok-4.5","created_at":12,"status":"completed","output":[{"type":"x_search_call","id":"search"},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer https://x.com/post"}]}],"usage":{"input_tokens":4,"output_tokens":5,"total_tokens":9}}}`)}
}
func incompleteEvent(id string) provider.Event {
	return provider.Event{Data: []byte(`{"type":"response.incomplete","response":{"id":"` + id + `","model":"grok-4.5","status":"incomplete","output":[],"usage":{"input_tokens":1,"output_tokens":2},"incomplete_details":{"reason":"max_output_tokens"}}}`)}
}
func TestChatHandlerNonStreamAndStream(t *testing.T) {
	transform, _ := translate.NewRegistry().Get(registry.OpenAIChat)
	execute := func(_ context.Context, request routing.Request) (routing.Result, error) {
		return routing.Result{Model: "grok-4.5", AccountID: "a", Events: []provider.Event{completedEvent()}}, nil
	}
	handler := ChatHandler{Transform: transform, Execute: execute, OpenStream: func(context.Context, routing.Request) (api.RoutedStream, error) {
		return &fakeStream{model: "grok-4.5", account: "a", events: []provider.Event{{Data: []byte(`{"type":"response.output_text.delta","delta":"hi"}`)}, completedEvent()}}, nil
	}}
	for _, test := range []struct {
		name, body string
		stream     bool
	}{{"nonstream", `{"model":"grok","messages":[{"role":"user","content":"current X news"}]}`, false}, {"stream", `{"model":"grok","messages":[{"role":"user","content":"hello"}],"stream":true}`, true}} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != 200 {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if test.stream {
				if strings.Count(response.Body.String(), "[DONE]") != 1 {
					t.Fatalf("stream=%s", response.Body.String())
				}
			} else if !strings.Contains(response.Body.String(), "https://x.com/post") || strings.Contains(response.Body.String(), "x_search_call") {
				t.Fatalf("response=%s", response.Body.String())
			}
		})
	}
}
func TestGenerationHandlersPassCanonicalBodyUnchangedBeforeRouting(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{24}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sessionService := sessions.NewService(store.NewResponseRepository(database.DB, keys))
	for _, test := range []struct {
		name, model, path, body string
		kind                    registry.Format
		responses               bool
	}{
		{name: "chat unknown", model: "unknown-model", path: "/v1/chat/completions", body: `{"model":"unknown-model","messages":[{"role":"user","content":"news"}]}`, kind: registry.OpenAIChat},
		{name: "responses devin", model: "kimi-k2-7", path: "/v1/responses", body: `{"model":"kimi-k2-7","input":"news"}`, kind: registry.OpenAIResponses, responses: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			transform, ok := translate.NewRegistry().Get(test.kind)
			if !ok {
				t.Fatal("transform not registered")
			}
			expected, err := transform.Request(test.model, []byte(test.body), false)
			if err != nil {
				t.Fatal(err)
			}
			called := false
			execute := func(_ context.Context, request routing.Request) (routing.Result, error) {
				called = true
				if request.Model != test.model || !bytes.Equal(request.Body, expected) {
					t.Fatalf("routing request model=%q body=%s, want model=%q body=%s", request.Model, request.Body, test.model, expected)
				}
				return routing.Result{}, routing.ErrModelUnavailable
			}
			request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			if test.responses {
				ResponsesHandler{Transform: transform, Execute: execute, Sessions: sessionService}.ServeHTTP(response, request)
			} else {
				ChatHandler{Transform: transform, Execute: execute}.ServeHTTP(response, request)
			}
			if !called {
				t.Fatal("routing was not called")
			}
		})
	}
}

func TestResponsesHandlerPersistsAndEmitsNativeEvents(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, _ := appcrypto.DeriveKeys(bytes.Repeat([]byte{16}, 32))
	sessionService := sessions.NewService(store.NewResponseRepository(database.DB, keys))
	transform, _ := translate.NewRegistry().Get(registry.OpenAIResponses)
	execute := func(_ context.Context, request routing.Request) (routing.Result, error) {
		return routing.Result{Model: "grok-4.5", AccountID: "acct", Events: []provider.Event{completedEvent()}}, nil
	}
	handler := ResponsesHandler{Transform: transform, Execute: execute, OpenStream: func(context.Context, routing.Request) (api.RoutedStream, error) {
		return &fakeStream{model: "grok-4.5", account: "acct", events: []provider.Event{completedEvent()}}, nil
	}, Sessions: sessionService}
	request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"grok","input":"hello"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 200 || !strings.Contains(response.Body.String(), "x_search_call") {
		t.Fatalf("response=%d %s", response.Code, response.Body.String())
	}
	if _, err := sessionService.Prepare(ctx, []byte(`{"model":"grok","previous_response_id":"resp_1","input":"again"}`)); err != nil {
		t.Fatalf("continuation=%v", err)
	}
	streamRequest := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"grok","input":"hello","stream":true,"store":false}`))
	streamRequest.Header.Set("Content-Type", "application/json")
	streamResponse := httptest.NewRecorder()
	handler.ServeHTTP(streamResponse, streamRequest)
	if strings.Contains(streamResponse.Body.String(), "[DONE]") || !strings.Contains(streamResponse.Body.String(), "response.completed") {
		t.Fatalf("stream=%s", streamResponse.Body.String())
	}
}

func TestResponsesHandlerAcceptsEasyInputMessages(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, _ := appcrypto.DeriveKeys(bytes.Repeat([]byte{20}, 32))
	transform, _ := translate.NewRegistry().Get(registry.OpenAIResponses)
	handler := ResponsesHandler{
		Transform: transform,
		Execute: func(_ context.Context, request routing.Request) (routing.Result, error) {
			if !strings.Contains(string(request.Body), `"type":"message"`) {
				t.Fatalf("easy input message was not normalized: %s", request.Body)
			}
			return routing.Result{Model: "grok-4.5", AccountID: "acct", Events: []provider.Event{completedEvent()}}, nil
		},
		Sessions: sessions.NewService(store.NewResponseRepository(database.DB, keys)),
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"grok","input":[{"role":"user","content":"hello"}]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("response=%d %s", response.Code, response.Body.String())
	}
}

func TestChatHandlerMapsUnavailableModel(t *testing.T) {
	transform, _ := translate.NewRegistry().Get(registry.OpenAIChat)
	handler := ChatHandler{Transform: transform, Execute: func(context.Context, routing.Request) (routing.Result, error) {
		return routing.Result{}, routing.ErrModelUnavailable
	}}
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"missing","messages":[{"role":"user","content":"hi"}]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), "model_not_found") {
		t.Fatalf("response=%d %s", response.Code, response.Body.String())
	}
}

func TestChatStreamIncompleteEmitsDoneOnce(t *testing.T) {
	transform, _ := translate.NewRegistry().Get(registry.OpenAIChat)
	event := provider.Event{Data: []byte(`{"type":"response.incomplete","response":{"id":"r","status":"incomplete","output":[],"usage":{"input_tokens":1,"output_tokens":2},"incomplete_details":{"reason":"max_output_tokens"}}}`)}
	handler := ChatHandler{Transform: transform, OpenStream: func(context.Context, routing.Request) (api.RoutedStream, error) {
		return &fakeStream{model: "grok-4.5", account: "a", events: []provider.Event{event}}, nil
	}}
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"grok","messages":[{"role":"user","content":"hi"}],"stream":true}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Count(response.Body.String(), "[DONE]") != 1 {
		t.Fatalf("response=%d %s", response.Code, response.Body.String())
	}
}

func TestResponsesStreamDoesNotEmitTerminalWhenPersistenceFails(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := appcrypto.DeriveKeys(bytes.Repeat([]byte{17}, 32))
	service := sessions.NewService(store.NewResponseRepository(database.DB, keys))
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	transform, _ := translate.NewRegistry().Get(registry.OpenAIResponses)
	handler := ResponsesHandler{Transform: transform, OpenStream: func(context.Context, routing.Request) (api.RoutedStream, error) {
		return &fakeStream{model: "grok-4.5", account: "a", events: []provider.Event{completedEvent()}}, nil
	}, Sessions: service}
	request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"grok","input":"hello","stream":true}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if strings.Contains(response.Body.String(), "response.completed") {
		t.Fatalf("terminal exposed: %s", response.Body.String())
	}
}

func TestChatHandlerCancellationClosesActiveStream(t *testing.T) {
	transform, _ := translate.NewRegistry().Get(registry.OpenAIChat)
	stream := &cancellingStream{second: make(chan struct{}), closed: make(chan struct{})}
	handler := ChatHandler{Transform: transform, OpenStream: func(context.Context, routing.Request) (api.RoutedStream, error) { return stream, nil }}
	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"grok","messages":[{"role":"user","content":"hi"}],"stream":true}`)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	done := make(chan struct{})
	go func() { handler.ServeHTTP(httptest.NewRecorder(), request); close(done) }()
	<-stream.second
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not stop")
	}
	select {
	case <-stream.closed:
	case <-time.After(time.Second):
		t.Fatal("stream not closed")
	}
}

func TestResponsesIncompleteIsNeverPersisted(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(map[bool]string{false: "nonstream", true: "stream"}[streaming], func(t *testing.T) {
			ctx := context.Background()
			database, err := store.Open(ctx, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			keys, _ := appcrypto.DeriveKeys(bytes.Repeat([]byte{19}, 32))
			service := sessions.NewService(store.NewResponseRepository(database.DB, keys))
			transform, _ := translate.NewRegistry().Get(registry.OpenAIResponses)
			id := "resp_incomplete"
			handler := ResponsesHandler{Transform: transform, Sessions: service, Execute: func(context.Context, routing.Request) (routing.Result, error) {
				return routing.Result{Model: "grok-4.5", AccountID: "acct", Events: []provider.Event{incompleteEvent(id)}}, nil
			}, OpenStream: func(context.Context, routing.Request) (api.RoutedStream, error) {
				return &fakeStream{model: "grok-4.5", account: "acct", events: []provider.Event{incompleteEvent(id)}}, nil
			}}
			body := `{"model":"grok","input":"hello"}`
			if streaming {
				body = `{"model":"grok","input":"hello","stream":true}`
			}
			request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			marker := `"status":"incomplete"`
			if streaming {
				marker = "response.incomplete"
			}
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), marker) {
				t.Fatalf("response=%d %s", response.Code, response.Body.String())
			}
			_, err = service.Prepare(ctx, []byte(`{"model":"grok","previous_response_id":"`+id+`","input":"again"}`))
			if !errors.Is(err, sessions.ErrPreviousResponseNotFound) {
				t.Fatalf("continuation error=%v", err)
			}
		})
	}
}
