package anthropic

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"supergrok-api/internal/api"
	"supergrok-api/internal/routing"
	"supergrok-api/internal/search"
	"supergrok-api/internal/translate"
	"supergrok-api/internal/translate/registry"
	"supergrok-api/internal/xai"
)

type fakeStream struct {
	events []xai.Event
	index  int
}

func (s *fakeStream) Next(context.Context) (xai.Event, error) {
	if s.index >= len(s.events) {
		return xai.Event{}, io.EOF
	}
	event := s.events[s.index]
	s.index++
	return event, nil
}
func (s *fakeStream) Close() error      { return nil }
func (s *fakeStream) Model() string     { return "grok-4.5" }
func (s *fakeStream) AccountID() string { return "acct" }
func anthropicCompleted() xai.Event {
	return xai.Event{Data: []byte(`{"type":"response.completed","response":{"id":"resp","status":"completed","output":[{"type":"x_search_call","id":"search"},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer https://x.com/post"}]}],"usage":{"input_tokens":2,"output_tokens":3}}}`)}
}
func TestMessagesHandlerContracts(t *testing.T) {
	transform, _ := translate.NewRegistry().Get(registry.Anthropic)
	execute := func(_ context.Context, request routing.Request) (routing.Result, error) {
		if err := search.Validate(request.Body); err != nil {
			t.Fatal(err)
		}
		canonical := string(request.Body)
		if strings.Contains(canonical, `"effort"`) {
			t.Fatalf("unsupported reasoning effort forwarded: %s", canonical)
		}
		if strings.Contains(canonical, `"name":"lookup"`) && !strings.Contains(canonical, `"parallel_tool_calls":false`) {
			t.Fatalf("parallel tool choice lost: %s", canonical)
		}
		return routing.Result{Model: "grok-4.5", AccountID: "acct", Events: []xai.Event{anthropicCompleted()}}, nil
	}
	handler := MessagesHandler{Transform: transform, Execute: execute, OpenStream: func(context.Context, routing.Request) (api.RoutedStream, error) {
		return &fakeStream{events: []xai.Event{{Data: []byte(`{"type":"response.output_text.delta","delta":"hi"}`)}, anthropicCompleted()}}, nil
	}}
	for _, body := range []string{`{"model":"grok","messages":[{"role":"user","content":"hello"}]}`, `{"model":"grok","messages":[{"role":"user","content":"hello"}],"stream":true}`, `{"model":"grok","max_tokens":1024,"messages":[{"role":"user","content":"hello"}],"tools":[{"name":"lookup","input_schema":{"type":"object","properties":{}}}],"tool_choice":{"type":"auto","disable_parallel_tool_use":true},"thinking":{"type":"adaptive"}}`} {
		request := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("anthropic-version", "2023-06-01")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != 200 || strings.Contains(response.Body.String(), "x_search_call") || strings.Contains(response.Body.String(), "tool_use\".*search") {
			t.Fatalf("response=%d %s", response.Code, response.Body.String())
		}
		if strings.Contains(body, "stream") && !strings.Contains(response.Body.String(), "message_stop") {
			t.Fatalf("stream=%s", response.Body.String())
		}
		if !strings.Contains(body, "stream") && !strings.Contains(response.Body.String(), `"stop_reason":"end_turn"`) {
			t.Fatalf("response=%s", response.Body.String())
		}
	}
}
func TestCountTokensHandlerStableAndValidates(t *testing.T) {
	body := `{"model":"grok","messages":[{"role":"user","content":"hello"}]}`
	var first string
	for range 2 {
		request := httptest.NewRequest(http.MethodPost, "/v1/messages/count_tokens", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("anthropic-version", "2023-06-01")
		response := httptest.NewRecorder()
		CountTokensHandler(response, request)
		if response.Code != 200 {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		if first == "" {
			first = response.Body.String()
		} else if response.Body.String() != first {
			t.Fatalf("unstable %s != %s", first, response.Body.String())
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/messages/count_tokens", strings.NewReader(`{"model":"grok","messages":[]} trailing`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("anthropic-version", "2023-06-01")
	response := httptest.NewRecorder()
	CountTokensHandler(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_request_error") {
		t.Fatalf("malformed status=%d body=%s", response.Code, response.Body.String())
	}
	missing := httptest.NewRequest(http.MethodPost, "/v1/messages/count_tokens", strings.NewReader(`{"messages":[]}`))
	missing.Header.Set("Content-Type", "application/json")
	missing.Header.Set("anthropic-version", "2023-06-01")
	missingResponse := httptest.NewRecorder()
	CountTokensHandler(missingResponse, missing)
	if missingResponse.Code != http.StatusBadRequest || !strings.Contains(missingResponse.Body.String(), "invalid_request_error") {
		t.Fatalf("missing model=%d %s", missingResponse.Code, missingResponse.Body.String())
	}
}

func TestMessagesMapsUnavailableModel(t *testing.T) {
	transform, _ := translate.NewRegistry().Get(registry.Anthropic)
	handler := MessagesHandler{Transform: transform, Execute: func(context.Context, routing.Request) (routing.Result, error) {
		return routing.Result{}, routing.ErrModelUnavailable
	}}
	request := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{"model":"missing","messages":[{"role":"user","content":"hi"}]}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("anthropic-version", "2023-06-01")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), "not_found_error") {
		t.Fatalf("response=%d %s", response.Code, response.Body.String())
	}
}
