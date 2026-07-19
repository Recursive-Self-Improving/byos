package anthropic

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"byos/internal/api"
	"byos/internal/provider"
	"byos/internal/routing"
	"byos/internal/translate"
	"byos/internal/translate/registry"
)

type fakeStream struct {
	events []provider.Event
	index  int
}

func (s *fakeStream) Next(context.Context) (provider.Event, error) {
	if s.index >= len(s.events) {
		return provider.Event{}, io.EOF
	}
	event := s.events[s.index]
	s.index++
	return event, nil
}
func (s *fakeStream) Close() error      { return nil }
func (s *fakeStream) Model() string     { return "grok-4.5" }
func (s *fakeStream) AccountID() string { return "acct" }
func anthropicCompleted() provider.Event {
	return provider.Event{Data: []byte(`{"type":"response.completed","response":{"id":"resp","status":"completed","output":[{"type":"x_search_call","id":"search"},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer https://x.com/post"}]}],"usage":{"input_tokens":2,"output_tokens":3}}}`)}
}
func TestMessagesHandlerContracts(t *testing.T) {
	transform, _ := translate.NewRegistry().Get(registry.Anthropic)
	execute := func(_ context.Context, request routing.Request) (routing.Result, error) {
		canonical := string(request.Body)
		if strings.Contains(canonical, `"effort"`) {
			t.Fatalf("unsupported reasoning effort forwarded: %s", canonical)
		}
		if strings.Contains(canonical, `"name":"lookup"`) && !strings.Contains(canonical, `"parallel_tool_calls":false`) {
			t.Fatalf("parallel tool choice lost: %s", canonical)
		}
		return routing.Result{Model: "grok-4.5", AccountID: "acct", Events: []provider.Event{anthropicCompleted()}}, nil
	}
	handler := MessagesHandler{Transform: transform, Execute: execute, OpenStream: func(context.Context, routing.Request) (api.RoutedStream, error) {
		return &fakeStream{events: []provider.Event{{Data: []byte(`{"type":"response.output_text.delta","delta":"hi"}`)}, anthropicCompleted()}}, nil
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
func TestMessagesHandlerPassesDevinCanonicalBodyUnchangedBeforeRouting(t *testing.T) {
	const body = `{"model":"swe-1-6-slow","messages":[{"role":"user","content":"news"}]}`
	transform, ok := translate.NewRegistry().Get(registry.Anthropic)
	if !ok {
		t.Fatal("transform not registered")
	}
	expected, err := transform.Request("swe-1-6-slow", []byte(body), false)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	handler := MessagesHandler{Transform: transform, Execute: func(_ context.Context, request routing.Request) (routing.Result, error) {
		called = true
		if request.Model != "swe-1-6-slow" || !bytes.Equal(request.Body, expected) {
			t.Fatalf("routing request model=%q body=%s, want unchanged body=%s", request.Model, request.Body, expected)
		}
		return routing.Result{}, routing.ErrModelUnavailable
	}}
	request := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("anthropic-version", "2023-06-01")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if !called {
		t.Fatal("routing was not called")
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
	searchPolicy := httptest.NewRequest(http.MethodPost, "/v1/messages/count_tokens", strings.NewReader(`{"model":"grok","messages":[{"role":"user","content":"hello"}],"tools":[{"name":"lookup","input_schema":{"type":"object"}}],"tool_choice":{"type":"none"}}`))
	searchPolicy.Header.Set("Content-Type", "application/json")
	searchPolicy.Header.Set("anthropic-version", "2023-06-01")
	searchPolicyResponse := httptest.NewRecorder()
	CountTokensHandler(searchPolicyResponse, searchPolicy)
	if searchPolicyResponse.Code != http.StatusOK || !strings.Contains(searchPolicyResponse.Body.String(), "input_tokens") {
		t.Fatalf("search policy status=%d body=%s", searchPolicyResponse.Code, searchPolicyResponse.Body.String())
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/messages/count_tokens", strings.NewReader(`{"model":"grok","messages":[]} trailing`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("anthropic-version", "2023-06-01")
	response := httptest.NewRecorder()
	CountTokensHandler(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_request_error") {
		t.Fatalf("malformed status=%d body=%s", response.Code, response.Body.String())
	}
	invalid := httptest.NewRequest(http.MethodPost, "/v1/messages/count_tokens", strings.NewReader(`{"model":"grok","messages":{}}`))
	invalid.Header.Set("Content-Type", "application/json")
	invalid.Header.Set("anthropic-version", "2023-06-01")
	invalidResponse := httptest.NewRecorder()
	CountTokensHandler(invalidResponse, invalid)
	if invalidResponse.Code != http.StatusBadRequest || !strings.Contains(invalidResponse.Body.String(), "messages must be an array") {
		t.Fatalf("invalid status=%d body=%s", invalidResponse.Code, invalidResponse.Body.String())
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
