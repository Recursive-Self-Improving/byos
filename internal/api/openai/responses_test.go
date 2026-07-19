package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"byos/internal/api"
	appcrypto "byos/internal/crypto"
	"byos/internal/provider"
	"byos/internal/routing"
	"byos/internal/sessions"
	"byos/internal/store"
	"byos/internal/translate"
	"byos/internal/translate/registry"
	"byos/internal/xai"
)

func TestResponsesPublicErrorMetadata(t *testing.T) {
	classes := []provider.ErrorClass{
		provider.ClassValidation, provider.ClassUnauthorized, provider.ClassInvalidGrant,
		provider.ClassPermission, provider.ClassTransient, provider.ClassConnection,
		provider.ClassRateLimit, provider.ClassFreeUsageExhausted,
		provider.ClassCancelled, provider.ClassUpstream,
	}
	for _, class := range classes {
		t.Run(string(class), func(t *testing.T) {
			response := httptest.NewRecorder()
			api.OpenAIError(response, &routing.ExecutionError{Classified: provider.ErrorClassification{
				Class: class, PublicStatus: 418, PublicCode: "sanitized_code",
				PublicMessage: "sanitized message", ExplicitRetryAfter: true,
			}})
			var body struct {
				Error struct {
					Type, Code, Message string
					Param               any
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if response.Code != 418 || body.Error.Code != "sanitized_code" || body.Error.Message != "sanitized message" || body.Error.Type == "" || body.Error.Param != nil {
				t.Fatalf("response=%d body=%s", response.Code, response.Body.String())
			}
			if got := response.Header().Get("Retry-After"); got != "0" {
				t.Fatalf("Retry-After=%q, want 0", got)
			}
			if response.Header().Get("WWW-Authenticate") != "" {
				t.Fatal("upstream error acquired client-auth header")
			}
		})
	}
}

type preparationCredentials struct{ calls int }

func (c *preparationCredentials) Credential(context.Context, string) (provider.Credential, error) {
	c.calls++
	return provider.Credential{Value: "secret"}, nil
}
func (*preparationCredentials) AuthenticationFailed(context.Context, string, *provider.UpstreamError) error {
	return nil
}

type preparationClient struct{ calls int }

func (c *preparationClient) Execute(context.Context, provider.GenerationRequest) ([]provider.Event, error) {
	c.calls++
	return nil, nil
}
func (c *preparationClient) Stream(context.Context, provider.GenerationRequest) (provider.Stream, error) {
	c.calls++
	return nil, nil
}

func TestResponsesRealExecutorRejectsPreparationErrorsWithoutSideEffects(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{29}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accounts := store.NewAccountRepository(database.DB, keys)
	if _, err := accounts.UpsertLogin(ctx, store.Account{Provider: provider.XAI, Label: "x", Status: "ready", Credentials: store.AccountCredentials{Issuer: "issuer", Subject: "subject", AccessToken: "token"}}); err != nil {
		t.Fatal(err)
	}
	models, err := provider.NewStaticModelCatalog([]provider.ResolvedModel{{PublicName: "grok", UpstreamName: "grok-4.5", Provider: provider.XAI, OwnedBy: "xai", PolicyKey: "xai"}})
	if err != nil {
		t.Fatal(err)
	}
	credentials := &preparationCredentials{}
	client := &preparationClient{}
	capabilities, err := provider.NewCapabilityRegistry([]provider.CapabilityRegistration{{Provider: provider.XAI, PolicyKey: "xai", Capabilities: provider.Capabilities{Policy: xai.RequestPolicy{}, Generation: client, Credentials: credentials}}})
	if err != nil {
		t.Fatal(err)
	}
	states := store.NewCooldownRepository(database.DB)
	executor := routing.NewExecutor(routing.NewScheduler(), models, capabilities, routing.NewCooldownManager(states, accounts), accounts, store.NewModelCapabilityRepository(database.DB), states)
	transform, ok := translate.NewRegistry().Get(registry.OpenAIResponses)
	if !ok {
		t.Fatal("Responses transform missing")
	}
	handler := ResponsesHandler{
		Transform: transform,
		Execute:   executor.Execute,
		OpenStream: func(ctx context.Context, request routing.Request) (api.RoutedStream, error) {
			return executor.Stream(ctx, request)
		},
		Sessions: sessions.NewService(store.NewResponseRepository(database.DB, keys)),
	}
	for _, test := range []struct {
		name, body, errorType, code, message string
		status                               int
	}{
		{name: "unknown model", body: `{"model":"unknown","input":"hello"}`, status: http.StatusNotFound, errorType: "invalid_request_error", code: "model_not_found", message: "requested model is unavailable"},
		{name: "duplicate x search", body: `{"model":"grok","input":"hello","tools":[{"type":"x_search"},{"type":"x_search"}]}`, status: http.StatusBadRequest, errorType: "invalid_request_error", code: "invalid_request_error", message: "invalid request"},
	} {
		for _, stream := range []bool{false, true} {
			t.Run(test.name+map[bool]string{false: "/nonstream", true: "/stream"}[stream], func(t *testing.T) {
				credentialCalls, clientCalls := credentials.calls, client.calls
				body := test.body
				if stream {
					body = strings.TrimSuffix(body, "}") + `,"stream":true}`
				}
				request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				var got map[string]any
				if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
					t.Fatalf("decode response: %v; body=%s", err, response.Body.String())
				}
				want := map[string]any{"error": map[string]any{"type": test.errorType, "code": test.code, "message": test.message, "param": nil}}
				if response.Code != test.status || !reflect.DeepEqual(got, want) {
					t.Fatalf("status=%d body=%s, want status=%d body=%v", response.Code, response.Body.String(), test.status, want)
				}
				if got := response.Header().Get("Content-Type"); got != "application/json" {
					t.Fatalf("Content-Type=%q, want application/json before SSE commitment", got)
				}
				if got := response.Header().Get("WWW-Authenticate"); got != "" {
					t.Fatalf("WWW-Authenticate=%q, want absent", got)
				}
				if got := response.Header().Get("Retry-After"); got != "" {
					t.Fatalf("Retry-After=%q, want absent", got)
				}
				if credentials.calls != credentialCalls || client.calls != clientCalls {
					t.Fatalf("speculative access: credentials %d->%d client %d->%d", credentialCalls, credentials.calls, clientCalls, client.calls)
				}
			})
		}
	}
}

func TestResponsesContinuationCarriesManagedAccountAffinity(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{30}, 32))
	if err != nil {
		t.Fatal(err)
	}
	service := sessions.NewService(store.NewResponseRepository(database.DB, keys))
	if err := service.PersistCompleted(ctx, sessions.CompletedNode{ResponseID: "resp_parent", UpstreamResponseID: "resp_parent", Model: "grok-4.5", AccountID: "acct_preferred", CanonicalInput: []byte(`{"input":"hello"}`), TerminalOutput: []byte(`{"id":"resp_parent","output":[]}`)}, true); err != nil {
		t.Fatal(err)
	}
	transform, ok := translate.NewRegistry().Get(registry.OpenAIResponses)
	if !ok {
		t.Fatal("Responses transform missing")
	}
	for _, streamMode := range []bool{false, true} {
		t.Run(map[bool]string{false: "execute", true: "stream"}[streamMode], func(t *testing.T) {
			var routed routing.Request
			handler := ResponsesHandler{Transform: transform, Sessions: service}
			handler.Execute = func(_ context.Context, request routing.Request) (routing.Result, error) {
				routed = request
				return routing.Result{Model: "grok-4.5", AccountID: "acct_preferred", Events: []provider.Event{completedEvent()}}, nil
			}
			handler.OpenStream = func(_ context.Context, request routing.Request) (api.RoutedStream, error) {
				routed = request
				return &fakeStream{model: "grok-4.5", account: "acct_preferred", events: []provider.Event{completedEvent()}}, nil
			}
			body := `{"model":"grok","previous_response_id":"resp_parent","input":"again"`
			if streamMode {
				body += `,"stream":true,"store":false`
			}
			body += `}`
			request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if routed.PreferredAccountID != "acct_preferred" {
				t.Fatalf("preferred account=%q", routed.PreferredAccountID)
			}
		})
	}
}

type responsesPostCommitFailureStream struct {
	calls  int
	cancel context.CancelFunc
	err    error
}

func (s *responsesPostCommitFailureStream) Next(context.Context) (provider.Event, error) {
	s.calls++
	if s.calls == 1 {
		return provider.Event{Data: []byte(`{"type":"response.output_text.delta","delta":"hi","sequence_number":7}`)}, nil
	}
	if s.cancel != nil {
		s.cancel()
	}
	if s.err != nil {
		return provider.Event{}, s.err
	}
	return provider.Event{}, errors.New("sensitive upstream account token detail")
}

func (*responsesPostCommitFailureStream) Close() error      { return nil }
func (*responsesPostCommitFailureStream) Model() string     { return "grok-4.5" }
func (*responsesPostCommitFailureStream) AccountID() string { return "acct" }

func TestResponsesPostCommitStreamFailureEmitsOneSanitizedError(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{32}, 32))
	if err != nil {
		t.Fatal(err)
	}
	transform, _ := translate.NewRegistry().Get(registry.OpenAIResponses)
	stream := &responsesPostCommitFailureStream{}
	handler := ResponsesHandler{
		Transform:  transform,
		OpenStream: func(context.Context, routing.Request) (api.RoutedStream, error) { return stream, nil },
		Sessions:   sessions.NewService(store.NewResponseRepository(database.DB, keys)),
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"grok","input":"hello","stream":true}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	body := response.Body.String()
	want := "event: error\ndata: {\"type\":\"error\",\"code\":\"server_error\",\"message\":\"stream terminated\",\"param\":null,\"sequence_number\":8}\n\n"
	if strings.Count(body, "event: error\n") != 1 || !strings.Contains(body, want) {
		t.Fatalf("stream body=%q, want exactly one sanitized error event", body)
	}
	for _, secret := range []string{"sensitive", "upstream account", "token detail"} {
		if strings.Contains(body, secret) {
			t.Fatalf("stream leaked %q: %q", secret, body)
		}
	}
}

func TestResponsesPostCommitCancellationEmitsNoError(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{33}, 32))
	if err != nil {
		t.Fatal(err)
	}
	transform, _ := translate.NewRegistry().Get(registry.OpenAIResponses)
	for _, test := range []struct {
		name    string
		stream  *responsesPostCommitFailureStream
		context context.Context
	}{
		{name: "classified", stream: &responsesPostCommitFailureStream{err: &routing.ExecutionError{Classified: provider.ErrorClassification{Class: provider.ClassCancelled}}}, context: context.Background()},
		{name: "request context", context: func() context.Context {
			requestContext, cancel := context.WithCancel(context.Background())
			returnContext := requestContext
			_ = returnContext
			return requestContextWithCancelStream(requestContext, cancel)
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			stream := test.stream
			requestContext := test.context
			if stream == nil {
				cancelContext := requestContext.(*cancelStreamContext)
				stream = &responsesPostCommitFailureStream{cancel: cancelContext.cancel}
				requestContext = cancelContext.Context
			}
			handler := ResponsesHandler{
				Transform:  transform,
				OpenStream: func(context.Context, routing.Request) (api.RoutedStream, error) { return stream, nil },
				Sessions:   sessions.NewService(store.NewResponseRepository(database.DB, keys)),
			}
			request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"grok","input":"hello","stream":true}`)).WithContext(requestContext)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if body := response.Body.String(); strings.Contains(body, "event: error") || !strings.Contains(body, "response.output_text.delta") {
				t.Fatalf("cancelled stream body=%q", body)
			}
		})
	}
}

type cancelStreamContext struct {
	context.Context
	cancel context.CancelFunc
}

func requestContextWithCancelStream(ctx context.Context, cancel context.CancelFunc) context.Context {
	return &cancelStreamContext{Context: ctx, cancel: cancel}
}
