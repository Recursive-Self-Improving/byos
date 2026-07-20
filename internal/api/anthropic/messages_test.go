package anthropic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"byos/internal/api"
	appcrypto "byos/internal/crypto"
	"byos/internal/provider"
	"byos/internal/routing"
	"byos/internal/store"
	"byos/internal/translate"
	"byos/internal/translate/registry"
)

func TestMessagesPublicErrorMetadata(t *testing.T) {
	classes := []provider.ErrorClass{
		provider.ClassValidation, provider.ClassUnauthorized, provider.ClassInvalidGrant,
		provider.ClassPermission, provider.ClassTransient, provider.ClassConnection,
		provider.ClassRateLimit, provider.ClassFreeUsageExhausted,
		provider.ClassCancelled, provider.ClassUpstream,
	}
	for _, class := range classes {
		t.Run(string(class), func(t *testing.T) {
			response := httptest.NewRecorder()
			api.AnthropicError(response, &routing.ExecutionError{Classified: provider.ErrorClassification{
				Class: class, PublicStatus: 418, PublicCode: "must_not_be_anthropic_type",
				PublicMessage: "sanitized message", ExplicitRetryAfter: true,
			}})
			var body struct {
				Type  string `json:"type"`
				Error struct {
					Type, Message string
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if response.Code != 418 || body.Type != "error" || body.Error.Message != "sanitized message" || body.Error.Type == "" || body.Error.Type == "must_not_be_anthropic_type" {
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

type anthropicPreparationCredentials struct{ calls int }

func (c *anthropicPreparationCredentials) Credential(context.Context, string) (provider.Credential, error) {
	c.calls++
	return provider.Credential{Value: "secret"}, nil
}

func (*anthropicPreparationCredentials) AuthenticationFailed(context.Context, string, *provider.UpstreamError) error {
	return nil
}

type anthropicPreparationClient struct{ calls int }

func (c *anthropicPreparationClient) Execute(context.Context, provider.GenerationRequest) ([]provider.Event, error) {
	c.calls++
	return nil, nil
}

func (c *anthropicPreparationClient) Stream(context.Context, provider.GenerationRequest) (provider.Stream, error) {
	c.calls++
	return nil, nil
}

type anthropicRejectingPolicy struct{}

func (anthropicRejectingPolicy) Prepare(context.Context, provider.ResolvedModel, provider.CanonicalRequest) error {
	return fmt.Errorf("internal policy detail: duplicate x_search: %w", &provider.UpstreamError{Provider: provider.XAI, Status: http.StatusBadRequest, Classification: provider.ErrorClassification{
		Class: provider.ClassValidation, PublicStatus: http.StatusBadRequest, PublicCode: "invalid_request_error", PublicMessage: "invalid request",
	}})
}

func TestMessagesRealExecutorPreparationErrorsUseExactAnthropicEnvelope(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{31}, 32))
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
	credentials := &anthropicPreparationCredentials{}
	client := &anthropicPreparationClient{}
	capabilities, err := provider.NewCapabilityRegistry([]provider.CapabilityRegistration{{Provider: provider.XAI, PolicyKey: "xai", Capabilities: provider.Capabilities{Policy: anthropicRejectingPolicy{}, Generation: client, Credentials: credentials}}})
	if err != nil {
		t.Fatal(err)
	}
	states := store.NewCooldownRepository(database.DB)
	executor := routing.NewExecutor(routing.NewScheduler(), models, capabilities, routing.NewCooldownManager(states, accounts), accounts, store.NewModelCapabilityRepository(database.DB), states)
	transform, ok := translate.NewRegistry().Get(registry.Anthropic)
	if !ok {
		t.Fatal("Anthropic transform missing")
	}
	handler := MessagesHandler{Transform: transform, Execute: executor.Execute, OpenStream: func(ctx context.Context, request routing.Request) (api.RoutedStream, error) {
		return executor.Stream(ctx, request)
	}}
	for _, test := range []struct {
		name, body, wantBody string
		status               int
	}{
		{name: "unknown nonstream", body: `{"model":"unknown","messages":[{"role":"user","content":"hello"}]}`, status: http.StatusNotFound, wantBody: "{\"error\":{\"message\":\"requested model is unavailable\",\"type\":\"not_found_error\"},\"type\":\"error\"}\n"},
		{name: "unknown stream", body: `{"model":"unknown","messages":[{"role":"user","content":"hello"}],"stream":true}`, status: http.StatusNotFound, wantBody: "{\"error\":{\"message\":\"requested model is unavailable\",\"type\":\"not_found_error\"},\"type\":\"error\"}\n"},
		{name: "policy invalid nonstream", body: `{"model":"grok","messages":[{"role":"user","content":"hello"}]}`, status: http.StatusBadRequest, wantBody: "{\"error\":{\"message\":\"invalid request\",\"type\":\"invalid_request_error\"},\"type\":\"error\"}\n"},
		{name: "policy invalid stream", body: `{"model":"grok","messages":[{"role":"user","content":"hello"}],"stream":true}`, status: http.StatusBadRequest, wantBody: "{\"error\":{\"message\":\"invalid request\",\"type\":\"invalid_request_error\"},\"type\":\"error\"}\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			credentialCalls, clientCalls := credentials.calls, client.calls
			request := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("anthropic-version", "2023-06-01")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || response.Body.String() != test.wantBody {
				t.Fatalf("status=%d body=%q, want status=%d body=%q", response.Code, response.Body.String(), test.status, test.wantBody)
			}
			if got := response.Header().Get("Content-Type"); got != "application/json" {
				t.Fatalf("Content-Type=%q, want application/json", got)
			}
			for _, header := range []string{"WWW-Authenticate", "Retry-After", "Cache-Control"} {
				if got := response.Header().Get(header); got != "" {
					t.Fatalf("%s=%q, want absent", header, got)
				}
			}
			if strings.Contains(response.Body.String(), "event:") || strings.Contains(response.Body.String(), "x_search") || strings.Contains(response.Body.String(), "tool_choice") {
				t.Fatalf("response leaked or committed SSE: %q", response.Body.String())
			}
			if credentials.calls != credentialCalls || client.calls != clientCalls {
				t.Fatalf("preparation reached credentials/client: credentials %d->%d client %d->%d", credentialCalls, credentials.calls, clientCalls, client.calls)
			}
		})
	}
}

type anthropicPostCommitFailureStream struct {
	calls int
	err   error
}

func (s *anthropicPostCommitFailureStream) Next(context.Context) (provider.Event, error) {
	s.calls++
	if s.calls == 1 {
		return provider.Event{Data: []byte(`{"type":"response.output_text.delta","delta":"hi"}`)}, nil
	}
	return provider.Event{}, s.err
}

func (*anthropicPostCommitFailureStream) Close() error      { return nil }
func (*anthropicPostCommitFailureStream) Model() string     { return "grok-4.5" }
func (*anthropicPostCommitFailureStream) AccountID() string { return "acct" }

func TestMessagesPostCommitStreamFailureContract(t *testing.T) {
	transform, _ := translate.NewRegistry().Get(registry.Anthropic)
	for _, test := range []struct {
		name      string
		err       error
		wantError bool
	}{
		{name: "failure", err: errors.New("sensitive upstream account token detail"), wantError: true},
		{name: "classified cancellation", err: &routing.ExecutionError{Classified: provider.ErrorClassification{Class: provider.ClassCancelled}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			stream := &anthropicPostCommitFailureStream{err: test.err}
			handler := MessagesHandler{Transform: transform, OpenStream: func(context.Context, routing.Request) (api.RoutedStream, error) { return stream, nil }}
			request := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{"model":"grok","messages":[{"role":"user","content":"hello"}],"stream":true}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("anthropic-version", "2023-06-01")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			body := response.Body.String()
			want := "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"stream terminated\"}}\n\n"
			if got := strings.Count(body, "event: error\n"); got != map[bool]int{false: 0, true: 1}[test.wantError] || (test.wantError && !strings.Contains(body, want)) {
				t.Fatalf("stream body=%q", body)
			}
			for _, secret := range []string{"sensitive", "upstream account", "token detail"} {
				if strings.Contains(body, secret) {
					t.Fatalf("stream leaked %q: %q", secret, body)
				}
			}
		})
	}
}
