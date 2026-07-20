package errors

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"byos/internal/provider"
	"byos/internal/routing"
	"byos/internal/sessions"
)

func TestSemanticMappings(t *testing.T) {
	kinds := []Kind{Validation, Authentication, ModelUnavailable, Cooldown, ContextLimit, PreviousResponseNotFound, UpstreamFailure, InternalFailure}
	for _, kind := range kinds {
		openai := OpenAI(kind, 1500*time.Millisecond)
		if openai.Status == 0 || openai.Type == "" || openai.Message == "" {
			t.Fatalf("OpenAI %s = %+v", kind, openai)
		}
		anthropic := Anthropic(kind, 1500*time.Millisecond)
		if anthropic.Status == 0 || anthropic.Type == "" || anthropic.Message == "" {
			t.Fatalf("Anthropic %s = %+v", kind, anthropic)
		}
	}
	if KindOf(sessions.ErrContextLengthExceeded) != ContextLimit || KindOf(sessions.ErrPreviousResponseNotFound) != PreviousResponseNotFound {
		t.Fatal("session error mapping failed")
	}
	if KindOf(routing.ErrModelUnavailable) != ModelUnavailable || KindOf(routing.ErrNoAvailableAccounts) != ModelUnavailable {
		t.Fatal("model unavailable mapping failed")
	}
	rateLimit := provider.ErrorClassification{Class: provider.ClassRateLimit}
	connection := provider.ErrorClassification{Class: provider.ClassConnection}
	if FromClassification(rateLimit) != Cooldown || FromClassification(connection) != UpstreamFailure {
		t.Fatal("provider classification mapping failed")
	}
	upstream := &provider.UpstreamError{Provider: provider.XAI, Status: 429, Classification: rateLimit}
	if KindOf(upstream) != Cooldown {
		t.Fatal("provider upstream error mapping failed")
	}
}
func TestExactProtocolFixtures(t *testing.T) {
	openAIResponse := httptest.NewRecorder()
	WriteOpenAI(openAIResponse, OpenAI(PreviousResponseNotFound, 0))
	var openAIBody map[string]any
	if err := json.Unmarshal(openAIResponse.Body.Bytes(), &openAIBody); err != nil {
		t.Fatal(err)
	}
	wantOpenAI := map[string]any{"error": map[string]any{"type": "invalid_request_error", "code": "previous_response_not_found", "message": "previous response was not found or has expired", "param": nil}}
	if !reflect.DeepEqual(openAIBody, wantOpenAI) {
		t.Fatalf("OpenAI body=%v", openAIBody)
	}
	anthropicResponse := httptest.NewRecorder()
	WriteAnthropic(anthropicResponse, Anthropic(Authentication, 0))
	var anthropicBody map[string]any
	if err := json.Unmarshal(anthropicResponse.Body.Bytes(), &anthropicBody); err != nil {
		t.Fatal(err)
	}
	wantAnthropic := map[string]any{"type": "error", "error": map[string]any{"type": "authentication_error", "message": "invalid authentication credentials"}}
	if !reflect.DeepEqual(anthropicBody, wantAnthropic) {
		t.Fatalf("Anthropic body=%v", anthropicBody)
	}
}
func TestRetryAfterUsesCeiling(t *testing.T) {
	for _, test := range []struct {
		duration time.Duration
		want     string
	}{{time.Nanosecond, "1"}, {500 * time.Millisecond, "1"}, {1100 * time.Millisecond, "2"}, {2 * time.Second, "2"}} {
		for _, writer := range []func(*httptest.ResponseRecorder){func(w *httptest.ResponseRecorder) { WriteOpenAI(w, OpenAI(Cooldown, test.duration)) }, func(w *httptest.ResponseRecorder) { WriteAnthropic(w, Anthropic(Cooldown, test.duration)) }} {
			response := httptest.NewRecorder()
			writer(response)
			if got := response.Header().Get("Retry-After"); got != test.want {
				t.Fatalf("duration %v Retry-After=%s want %s", test.duration, got, test.want)
			}
		}
	}
}
func TestMappingsNeverCopyInternalErrorText(t *testing.T) {
	secret := "oauth-token account@example.com /private/sqlite upstream-body"
	_ = secret
	for _, kind := range []Kind{UpstreamFailure, InternalFailure, Authentication} {
		if OpenAI(kind, 0).Message == secret || Anthropic(kind, 0).Message == secret {
			t.Fatal("mapping copied internal text")
		}
	}
}

func TestClassificationPublicMetadata(t *testing.T) {
	classes := []provider.ErrorClass{
		provider.ClassValidation,
		provider.ClassUnauthorized,
		provider.ClassInvalidGrant,
		provider.ClassPermission,
		provider.ClassTransient,
		provider.ClassConnection,
		provider.ClassRateLimit,
		provider.ClassFreeUsageExhausted,
		provider.ClassCancelled,
		provider.ClassUpstream,
	}
	for _, class := range classes {
		t.Run(string(class), func(t *testing.T) {
			classified := provider.ErrorClassification{Class: class, PublicStatus: 418, PublicCode: "sanitized_code", PublicMessage: "sanitized message"}
			openai := OpenAIClassification(classified, 3*time.Second)
			if openai.Status != 418 || openai.Code != "sanitized_code" || openai.Message != "sanitized message" {
				t.Fatalf("OpenAI classification lost metadata: %+v", openai)
			}
			anthropic := AnthropicClassification(classified, 3*time.Second)
			if anthropic.Status != 418 || anthropic.Message != "sanitized message" {
				t.Fatalf("Anthropic classification lost metadata: %+v", anthropic)
			}
			if openai.Type == "" || anthropic.Type == "" {
				t.Fatalf("protocol type lost: OpenAI=%+v Anthropic=%+v", openai, anthropic)
			}
		})
	}
}

func TestClassificationAbsentPublicMetadataUsesSanitizedDefaults(t *testing.T) {
	for _, class := range []provider.ErrorClass{provider.ClassValidation, provider.ClassUnauthorized, provider.ClassRateLimit, provider.ClassPermission, provider.ClassCancelled, provider.ClassUpstream} {
		classified := provider.ErrorClassification{Class: class}
		openai := OpenAIClassification(classified, 0)
		anthropic := AnthropicClassification(classified, 0)
		if openai.Status == 0 || openai.Code == "" || openai.Message == "" || anthropic.Status == 0 || anthropic.Message == "" {
			t.Fatalf("class %q did not receive defaults: OpenAI=%+v Anthropic=%+v", class, openai, anthropic)
		}
	}
}
