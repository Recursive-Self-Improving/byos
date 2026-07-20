package devin

import (
	"reflect"
	"strings"
	"testing"

	"byos/internal/devin/proto"
	"byos/internal/provider"
)

func TestBuildChatRequestPreservesCanonicalHistoryAndDefaults(t *testing.T) {
	canonical := provider.CanonicalRequest{
		"model": "claude-sonnet-4-5",
		"input": []any{
			map[string]any{"type": "message", "role": "developer", "content": []any{map[string]any{"type": "input_text", "text": "rules"}}},
			map[string]any{"type": "message", "role": "user", "id": "user-1", "content": []any{map[string]any{"type": "input_text", "text": "look"}, map[string]any{"type": "input_image", "image_url": "data:image/png;base64,AA=="}}},
			map[string]any{"type": "message", "role": "system", "id": "system-1", "content": []any{map[string]any{"type": "input_text", "text": "policy"}}},
			map[string]any{"type": "reasoning", "id": "reason-1", "summary": []any{map[string]any{"type": "summary_text", "text": "plan"}}, "encrypted_content": "sig"},
			map[string]any{"type": "message", "role": "assistant", "id": "assistant-1", "content": []any{map[string]any{"type": "output_text", "text": "calling"}}},
			map[string]any{"type": "function_call", "id": "output-1", "call_id": "call-1", "name": "lookup", "arguments": `{"q":"x"}`},
			map[string]any{"type": "function_call_output", "id": "result-1", "call_id": "call-1", "output": []any{map[string]any{"type": "input_text", "text": "ok"}, map[string]any{"type": "input_image", "image_url": "data:image/jpeg;base64,/9g="}}},
		},
		"tools": []any{map[string]any{"type": "function", "name": "lookup", "description": "Lookup", "parameters": map[string]any{"type": "object"}, "strict": true}},
		"stop":  []any{"END"},
	}
	got, err := BuildChatRequest(canonical, "devin-session-token$session", "jwt")
	if err != nil {
		t.Fatal(err)
	}
	if got.ChatModelUID != "claude-sonnet-4-5" || got.Prompt != "rules\n\npolicy" {
		t.Fatalf("model/prompt changed: %#v", got)
	}
	if got.Metadata.APIKey != "devin-session-token$session" || got.Metadata.UserJWT != "jwt" {
		t.Fatal("metadata credentials changed")
	}
	if got.RequestType != proto.ChatMessageRequestTypeCascade || got.ProviderSource != proto.ProviderSourceCascade || got.PlannerMode != proto.ConversationalPlannerModeDefault {
		t.Fatal("Devin enums not locked")
	}
	if !got.DisableParallelToolCalls || got.ToolChoice.OptionName != "auto" {
		t.Fatal("tool defaults not locked")
	}
	wantConfig := &proto.CompletionConfiguration{NumCompletions: 1, MaxTokens: 64000, MaxNewlines: 200, Temperature: .4, FirstTemperature: .4, TopK: 50, TopP: 1, StopPatterns: append(append([]string{}, defaultStopPatterns...), "END"), FIMEOTProbabilityThreshold: 1}
	if !reflect.DeepEqual(got.Configuration, wantConfig) {
		t.Fatalf("configuration=%#v", got.Configuration)
	}
	if len(got.ChatMessagePrompts) != 7 {
		t.Fatalf("prompts=%#v", got.ChatMessagePrompts)
	}
	developer, user, system, reasoning, assistant, call, result := got.ChatMessagePrompts[0], got.ChatMessagePrompts[1], got.ChatMessagePrompts[2], got.ChatMessagePrompts[3], got.ChatMessagePrompts[4], got.ChatMessagePrompts[5], got.ChatMessagePrompts[6]
	if developer.Source != proto.ChatMessageSourceUser || developer.Prompt != "rules" || developer.PromptCacheOptions != nil {
		t.Fatalf("developer=%#v", developer)
	}
	if user.MessageID != "user-1" || user.Source != proto.ChatMessageSourceUser || user.Prompt != "look" || len(user.Images) != 1 || user.Images[0].Base64Data != "AA==" || user.Images[0].MIMEType != "image/png" {
		t.Fatalf("user=%#v", user)
	}
	if system.MessageID != "system-1" || system.Source != proto.ChatMessageSourceSystemPrompt || system.Prompt != "policy" || system.PromptCacheOptions == nil || system.PromptCacheOptions.Type != proto.CacheControlTypeEphemeral {
		t.Fatalf("system=%#v", system)
	}
	if reasoning.MessageID != "reason-1" || reasoning.Thinking != "plan" || reasoning.Signature != "sig" {
		t.Fatalf("reasoning=%#v", reasoning)
	}
	if assistant.MessageID != "assistant-1" || assistant.Source != proto.ChatMessageSourceSystem || assistant.Prompt != "calling" {
		t.Fatalf("assistant=%#v", assistant)
	}
	if call.ToolCalls[0].ID != "call-1" || call.ToolCalls[0].Name != "lookup" || call.ToolCalls[0].ArgumentsJSON != `{"q":"x"}` || call.OutputID != "output-1" {
		t.Fatalf("call=%#v", call)
	}
	if result.ToolCallID != "call-1" || result.Prompt != "ok" || result.OutputID != "result-1" || len(result.Images) != 1 {
		t.Fatalf("result=%#v", result)
	}
	if len(got.Tools) != 1 || got.Tools[0].Name != "lookup" || got.Tools[0].JSONSchemaString != `{"type":"object"}` || !got.Tools[0].Strict {
		t.Fatalf("tools=%#v", got.Tools)
	}
	again, err := BuildChatRequest(canonical, "other-session", "other-jwt")
	if err != nil {
		t.Fatal(err)
	}
	if got.CascadeID != again.CascadeID || got.ExecutionID != again.ExecutionID {
		t.Fatal("structural IDs depend on credentials or are unstable")
	}
}

func TestBuildChatRequestToolChoicesAcrossTranslatorShapes(t *testing.T) {
	base := func() provider.CanonicalRequest {
		return provider.CanonicalRequest{"model": "model", "input": []any{}, "tools": []any{map[string]any{"type": "function", "name": "exact_name", "parameters": map[string]any{"type": "object"}}}}
	}
	cases := []struct {
		name         string
		choice       any
		option, tool string
		wantErr      string
	}{
		{"omitted", nil, "auto", "", ""}, {"auto", "auto", "auto", "", ""}, {"none", "none", "none", "", ""},
		{"selected", map[string]any{"type": "function", "name": "exact_name"}, "", "exact_name", ""},
		{"required", "required", "", "", "required is not supported"}, {"unknown", "sometimes", "", "", "unsupported tool choice"},
		{"malformed object", map[string]any{"type": "function"}, "", "", "malformed selected tool choice"},
		{"undefined selected", map[string]any{"type": "function", "name": "missing"}, "", "", "is not defined"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request := base()
			if test.choice != nil {
				request["tool_choice"] = test.choice
			}
			got, err := BuildChatRequest(request, "session", "jwt")
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("err=%v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.ToolChoice.OptionName != test.option || got.ToolChoice.ToolName != test.tool || !got.DisableParallelToolCalls {
				t.Fatalf("choice=%#v parallel=%v", got.ToolChoice, got.DisableParallelToolCalls)
			}
		})
	}
}

func TestBuildChatRequestRejectsRemoteAndMalformedImages(t *testing.T) {
	for _, image := range []string{"https://example.com/image.png", "data:image/png;base64,***"} {
		_, err := BuildChatRequest(provider.CanonicalRequest{"model": "model", "input": []any{map[string]any{"type": "message", "role": "user", "content": []any{map[string]any{"type": "input_image", "image_url": image}}}}}, "session", "jwt")
		if err == nil {
			t.Fatalf("accepted image %q", image)
		}
	}
}
