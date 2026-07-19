package xai

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"byos/internal/provider"
	"byos/internal/search"
)

func TestRequestPolicyPrepare(t *testing.T) {
	model := provider.ResolvedModel{PublicName: "grok", UpstreamName: "grok-4.5", Provider: provider.XAI, OwnedBy: "byos", PolicyKey: "xai"}
	tests := []struct {
		name       string
		request    provider.CanonicalRequest
		wantChoice any
		wantErr    bool
	}{
		{name: "absent tools", request: provider.CanonicalRequest{"model": "grok"}},
		{name: "none becomes auto", request: provider.CanonicalRequest{"model": "grok", "tools": []any{}, "tool_choice": "none"}, wantChoice: "auto"},
		{name: "auto preserved", request: provider.CanonicalRequest{"model": "grok", "tool_choice": "auto"}, wantChoice: "auto"},
		{name: "required preserved", request: provider.CanonicalRequest{"model": "grok", "tool_choice": "required"}, wantChoice: "required"},
		{name: "selected function preserved", request: provider.CanonicalRequest{"model": "grok", "tools": []any{map[string]any{"type": "function", "name": "lookup"}}, "tool_choice": map[string]any{"type": "function", "name": "lookup"}}, wantChoice: map[string]any{"type": "function", "name": "lookup"}},
		{name: "duplicate search rejected", request: provider.CanonicalRequest{"model": "grok", "tools": []any{map[string]any{"type": "x_search"}, map[string]any{"type": "x_search"}}}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := (RequestPolicy{}).Prepare(context.Background(), model, test.request)
			if test.wantErr {
				var upstream *provider.UpstreamError
				if !errors.As(err, &upstream) || upstream.Provider != provider.XAI || upstream.Status != http.StatusBadRequest || upstream.Classification.Class != provider.ClassValidation || upstream.Classification.PublicStatus != http.StatusBadRequest || upstream.Classification.PublicCode != "invalid_request_error" || upstream.Classification.PublicMessage != "invalid request" {
					t.Fatalf("error = %#v", err)
				}
				if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "x_search") {
					t.Fatalf("error leaked validation details: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := search.Validate(test.request); err != nil {
				t.Fatalf("prepared request is invalid: %v", err)
			}
			request := test.request
			if request["model"] != "grok" {
				t.Fatalf("policy changed public model: %v", request["model"])
			}
			count := 0
			for _, raw := range request["tools"].([]any) {
				if raw.(map[string]any)["type"] == "x_search" {
					count++
				}
			}
			if count != 1 {
				t.Fatalf("x_search count = %d", count)
			}
			if test.wantChoice != nil {
				gotChoice, _ := json.Marshal(request["tool_choice"])
				wantChoice, _ := json.Marshal(test.wantChoice)
				if string(gotChoice) != string(wantChoice) {
					t.Fatalf("tool_choice = %s, want %s", gotChoice, wantChoice)
				}
			}
		})
	}
}

func TestRequestPolicyPreservesConfiguredSearch(t *testing.T) {
	tool := map[string]any{"type": "x_search", "allowed_x_handles": []any{"xai"}, "from_date": "2026-01-01", "enable_image_understanding": true}
	request := provider.CanonicalRequest{"model": "grok", "tools": []any{tool}}
	if err := (RequestPolicy{}).Prepare(context.Background(), provider.ResolvedModel{PublicName: "grok", Provider: provider.XAI}, request); err != nil {
		t.Fatal(err)
	}
	preparedTool := request["tools"].([]any)[0].(map[string]any)
	if preparedTool["from_date"] != "2026-01-01" || preparedTool["enable_image_understanding"] != true || preparedTool["allowed_x_handles"].([]any)[0] != "xai" {
		t.Fatalf("configured search changed: %#v", preparedTool)
	}
	if preparedTool["type"] != tool["type"] {
		t.Fatalf("caller-owned search tool changed: %#v", tool)
	}
}

func TestRequestPolicyRejectsInvalidCanonicalRequest(t *testing.T) {
	for name, request := range map[string]provider.CanonicalRequest{
		"nil request":     nil,
		"non-array tools": {"tools": map[string]any{}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := (RequestPolicy{}).Prepare(context.Background(), provider.ResolvedModel{}, request); err == nil {
				t.Fatalf("invalid request %#v accepted", request)
			}
		})
	}
}

var _ provider.RequestPolicy = RequestPolicy{}
