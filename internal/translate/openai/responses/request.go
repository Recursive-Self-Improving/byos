// Package responses implements the native OpenAI Responses compatibility path.
// Request normalization is adapted in part from CLIProxyAPI v7's
// codex/openai/responses translator (MIT License).
package responses

import (
	"encoding/json"
	"errors"

	"supergrok-api/internal/translate/common"
)

func Request(model string, body []byte, _ bool) ([]byte, error) {
	request, err := common.DecodeObject(body)
	if err != nil {
		return nil, err
	}
	if model != "" {
		request["model"] = model
	} else if common.String(request["model"]) == "" {
		return nil, errors.New("model is required")
	}
	switch input := request["input"].(type) {
	case string:
		request["input"] = []any{map[string]any{"type": "message", "role": "user", "content": []any{map[string]any{"type": "input_text", "text": input}}}}
	case []any:
		for _, raw := range input {
			item := common.Object(raw)
			if common.String(item["role"]) == "system" {
				item["role"] = "developer"
			}
		}
	case nil:
		return nil, errors.New("input is required")
	default:
		return nil, errors.New("input must be a string or array")
	}
	request["stream"] = true
	request["store"] = false
	request["parallel_tool_calls"] = true
	request["include"] = mergeInclude(common.Array(request["include"]), "reasoning.encrypted_content")
	for _, field := range []string{"max_output_tokens", "max_completion_tokens", "temperature", "top_p", "truncation", "user", "context_management"} {
		delete(request, field)
	}
	if tier := common.String(request["service_tier"]); tier != "" && tier != "priority" {
		delete(request, "service_tier")
	}
	return json.Marshal(request)
}
func mergeInclude(values []any, want string) []any {
	for _, v := range values {
		if common.String(v) == want {
			return values
		}
	}
	return append(values, want)
}
func ConvertOpenAIResponsesRequestToCodex(model string, body []byte, stream bool) []byte {
	out, _ := Request(model, body, stream)
	return out
}
