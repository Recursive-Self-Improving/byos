// Package chatcompletions translates OpenAI Chat Completions to canonical Responses.
// Portions of the transformation behavior are adapted from CLIProxyAPI v7's
// codex/openai/chat-completions translator (MIT License).
package chatcompletions

import (
	"encoding/json"
	"errors"

	"byoo/internal/translate/common"
)

func Request(model string, body []byte, stream bool) ([]byte, error) {
	request, err := common.DecodeObject(body)
	if err != nil {
		return nil, err
	}
	messages, ok := request["messages"].([]any)
	if !ok {
		return nil, errors.New("messages must be an array")
	}
	if value := common.String(request["model"]); model == "" {
		model = value
	}
	out := map[string]any{"model": model, "input": []any{}, "stream": stream, "store": false, "parallel_tool_calls": true, "include": []any{"reasoning.encrypted_content"}}
	input := make([]any, 0, len(messages))
	forward, _ := common.ToolNames(request, false)
	for _, rawMessage := range messages {
		message := common.Object(rawMessage)
		role := common.String(message["role"])
		if role == "" {
			return nil, errors.New("message role is required")
		}
		if role == "tool" {
			input = append(input, map[string]any{"type": "function_call_output", "call_id": common.String(message["tool_call_id"]), "output": toolOutput(message["content"])})
			continue
		}
		if role == "system" {
			role = "developer"
		}
		parts, err := chatContent(role, message["content"])
		if err != nil {
			return nil, err
		}
		if len(parts) > 0 {
			input = append(input, map[string]any{"type": "message", "role": role, "content": parts})
		}
		if role == "assistant" {
			for _, rawCall := range common.Array(message["tool_calls"]) {
				call := common.Object(rawCall)
				function := common.Object(call["function"])
				if common.String(call["type"]) != "function" {
					continue
				}
				name := common.String(function["name"])
				if short := forward[name]; short != "" {
					name = short
				} else {
					name = common.ShortName(name)
				}
				input = append(input, map[string]any{"type": "function_call", "call_id": common.String(call["id"]), "name": name, "arguments": common.String(function["arguments"])})
			}
		}
	}
	out["input"] = input
	if tools := common.Array(request["tools"]); len(tools) > 0 {
		converted := make([]any, 0, len(tools))
		for _, rawTool := range tools {
			tool := common.Object(rawTool)
			function := common.Object(tool["function"])
			if common.String(tool["type"]) != "function" || function == nil {
				continue
			}
			name := common.String(function["name"])
			if short := forward[name]; short != "" {
				name = short
			}
			item := map[string]any{"type": "function", "name": name}
			common.CopyFields(item, function, "description", "parameters", "strict")
			converted = append(converted, item)
		}
		out["tools"] = converted
	}
	convertToolChoice(out, request["tool_choice"], forward)
	reasoning := map[string]any{"summary": "auto"}
	if effort, ok := request["reasoning_effort"]; ok {
		reasoning["effort"] = effort
	}
	out["reasoning"] = reasoning
	if format := common.Object(request["response_format"]); format != nil {
		canonical := map[string]any{"type": common.String(format["type"])}
		if schema := common.Object(format["json_schema"]); schema != nil {
			canonical = map[string]any{"type": "json_schema"}
			common.CopyFields(canonical, schema, "name", "schema", "strict", "description")
		}
		out["text"] = map[string]any{"format": canonical}
	}
	common.CopyFields(out, request, "metadata", "stop")
	return json.Marshal(out)
}

func ConvertOpenAIRequestToCodex(model string, body []byte, stream bool) []byte {
	out, _ := Request(model, body, stream)
	return out
}

func chatContent(role string, content any) ([]any, error) {
	partType := "input_text"
	if role == "assistant" {
		partType = "output_text"
	}
	if text, ok := content.(string); ok {
		if text == "" {
			return nil, nil
		}
		return []any{map[string]any{"type": partType, "text": text}}, nil
	}
	if content == nil {
		return nil, nil
	}
	items, ok := content.([]any)
	if !ok {
		return nil, errors.New("message content must be a string or array")
	}
	parts := make([]any, 0, len(items))
	for _, raw := range items {
		part := common.Object(raw)
		switch common.String(part["type"]) {
		case "text":
			parts = append(parts, map[string]any{"type": partType, "text": common.String(part["text"])})
		case "image_url":
			if role == "user" {
				image := common.Object(part["image_url"])
				item := map[string]any{"type": "input_image", "image_url": common.String(image["url"])}
				common.CopyFields(item, image, "detail")
				parts = append(parts, item)
			}
		case "input_audio":
			if role == "user" {
				audio := common.Object(part["input_audio"])
				parts = append(parts, map[string]any{"type": "input_audio", "data": audio["data"], "format": audio["format"]})
			}
		case "file":
			if role == "user" {
				file := common.Object(part["file"])
				item := map[string]any{"type": "input_file"}
				common.CopyFields(item, file, "file_data", "file_id", "filename")
				parts = append(parts, item)
			}
		}
	}
	return parts, nil
}

func toolOutput(value any) any {
	if text, ok := value.(string); ok {
		return text
	}
	if array, ok := value.([]any); ok {
		return array
	}
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func convertToolChoice(out map[string]any, raw any, names map[string]string) {
	if text, ok := raw.(string); ok {
		out["tool_choice"] = text
		return
	}
	choice := common.Object(raw)
	function := common.Object(choice["function"])
	if common.String(choice["type"]) == "function" && function != nil {
		name := common.String(function["name"])
		if short := names[name]; short != "" {
			name = short
		}
		out["tool_choice"] = map[string]any{"type": "function", "name": name}
	}
}
