// Package anthropic translates Anthropic Messages to canonical Responses.
// The protocol mapping is adapted in part from CLIProxyAPI v7's codex/claude
// translator (MIT License), with server-side search intentionally kept internal.
package anthropic

import (
	"encoding/json"
	"errors"
	"fmt"

	"byos/internal/translate/common"
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
	if model == "" {
		model = common.String(request["model"])
	}
	if model == "" {
		return nil, errors.New("model is required")
	}
	out := map[string]any{"model": model, "input": []any{}, "stream": stream, "store": false, "parallel_tool_calls": true, "include": []any{"reasoning.encrypted_content"}}
	input := make([]any, 0, len(messages)+1)
	if systemParts, err := anthropicSystem(request["system"]); err != nil {
		return nil, err
	} else if len(systemParts) > 0 {
		input = append(input, map[string]any{"type": "message", "role": "developer", "content": systemParts})
	}
	forward, _ := common.ToolNames(request, true)
	for _, rawMessage := range messages {
		message := common.Object(rawMessage)
		role := common.String(message["role"])
		if role != "user" && role != "assistant" {
			return nil, errors.New("message role must be user or assistant")
		}
		blocks := message["content"]
		if text, ok := blocks.(string); ok {
			kind := "input_text"
			if role == "assistant" {
				kind = "output_text"
			}
			input = append(input, map[string]any{"type": "message", "role": role, "content": []any{map[string]any{"type": kind, "text": text}}})
			continue
		}
		array, ok := blocks.([]any)
		if !ok {
			return nil, errors.New("message content must be a string or array")
		}
		parts := make([]any, 0)
		flush := func() {
			if len(parts) > 0 {
				input = append(input, map[string]any{"type": "message", "role": role, "content": parts})
				parts = nil
			}
		}
		for _, rawBlock := range array {
			block := common.Object(rawBlock)
			switch common.String(block["type"]) {
			case "text":
				kind := "input_text"
				if role == "assistant" {
					kind = "output_text"
				}
				parts = append(parts, map[string]any{"type": kind, "text": common.String(block["text"])})
			case "image":
				if role == "user" {
					source := common.Object(block["source"])
					if common.String(source["type"]) == "base64" {
						parts = append(parts, map[string]any{"type": "input_image", "image_url": fmt.Sprintf("data:%s;base64,%s", common.String(source["media_type"]), common.String(source["data"]))})
					} else if url := common.String(source["url"]); url != "" {
						parts = append(parts, map[string]any{"type": "input_image", "image_url": url})
					}
				}
			case "thinking":
				if role == "assistant" {
					flush()
					summary := []any{}
					if text := common.String(block["thinking"]); text != "" {
						summary = append(summary, map[string]any{"type": "summary_text", "text": text})
					}
					item := map[string]any{"type": "reasoning", "summary": summary}
					if signature := common.String(block["signature"]); signature != "" {
						item["encrypted_content"] = signature
					}
					input = append(input, item)
				}
			case "tool_use":
				flush()
				name := common.String(block["name"])
				if short := forward[name]; short != "" {
					name = short
				} else {
					name = common.ShortName(name)
				}
				arguments, _ := json.Marshal(block["input"])
				input = append(input, map[string]any{"type": "function_call", "call_id": common.ShortName(common.String(block["id"])), "name": name, "arguments": string(arguments)})
			case "tool_result":
				flush()
				input = append(input, map[string]any{"type": "function_call_output", "call_id": common.ShortName(common.String(block["tool_use_id"])), "output": anthropicToolOutput(block["content"])})
			}
		}
		flush()
	}
	out["input"] = input
	if tools := common.Array(request["tools"]); len(tools) > 0 {
		converted := make([]any, 0, len(tools))
		for _, raw := range tools {
			tool := common.Object(raw)
			name := common.String(tool["name"])
			if short := forward[name]; short != "" {
				name = short
			}
			item := map[string]any{"type": "function", "name": name, "parameters": tool["input_schema"]}
			common.CopyFields(item, tool, "description")
			converted = append(converted, item)
		}
		out["tools"] = converted
		out["tool_choice"] = "auto"
	}
	convertAnthropicChoice(out, common.Object(request["tool_choice"]), forward)
	if thinking := common.Object(request["thinking"]); thinking != nil {
		switch common.String(thinking["type"]) {
		case "enabled", "adaptive", "auto":
			out["reasoning"] = map[string]any{"summary": "auto"}
		}
	}
	if stops := common.Array(request["stop_sequences"]); len(stops) > 0 {
		out["stop"] = stops
	}
	return json.Marshal(out)
}
func anthropicSystem(value any) ([]any, error) {
	if value == nil {
		return nil, nil
	}
	if text, ok := value.(string); ok {
		return []any{map[string]any{"type": "input_text", "text": text}}, nil
	}
	array, ok := value.([]any)
	if !ok {
		return nil, errors.New("system must be a string or array")
	}
	parts := make([]any, 0, len(array))
	for _, raw := range array {
		block := common.Object(raw)
		if common.String(block["type"]) == "text" {
			parts = append(parts, map[string]any{"type": "input_text", "text": common.String(block["text"])})
		}
	}
	return parts, nil
}
func anthropicToolOutput(value any) any {
	if text, ok := value.(string); ok {
		return text
	}
	if array, ok := value.([]any); ok {
		out := make([]any, 0, len(array))
		for _, raw := range array {
			block := common.Object(raw)
			switch common.String(block["type"]) {
			case "text":
				out = append(out, map[string]any{"type": "input_text", "text": common.String(block["text"])})
			case "image":
				source := common.Object(block["source"])
				out = append(out, map[string]any{"type": "input_image", "image_url": fmt.Sprintf("data:%s;base64,%s", common.String(source["media_type"]), common.String(source["data"]))})
			}
		}
		return out
	}
	return ""
}
func convertAnthropicChoice(out map[string]any, choice map[string]any, names map[string]string) {
	if choice == nil {
		return
	}
	if disabled, ok := choice["disable_parallel_tool_use"].(bool); ok {
		out["parallel_tool_calls"] = !disabled
	}

	switch common.String(choice["type"]) {
	case "auto", "any", "none":
		value := common.String(choice["type"])
		if value == "any" {
			value = "required"
		}
		out["tool_choice"] = value
	case "tool":
		name := common.String(choice["name"])
		if short := names[name]; short != "" {
			name = short
		}
		out["tool_choice"] = map[string]any{"type": "function", "name": name}
	}
}
func ConvertClaudeRequestToCodex(model string, body []byte, stream bool) []byte {
	out, _ := Request(model, body, stream)
	return out
}
