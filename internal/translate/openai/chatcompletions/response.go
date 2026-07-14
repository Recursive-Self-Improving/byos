// Response event mappings are adapted in part from CLIProxyAPI v7.2.71
// internal/translator/codex/openai/chat-completions/codex_openai_response.go
// (MIT License, https://github.com/router-for-me/CLIProxyAPI/blob/v7.2.71/internal/translator/codex/openai/chat-completions/codex_openai_response.go).
package chatcompletions

import (
	"context"
	"encoding/json"
	"time"

	"supergrok-api/internal/translate/common"
	"supergrok-api/internal/translate/registry"
)

type StreamState struct {
	ID                    string
	Model                 string
	Created               int64
	FunctionIndex         int
	FunctionIndexes       map[string]int
	OutputFunctionIndexes map[int]int
	FunctionArgumentsSeen map[int]bool
	HasClientTool         bool
	TextSeen              bool
}

type Transformer struct{}

func (Transformer) Request(model string, body []byte, stream bool) ([]byte, error) {
	return Request(model, body, stream)
}
func (Transformer) Response(model string, original []byte, events [][]byte) ([]byte, error) {
	return Response(model, original, events)
}
func (Transformer) Stream(model string, original, event []byte, state *registry.StreamState) ([][]byte, error) {
	var typed *StreamState
	if *state != nil {
		typed, _ = (*state).(*StreamState)
	}
	out, next, err := Stream(model, original, event, typed)
	*state = next
	return out, err
}

func Response(model string, original []byte, events [][]byte) ([]byte, error) {
	response, err := common.TerminalResponse(events)
	if err != nil {
		return nil, err
	}
	if m := common.String(response["model"]); m != "" {
		model = m
	}
	message := map[string]any{"role": "assistant", "content": ""}
	var text, reasoning string
	toolCalls := make([]any, 0)
	_, reverse := toolMaps(original)
	for _, rawItem := range common.Array(response["output"]) {
		item := common.Object(rawItem)
		switch common.String(item["type"]) {
		case "message":
			for _, rawPart := range common.Array(item["content"]) {
				part := common.Object(rawPart)
				if common.String(part["type"]) == "output_text" {
					text += common.String(part["text"])
				}
			}
		case "reasoning":
			for _, rawSummary := range common.Array(item["summary"]) {
				reasoning += common.String(common.Object(rawSummary)["text"])
			}
		case "function_call":
			name := common.String(item["name"])
			if originalName := reverse[name]; originalName != "" {
				name = originalName
			}
			toolCalls = append(toolCalls, map[string]any{"id": common.String(item["call_id"]), "type": "function", "function": map[string]any{"name": name, "arguments": common.String(item["arguments"])}})
		}
	}
	message["content"] = text
	if reasoning != "" {
		message["reasoning_content"] = reasoning
	}
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
	}
	inputTokens, outputTokens, total, cached, reasoningTokens := common.Usage(response)
	usage := map[string]any{"prompt_tokens": inputTokens, "completion_tokens": outputTokens, "total_tokens": total}
	if cached > 0 {
		usage["prompt_tokens_details"] = map[string]any{"cached_tokens": cached}
	}
	if reasoningTokens > 0 {
		usage["completion_tokens_details"] = map[string]any{"reasoning_tokens": reasoningTokens}
	}
	created := common.Number(response["created_at"])
	if created == 0 {
		created = time.Now().Unix()
	}
	out := map[string]any{"id": common.String(response["id"]), "object": "chat.completion", "created": created, "model": model, "choices": []any{map[string]any{"index": 0, "message": message, "finish_reason": common.StopReason(response, len(toolCalls) > 0)}}, "usage": usage}
	return json.Marshal(out)
}

func Stream(model string, original, event []byte, state *StreamState) ([][]byte, *StreamState, error) {
	if state == nil {
		state = &StreamState{Model: model, Created: time.Now().Unix(), FunctionIndex: -1, FunctionIndexes: map[string]int{}, OutputFunctionIndexes: map[int]int{}, FunctionArgumentsSeen: map[int]bool{}}
	}
	var envelope map[string]any
	if err := json.Unmarshal(registry.EventData(event), &envelope); err != nil {
		return nil, state, nil
	}
	typeName := common.String(envelope["type"])
	if typeName == "response.created" {
		response := common.Object(envelope["response"])
		state.ID = common.String(response["id"])
		if value := common.String(response["model"]); value != "" {
			state.Model = value
		}
		if value := common.Number(response["created_at"]); value > 0 {
			state.Created = value
		}
		return nil, state, nil
	}
	delta := map[string]any{}
	var finish any
	switch typeName {
	case "response.output_text.delta":
		state.TextSeen = true
		delta["role"], delta["content"] = "assistant", common.String(envelope["delta"])
	case "response.reasoning_summary_text.delta":
		delta["role"], delta["reasoning_content"] = "assistant", common.String(envelope["delta"])
	case "response.output_item.added":
		item := common.Object(envelope["item"])
		if common.String(item["type"]) != "function_call" {
			return nil, state, nil
		}
		announceChatFunction(delta, state, original, item, int(common.Number(envelope["output_index"])), "")
	case "response.function_call_arguments.delta":
		index, ok := chatFunctionIndex(state, envelope)
		if !ok {
			return nil, state, nil
		}
		state.FunctionArgumentsSeen[index] = true
		delta["tool_calls"] = []any{map[string]any{"index": index, "function": map[string]any{"arguments": common.String(envelope["delta"])}}}
	case "response.function_call_arguments.done":
		index, ok := chatFunctionIndex(state, envelope)
		if !ok || state.FunctionArgumentsSeen[index] {
			return nil, state, nil
		}
		delta["tool_calls"] = []any{map[string]any{"index": index, "function": map[string]any{"arguments": common.String(envelope["arguments"])}}}
	case "response.output_item.done":
		item := common.Object(envelope["item"])
		switch common.String(item["type"]) {
		case "message":
			if state.TextSeen {
				return nil, state, nil
			}
			text := ""
			for _, rawPart := range common.Array(item["content"]) {
				part := common.Object(rawPart)
				if common.String(part["type"]) == "output_text" {
					text += common.String(part["text"])
				}
			}
			if text == "" {
				return nil, state, nil
			}
			state.TextSeen = true
			delta["role"], delta["content"] = "assistant", text
		case "function_call":
			if _, announced := chatFunctionIndex(state, envelope); announced {
				return nil, state, nil
			}
			announceChatFunction(delta, state, original, item, int(common.Number(envelope["output_index"])), common.String(item["arguments"]))
		default:
			return nil, state, nil
		}
	case "response.completed", "response.incomplete":
		finish = common.StopReason(common.Object(envelope["response"]), state.HasClientTool)
	default:
		return nil, state, nil
	}
	chunk := map[string]any{"id": state.ID, "object": "chat.completion.chunk", "created": state.Created, "model": state.Model, "choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}}}
	if finish != nil {
		input, output, total, cached, reasoning := common.Usage(common.Object(envelope["response"]))
		usage := map[string]any{"prompt_tokens": input, "completion_tokens": output, "total_tokens": total}
		if cached > 0 {
			usage["prompt_tokens_details"] = map[string]any{"cached_tokens": cached}
		}
		if reasoning > 0 {
			usage["completion_tokens_details"] = map[string]any{"reasoning_tokens": reasoning}
		}
		chunk["usage"] = usage
	}
	encoded, err := json.Marshal(chunk)
	if err != nil {
		return nil, state, err
	}
	return [][]byte{encoded}, state, nil
}

func announceChatFunction(delta map[string]any, state *StreamState, original []byte, item map[string]any, outputIndex int, arguments string) {
	state.FunctionIndex++
	state.HasClientTool = true
	key := common.String(item["call_id"])
	if key == "" {
		key = common.String(item["id"])
	}
	if key != "" {
		state.FunctionIndexes[key] = state.FunctionIndex
	}
	state.OutputFunctionIndexes[outputIndex] = state.FunctionIndex
	_, reverse := toolMaps(original)
	name := common.String(item["name"])
	if full := reverse[name]; full != "" {
		name = full
	}
	delta["role"] = "assistant"
	delta["tool_calls"] = []any{map[string]any{"index": state.FunctionIndex, "id": key, "type": "function", "function": map[string]any{"name": name, "arguments": arguments}}}
}

func chatFunctionIndex(state *StreamState, envelope map[string]any) (int, bool) {
	if callID := common.String(envelope["call_id"]); callID != "" {
		index, ok := state.FunctionIndexes[callID]
		return index, ok
	}
	index, ok := state.OutputFunctionIndexes[int(common.Number(envelope["output_index"]))]
	return index, ok
}

func toolMaps(original []byte) (map[string]string, map[string]string) {
	request, _ := common.DecodeObject(original)
	if request == nil {
		return map[string]string{}, map[string]string{}
	}
	return common.ToolNames(request, false)
}

func ConvertCodexResponseToOpenAI(_ context.Context, model string, original, _, raw []byte, param *any) [][]byte {
	var state *StreamState
	if *param != nil {
		state, _ = (*param).(*StreamState)
	}
	out, next, _ := Stream(model, original, raw, state)
	*param = next
	return out
}
func ConvertCodexResponseToOpenAINonStream(_ context.Context, model string, original, _ []byte, raw []byte, _ *any) []byte {
	out, _ := Response(model, original, [][]byte{raw})
	return out
}
