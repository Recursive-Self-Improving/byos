// Anthropic response event mappings are adapted in part from CLIProxyAPI v7.2.71
// internal/translator/codex/claude/codex_claude_response.go
// (MIT License, https://github.com/router-for-me/CLIProxyAPI/blob/v7.2.71/internal/translator/codex/claude/codex_claude_response.go).
package anthropic

import (
	"context"
	"encoding/json"

	"byoo/internal/translate/common"
	"byoo/internal/translate/registry"
)

type StreamState struct {
	BlockIndex            int
	BlockType             string
	FunctionOutputIndexes map[string]int
	OutputBlockIndexes    map[int]int
	FunctionArgumentsSeen map[int]bool
	PendingFunctions      map[int]map[string]any
	PendingArguments      map[int]string
	PendingDone           map[int]bool
	ActiveFunctionOutput  int
	FunctionActive        bool
	HasClientTool         bool
	Started               bool
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
	if value := common.String(response["model"]); value != "" {
		model = value
	}
	content := make([]any, 0)
	hasTool := false
	_, reverse := anthropicToolMaps(original)
	for _, raw := range common.Array(response["output"]) {
		item := common.Object(raw)
		switch common.String(item["type"]) {
		case "reasoning":
			var thinking string
			for _, summary := range common.Array(item["summary"]) {
				thinking += common.String(common.Object(summary)["text"])
			}
			if thinking != "" || common.String(item["encrypted_content"]) != "" {
				content = append(content, map[string]any{"type": "thinking", "thinking": thinking, "signature": common.String(item["encrypted_content"])})
			}
		case "message":
			for _, rawPart := range common.Array(item["content"]) {
				part := common.Object(rawPart)
				partType := common.String(part["type"])
				if partType == "output_text" || partType == "refusal" {
					text := common.String(part["text"])
					if text == "" {
						text = common.String(part["refusal"])
					}
					content = append(content, map[string]any{"type": "text", "text": text})
				}
			}
		case "function_call":
			hasTool = true
			name := common.String(item["name"])
			if full := reverse[name]; full != "" {
				name = full
			}
			var input any = map[string]any{}
			_ = json.Unmarshal([]byte(common.String(item["arguments"])), &input)
			content = append(content, map[string]any{"type": "tool_use", "id": common.String(item["call_id"]), "name": name, "input": input})
		}
	}
	inputTokens, outputTokens, _, cached, _ := common.Usage(response)
	usage := map[string]any{"input_tokens": inputTokens, "output_tokens": outputTokens}
	if cached > 0 {
		usage["cache_read_input_tokens"] = cached
	}
	out := map[string]any{"id": common.String(response["id"]), "type": "message", "role": "assistant", "model": model, "content": content, "stop_reason": anthropicStopReason(response, hasTool), "stop_sequence": response["stop_sequence"], "usage": usage}
	if out["stop_sequence"] == nil {
		out["stop_sequence"] = nil
	}
	return json.Marshal(out)
}

func Stream(model string, original, event []byte, state *StreamState) ([][]byte, *StreamState, error) {
	if state == nil {
		state = &StreamState{FunctionOutputIndexes: map[string]int{}, OutputBlockIndexes: map[int]int{}, FunctionArgumentsSeen: map[int]bool{}, PendingFunctions: map[int]map[string]any{}, PendingArguments: map[int]string{}, PendingDone: map[int]bool{}}
	}
	var envelope map[string]any
	if json.Unmarshal(registry.EventData(event), &envelope) != nil {
		return nil, state, nil
	}
	kind := common.String(envelope["type"])
	out := make([][]byte, 0, 4)
	emit := func(name string, payload map[string]any) {
		encoded, _ := json.Marshal(payload)
		out = append(out, registry.SSE(name, encoded))
	}
	closeBlock := func() {
		if state.BlockType != "" {
			emit("content_block_stop", map[string]any{"type": "content_block_stop", "index": state.BlockIndex})
			state.BlockIndex++
			state.BlockType = ""
		}
	}
	start := func(blockType string, block map[string]any) {
		if state.BlockType == blockType {
			return
		}
		closeBlock()
		state.BlockType = blockType
		emit("content_block_start", map[string]any{"type": "content_block_start", "index": state.BlockIndex, "content_block": block})
	}
	var pumpFunctions func()
	pumpFunctions = func() {
		for !state.FunctionActive && len(state.PendingFunctions) > 0 {
			first := true
			next := 0
			for outputIndex := range state.PendingFunctions {
				if first || outputIndex < next {
					first = false
					next = outputIndex
				}
			}
			item := state.PendingFunctions[next]
			delete(state.PendingFunctions, next)
			callID := common.String(item["call_id"])
			if callID == "" {
				callID = common.String(item["id"])
			}
			_, reverse := anthropicToolMaps(original)
			name := common.String(item["name"])
			if full := reverse[name]; full != "" {
				name = full
			}
			state.HasClientTool = true
			state.FunctionActive = true
			state.ActiveFunctionOutput = next
			state.BlockType = "tool_use"
			state.OutputBlockIndexes[next] = state.BlockIndex
			emit("content_block_start", map[string]any{"type": "content_block_start", "index": state.BlockIndex, "content_block": map[string]any{"type": "tool_use", "id": callID, "name": name, "input": map[string]any{}}})
			if arguments := state.PendingArguments[next]; arguments != "" {
				emit("content_block_delta", map[string]any{"type": "content_block_delta", "index": state.BlockIndex, "delta": map[string]any{"type": "input_json_delta", "partial_json": arguments}})
				state.FunctionArgumentsSeen[next] = true
				delete(state.PendingArguments, next)
			}
			if !state.PendingDone[next] {
				return
			}
			delete(state.PendingDone, next)
			closeBlock()
			state.FunctionActive = false
		}
	}
	switch kind {
	case "response.created":
		response := common.Object(envelope["response"])
		if value := common.String(response["model"]); value != "" {
			model = value
		}
		state.Started = true
		emit("message_start", map[string]any{"type": "message_start", "message": map[string]any{"id": common.String(response["id"]), "type": "message", "role": "assistant", "model": model, "content": []any{}, "stop_reason": nil, "stop_sequence": nil, "usage": map[string]any{"input_tokens": int64(0), "output_tokens": int64(0)}}})
	case "response.reasoning_summary_text.delta":
		start("thinking", map[string]any{"type": "thinking", "thinking": "", "signature": ""})
		emit("content_block_delta", map[string]any{"type": "content_block_delta", "index": state.BlockIndex, "delta": map[string]any{"type": "thinking_delta", "thinking": common.String(envelope["delta"])}})
	case "response.output_text.delta", "response.refusal.delta":
		state.TextSeen = true
		start("text", map[string]any{"type": "text", "text": ""})
		emit("content_block_delta", map[string]any{"type": "content_block_delta", "index": state.BlockIndex, "delta": map[string]any{"type": "text_delta", "text": common.String(envelope["delta"])}})
	case "response.output_item.added":
		item := common.Object(envelope["item"])
		if common.String(item["type"]) != "function_call" {
			return out, state, nil
		}
		outputIndex := int(common.Number(envelope["output_index"]))
		state.PendingFunctions[outputIndex] = item
		if callID := common.String(item["call_id"]); callID != "" {
			state.FunctionOutputIndexes[callID] = outputIndex
		}
		pumpFunctions()
	case "response.function_call_arguments.delta":
		outputIndex, ok := anthropicFunctionOutputIndex(state, envelope)
		if !ok {
			return nil, state, nil
		}
		arguments := common.String(envelope["delta"])
		if state.FunctionActive && state.ActiveFunctionOutput == outputIndex {
			emit("content_block_delta", map[string]any{"type": "content_block_delta", "index": state.OutputBlockIndexes[outputIndex], "delta": map[string]any{"type": "input_json_delta", "partial_json": arguments}})
			state.FunctionArgumentsSeen[outputIndex] = true
		} else {
			state.PendingArguments[outputIndex] += arguments
		}
	case "response.function_call_arguments.done":
		outputIndex, ok := anthropicFunctionOutputIndex(state, envelope)
		if !ok {
			return nil, state, nil
		}
		if !state.FunctionArgumentsSeen[outputIndex] && state.PendingArguments[outputIndex] == "" {
			state.PendingArguments[outputIndex] = common.String(envelope["arguments"])
		}
		state.PendingDone[outputIndex] = true
		if state.FunctionActive && state.ActiveFunctionOutput == outputIndex {
			if arguments := state.PendingArguments[outputIndex]; arguments != "" {
				emit("content_block_delta", map[string]any{"type": "content_block_delta", "index": state.OutputBlockIndexes[outputIndex], "delta": map[string]any{"type": "input_json_delta", "partial_json": arguments}})
				delete(state.PendingArguments, outputIndex)
			}
			delete(state.PendingDone, outputIndex)
			closeBlock()
			state.FunctionActive = false
			pumpFunctions()
		}
	case "response.output_item.done":
		item := common.Object(envelope["item"])
		switch common.String(item["type"]) {
		case "reasoning":
			if state.BlockType == "thinking" {
				if signature := common.String(item["encrypted_content"]); signature != "" {
					emit("content_block_delta", map[string]any{"type": "content_block_delta", "index": state.BlockIndex, "delta": map[string]any{"type": "signature_delta", "signature": signature}})
				}
			}
		case "message":
			if !state.TextSeen {
				text := ""
				for _, rawPart := range common.Array(item["content"]) {
					part := common.Object(rawPart)
					if common.String(part["type"]) == "output_text" || common.String(part["type"]) == "refusal" {
						text += common.String(part["text"])
						if text == "" {
							text += common.String(part["refusal"])
						}
					}
				}
				if text != "" {
					state.TextSeen = true
					start("text", map[string]any{"type": "text", "text": ""})
					emit("content_block_delta", map[string]any{"type": "content_block_delta", "index": state.BlockIndex, "delta": map[string]any{"type": "text_delta", "text": text}})
				}
			}
		case "function_call":
			outputIndex := int(common.Number(envelope["output_index"]))
			if _, active := state.OutputBlockIndexes[outputIndex]; !active {
				state.PendingFunctions[outputIndex] = item
				if callID := common.String(item["call_id"]); callID != "" {
					state.FunctionOutputIndexes[callID] = outputIndex
				}
			}
			if args := common.String(item["arguments"]); args != "" && state.PendingArguments[outputIndex] == "" && !state.FunctionArgumentsSeen[outputIndex] {
				state.PendingArguments[outputIndex] = args
			}
			state.PendingDone[outputIndex] = true
			if state.FunctionActive && state.ActiveFunctionOutput == outputIndex {
				if arguments := state.PendingArguments[outputIndex]; arguments != "" {
					emit("content_block_delta", map[string]any{"type": "content_block_delta", "index": state.OutputBlockIndexes[outputIndex], "delta": map[string]any{"type": "input_json_delta", "partial_json": arguments}})
					delete(state.PendingArguments, outputIndex)
				}
				delete(state.PendingDone, outputIndex)
				closeBlock()
				state.FunctionActive = false
				pumpFunctions()
			} else {
				pumpFunctions()
			}
		}
	case "response.completed", "response.incomplete":
		pumpFunctions()
		if state.FunctionActive {
			closeBlock()
			state.FunctionActive = false
		}
		response := common.Object(envelope["response"])
		closeBlock()
		input, outputTokens, _, cached, _ := common.Usage(response)
		usage := map[string]any{"input_tokens": input, "output_tokens": outputTokens}
		if cached > 0 {
			usage["cache_read_input_tokens"] = cached
		}
		emit("message_delta", map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": anthropicStopReason(response, state.HasClientTool), "stop_sequence": response["stop_sequence"]}, "usage": usage})
		emit("message_stop", map[string]any{"type": "message_stop"})
	default:
		return nil, state, nil
	}
	return out, state, nil
}

func anthropicFunctionOutputIndex(state *StreamState, envelope map[string]any) (int, bool) {
	if callID := common.String(envelope["call_id"]); callID != "" {
		index, ok := state.FunctionOutputIndexes[callID]
		return index, ok
	}
	_, exists := envelope["output_index"]
	if !exists {
		return 0, false
	}
	return int(common.Number(envelope["output_index"])), true
}
func anthropicStopReason(response map[string]any, hasTool bool) string {
	if hasTool {
		return "tool_use"
	}
	switch common.String(response["stop_reason"]) {
	case "stop_sequence":
		return "stop_sequence"
	case "refusal", "content_filter":
		return "refusal"
	case "max_output_tokens", "max_tokens", "length":
		return "max_tokens"
	}
	if common.String(response["stop_sequence"]) != "" {
		return "stop_sequence"
	}
	if common.String(response["status"]) == "incomplete" {
		switch common.String(common.Object(response["incomplete_details"])["reason"]) {
		case "max_output_tokens", "max_tokens":
			return "max_tokens"
		case "stop_sequence":
			return "stop_sequence"
		case "content_filter", "refusal":
			return "refusal"
		}
	}
	for _, rawItem := range common.Array(response["output"]) {
		item := common.Object(rawItem)
		if common.String(item["type"]) != "message" {
			continue
		}
		for _, rawPart := range common.Array(item["content"]) {
			if common.String(common.Object(rawPart)["type"]) == "refusal" {
				return "refusal"
			}
		}
	}
	return "end_turn"
}
func anthropicToolMaps(original []byte) (map[string]string, map[string]string) {
	request, _ := common.DecodeObject(original)
	if request == nil {
		return map[string]string{}, map[string]string{}
	}
	return common.ToolNames(request, true)
}
func ConvertCodexResponseToClaude(_ context.Context, model string, original, _, raw []byte, param *any) [][]byte {
	var state *StreamState
	if *param != nil {
		state, _ = (*param).(*StreamState)
	}
	out, next, _ := Stream(model, original, raw, state)
	*param = next
	return out
}
func ConvertCodexResponseToClaudeNonStream(_ context.Context, model string, original, _ []byte, raw []byte, _ *any) []byte {
	out, _ := Response(model, original, [][]byte{raw})
	return out
}
