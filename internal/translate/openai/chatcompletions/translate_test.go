package chatcompletions

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRequestPreservesMessagesMultimodalAndClientTools(t *testing.T) {
	longName := strings.Repeat("weather_lookup_", 6)
	body := []byte(`{"model":"grok","messages":[{"role":"system","content":"rules"},{"role":"user","content":[{"type":"text","text":"look"},{"type":"image_url","image_url":{"url":"data:image/png;base64,AA","detail":"high"}}]},{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"` + longName + `","arguments":"{\"city\":\"NYC\"}"}}]},{"role":"tool","tool_call_id":"call_1","content":"sunny"}],"tools":[{"type":"function","function":{"name":"` + longName + `","description":"weather","parameters":{"type":"object"},"strict":true}}],"response_format":{"type":"json_schema","json_schema":{"name":"answer","schema":{"type":"object"},"strict":true}}}`)
	out, err := Request("grok-4.5", body, true)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if json.Unmarshal(out, &got) != nil {
		t.Fatal("invalid output")
	}
	input := got["input"].([]any)
	if len(input) != 4 {
		t.Fatalf("input=%s", out)
	}
	if input[0].(map[string]any)["role"] != "developer" {
		t.Fatalf("system role not normalized: %s", out)
	}
	userParts := input[1].(map[string]any)["content"].([]any)
	if userParts[1].(map[string]any)["type"] != "input_image" {
		t.Fatalf("image lost: %s", out)
	}
	call := input[2].(map[string]any)
	if len(call["name"].(string)) > 64 {
		t.Fatalf("tool name not shortened: %s", out)
	}
	if input[3].(map[string]any)["type"] != "function_call_output" {
		t.Fatalf("tool result lost: %s", out)
	}
	if got["text"].(map[string]any)["format"].(map[string]any)["type"] != "json_schema" {
		t.Fatalf("structured output lost: %s", out)
	}
}

func TestResponseSuppressesSearchAndPreservesCitationUsage(t *testing.T) {
	event := []byte(`{"type":"response.completed","response":{"id":"resp_1","model":"grok-4.5","created_at":12,"status":"completed","output":[{"type":"x_search_call","id":"search_1","status":"completed"},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer [source](https://x.com/post)","annotations":[{"type":"url_citation","url":"https://x.com/post"}]}]}],"usage":{"input_tokens":4,"output_tokens":5,"total_tokens":9,"output_tokens_details":{"reasoning_tokens":2}}}}`)
	out, err := Response("grok", []byte(`{"messages":[]}`), [][]byte{event})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "x_search") || strings.Contains(string(out), "annotations") {
		t.Fatalf("server search leaked: %s", out)
	}
	if !strings.Contains(string(out), "https://x.com/post") {
		t.Fatalf("inline citation lost: %s", out)
	}
	var got map[string]any
	_ = json.Unmarshal(out, &got)
	choice := got["choices"].([]any)[0].(map[string]any)
	if choice["finish_reason"] != "stop" {
		t.Fatalf("finish=%v", choice["finish_reason"])
	}
	if got["usage"].(map[string]any)["total_tokens"].(float64) != 9 {
		t.Fatalf("usage=%s", out)
	}
}

func TestStreamSearchUnknownSuppressedAndClientToolFinishesToolCalls(t *testing.T) {
	original := []byte(`{"messages":[],"tools":[{"type":"function","function":{"name":"lookup","parameters":{}}}]}`)
	state := (*StreamState)(nil)
	ignored := [][]byte{[]byte(`{"type":"response.x_search_call.in_progress"}`), []byte(`{"type":"response.output_item.added","item":{"type":"x_search_call","id":"s"}}`), []byte(`{"type":"response.future_server_tool.delta","delta":"secret"}`)}
	for _, event := range ignored {
		out, next, err := Stream("grok", original, event, state)
		if err != nil || len(out) != 0 {
			t.Fatalf("unexpected output %q err=%v", out, err)
		}
		state = next
	}
	text, next, err := Stream("grok", original, []byte(`{"type":"response.output_text.delta","delta":"see https://x.com/a"}`), state)
	if err != nil || len(text) != 1 || !strings.Contains(string(text[0]), "https://x.com/a") {
		t.Fatalf("text=%q err=%v", text, err)
	}
	state = next
	call, next, _ := Stream("grok", original, []byte(`{"type":"response.output_item.added","item":{"type":"function_call","call_id":"c1","name":"lookup"}}`), state)
	if len(call) != 1 {
		t.Fatal("client tool call missing")
	}
	state = next
	arguments, next, _ := Stream("grok", original, []byte(`{"type":"response.function_call_arguments.done","call_id":"c1","arguments":"{\"q\":\"x\"}"}`), state)
	if len(arguments) != 1 || !strings.Contains(string(arguments[0]), `{\"q\":\"x\"}`) {
		t.Fatalf("arguments=%q", arguments)
	}
	state = next
	terminal, _, _ := Stream("grok", original, []byte(`{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":1,"output_tokens":2}}}`), state)
	if len(terminal) != 1 || !strings.Contains(string(terminal[0]), `"finish_reason":"tool_calls"`) {
		t.Fatalf("terminal=%q", terminal)
	}
}
