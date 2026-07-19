package anthropic

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRequestPreservesBlocksToolsResultsAndStopSequences(t *testing.T) {
	body := []byte(`{"model":"grok","system":[{"type":"text","text":"rules"}],"messages":[{"role":"user","content":[{"type":"text","text":"look"},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AA"}}]},{"role":"assistant","content":[{"type":"thinking","thinking":"plan","signature":"sig"},{"type":"tool_use","id":"c1","name":"lookup","input":{"q":"x"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"c1","content":[{"type":"text","text":"ok"}]}]}],"tools":[{"name":"lookup","description":"lookup","input_schema":{"type":"object"}}],"tool_choice":{"type":"tool","name":"lookup"},"thinking":{"type":"enabled","budget_tokens":1000},"stop_sequences":["END"]}`)
	out, err := Request("grok-4.5", body, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"role":"developer"`, `"type":"input_image"`, `"type":"reasoning"`, `"encrypted_content":"sig"`, `"type":"function_call"`, `"type":"function_call_output"`, `"stop":["END"]`} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("missing %s: %s", want, out)
		}
	}
}

func TestRequestSupportsCurrentToolChoiceAndThinkingFields(t *testing.T) {
	callID := strings.Repeat("tool-call-", 10)
	body := []byte(`{"model":"grok","max_tokens":1024,"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"` + callID + `","name":"lookup","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"` + callID + `","content":"boom","is_error":true}]}],"tools":[{"name":"lookup","input_schema":{"type":"object"}}],"tool_choice":{"type":"auto","disable_parallel_tool_use":true},"thinking":{"type":"adaptive"}}`)
	out, err := Request("grok-4.5", body, true)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got["parallel_tool_calls"] != false {
		t.Fatalf("parallel tool choice lost: %s", out)
	}
	reasoning := got["reasoning"].(map[string]any)
	if reasoning["summary"] != "auto" {
		t.Fatalf("adaptive thinking lost: %s", out)
	}
	if _, exists := reasoning["effort"]; exists {
		t.Fatalf("unsupported reasoning effort forwarded: %s", out)
	}
	items := got["input"].([]any)
	if len(items) != 2 {
		t.Fatalf("input=%s", out)
	}
	toolUse := items[0].(map[string]any)
	toolResult := items[1].(map[string]any)
	shortID := toolUse["call_id"].(string)
	if len(shortID) > 64 || toolResult["call_id"] != shortID {
		t.Fatalf("call IDs are incompatible: %s", out)
	}
	if _, exists := toolResult["status"]; exists {
		t.Fatalf("invalid function output status: %s", out)
	}
}

func TestRequestDropsUnsupportedMetadataAndDefaultsToolChoice(t *testing.T) {
	body := []byte(`{"model":"grok-4.5","messages":[{"role":"user","content":"hi"}],"tools":[{"name":"read","input_schema":{"type":"object","properties":{}}}],"metadata":{"user_id":"session"}}`)
	out, err := Request("grok-4.5", body, true)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if _, exists := got["metadata"]; exists {
		t.Fatalf("unsupported metadata forwarded: %s", out)
	}
	if got["tool_choice"] != "auto" {
		t.Fatalf("tool choice=%v body=%s", got["tool_choice"], out)
	}
}

func TestResponseSuppressesSearchAndUsesEndTurn(t *testing.T) {
	event := []byte(`{"type":"response.completed","response":{"id":"r1","model":"grok","status":"completed","output":[{"type":"x_search_call","id":"s1"},{"type":"message","content":[{"type":"output_text","text":"answer [post](https://x.com/a)","annotations":[{"type":"url_citation","url":"https://x.com/a"}]}]}],"usage":{"input_tokens":2,"output_tokens":3}}}`)
	out, err := Response("grok", []byte(`{"messages":[]}`), [][]byte{event})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "x_search") || strings.Contains(string(out), "server_tool_use") || strings.Contains(string(out), "annotations") {
		t.Fatalf("search leaked: %s", out)
	}
	if !strings.Contains(string(out), "https://x.com/a") || !strings.Contains(string(out), `"stop_reason":"end_turn"`) {
		t.Fatalf("citation/stop lost: %s", out)
	}
}

func TestResponseClientToolAndStopReason(t *testing.T) {
	event := []byte(`{"type":"response.completed","response":{"id":"r2","status":"completed","output":[{"type":"function_call","call_id":"c1","name":"lookup","arguments":"{\"q\":\"x\"}"}],"usage":{}}}`)
	out, err := Response("grok", []byte(`{"messages":[],"tools":[{"name":"lookup","input_schema":{}}]}`), [][]byte{event})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"type":"tool_use"`) || !strings.Contains(string(out), `"stop_reason":"tool_use"`) {
		t.Fatalf("tool call lost: %s", out)
	}
}

func TestStreamOrderingSearchSuppressionAndUnknownEvents(t *testing.T) {
	state := (*StreamState)(nil)
	original := []byte(`{"messages":[]}`)
	var all strings.Builder
	events := [][]byte{
		[]byte(`{"type":"response.created","response":{"id":"r1","model":"grok"}}`),
		[]byte(`{"type":"response.x_search_call.in_progress"}`),
		[]byte(`{"type":"response.output_item.added","item":{"type":"x_search_call","id":"s"}}`),
		[]byte(`{"type":"response.future_server_tool.delta"}`),
		[]byte(`{"type":"response.reasoning_summary_text.delta","delta":"think"}`),
		[]byte(`{"type":"response.output_item.done","item":{"type":"reasoning","encrypted_content":"sig"}}`),
		[]byte(`{"type":"response.output_text.delta","delta":"answer https://x.com/a"}`),
		[]byte(`{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":2,"output_tokens":3}}}`),
	}
	for _, event := range events {
		out, next, err := Stream("grok", original, event, state)
		if err != nil {
			t.Fatal(err)
		}
		state = next
		for _, chunk := range out {
			all.Write(chunk)
		}
	}
	got := all.String()
	for _, want := range []string{"event: message_start", "thinking_delta", "signature_delta", "event: content_block_stop", "text_delta", "event: message_delta", "event: message_stop"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s:\n%s", want, got)
		}
	}
	if strings.Contains(got, "x_search") || strings.Contains(got, "server_tool") || strings.Contains(got, "future_server") {
		t.Fatalf("server tool leaked:\n%s", got)
	}
	positions := []int{strings.Index(got, "event: message_start"), strings.Index(got, "thinking_delta"), strings.Index(got, "signature_delta"), strings.Index(got, "text_delta"), strings.Index(got, "event: message_delta"), strings.Index(got, "event: message_stop")}
	for i := 1; i < len(positions); i++ {
		if positions[i] <= positions[i-1] {
			t.Fatalf("bad event ordering %v:\n%s", positions, got)
		}
	}
	if !strings.Contains(got, `"stop_reason":"end_turn"`) {
		t.Fatalf("bad stop reason:\n%s", got)
	}
}

func TestStreamClientToolFallbackHasValidOrdering(t *testing.T) {
	state := (*StreamState)(nil)
	original := []byte(`{"messages":[],"tools":[{"name":"lookup","input_schema":{}}]}`)
	var all strings.Builder
	for _, event := range [][]byte{[]byte(`{"type":"response.created","response":{"id":"r","model":"grok"}}`), []byte(`{"type":"response.output_item.done","item":{"type":"function_call","call_id":"c","name":"lookup","arguments":"{\"q\":\"x\"}"}}`), []byte(`{"type":"response.completed","response":{"status":"completed","usage":{}}}`)} {
		out, next, err := Stream("grok", original, event, state)
		if err != nil {
			t.Fatal(err)
		}
		state = next
		for _, chunk := range out {
			all.Write(chunk)
		}
	}
	got := all.String()
	for _, want := range []string{`"type":"tool_use"`, `"partial_json":"{\"q\":\"x\"}"`, `"stop_reason":"tool_use"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s:\n%s", want, got)
		}
	}
	if start, delta, stop := strings.Index(got, "content_block_start"), strings.Index(got, "input_json_delta"), strings.Index(got, "content_block_stop"); !(start >= 0 && delta > start && stop > delta) {
		t.Fatalf("bad tool ordering:\n%s", got)
	}
}

func TestCountTokensStableIncludesSearchAndMalformedError(t *testing.T) {
	body := []byte(`{"model":"grok","messages":[{"role":"user","content":"hello"}]}`)
	first, err := CountTokens("grok", body)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CountTokens("grok", []byte(`{"messages":[{"content":"hello","role":"user"}],"model":"grok"}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("unstable count: %s != %s", first, second)
	}
	var count map[string]int
	if json.Unmarshal(first, &count) != nil || count["input_tokens"] <= 0 {
		t.Fatalf("bad response: %s", first)
	}
	_, err1 := CountTokens("grok", []byte(`{"messages":`))
	_, err2 := CountTokens("grok", []byte(`{"messages":`))
	if err1 == nil || err2 == nil || err1.Error() != err2.Error() || err1.Error() != "Invalid request: malformed JSON" {
		t.Fatalf("unstable malformed errors: %v / %v", err1, err2)
	}
	validation, ok := err1.(*ValidationError)
	if !ok || string(validation.Body()) != `{"error":{"message":"Invalid request: malformed JSON","type":"invalid_request_error"},"type":"error"}` {
		t.Fatalf("nonstandard validation body: %T %s", err1, validation.Body())
	}
	if _, trailingErr := CountTokens("grok", []byte(`{"model":"grok","messages":[]} trailing`)); trailingErr == nil || trailingErr.Error() != "Invalid request: malformed JSON" {
		t.Fatalf("trailing JSON accepted: %v", trailingErr)
	}
}

func TestCountTokenRequestInjectsSearchAndPreservesNumbers(t *testing.T) {
	request, err := countTokenRequest("grok", []byte(`{"model":"grok","messages":[{"role":"user","content":"hello"}],"tools":[{"name":"lookup","input_schema":{"type":"object","maximum":9007199254740993}}],"tool_choice":{"type":"none"}}`))
	if err != nil {
		t.Fatal(err)
	}
	tools, ok := request["tools"].([]any)
	if !ok || len(tools) != 2 {
		t.Fatalf("tools=%#v, want client tool plus x_search", request["tools"])
	}
	searchTool, ok := tools[1].(map[string]any)
	if !ok || searchTool["type"] != "x_search" {
		t.Fatalf("search tool=%#v", tools[1])
	}
	if request["tool_choice"] != "auto" {
		t.Fatalf("tool_choice=%#v, want auto", request["tool_choice"])
	}
	clientTool, ok := tools[0].(map[string]any)
	if !ok {
		t.Fatalf("client tool=%#v", tools[0])
	}
	parameters, ok := clientTool["parameters"].(map[string]any)
	if !ok || parameters["maximum"] != json.Number("9007199254740993") {
		t.Fatalf("parameters=%#v, want exact json.Number", clientTool["parameters"])
	}
}

func TestCountTokenRequestRejectsInvalidRequest(t *testing.T) {
	if _, err := countTokenRequest("grok", []byte(`{"messages":{}}`)); err == nil || err.Error() != "messages must be an array" {
		t.Fatalf("invalid request error=%v", err)
	}
}
