package responses

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRequestNormalizesStringSystemAndUnsupportedFields(t *testing.T) {
	out, err := Request("grok-4.5", []byte(`{"input":"hello","max_output_tokens":9,"temperature":0.2,"user":"u","include":["file_search_call.results"],"tools":[{"type":"x_search","allowed_x_handles":["openai"]}]}`), false)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(out, &got)
	if _, ok := got["max_output_tokens"]; ok {
		t.Fatalf("unsupported field retained: %s", out)
	}
	input := got["input"].([]any)[0].(map[string]any)
	if input["role"] != "user" {
		t.Fatalf("input not normalized: %s", out)
	}
	if len(got["include"].([]any)) != 2 {
		t.Fatalf("include not merged: %s", out)
	}
	tool := got["tools"].([]any)[0].(map[string]any)
	if tool["type"] != "x_search" || tool["allowed_x_handles"] == nil {
		t.Fatalf("search changed: %s", out)
	}

	system, err := Request("grok", []byte(`{"input":[{"type":"message","role":"system","content":[{"type":"input_text","text":"rules"}]}]}`), true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(system), `"role":"developer"`) {
		t.Fatalf("system not normalized: %s", system)
	}
}

func TestNativeEventsAndTerminalResponsePreserved(t *testing.T) {
	events := [][]byte{
		[]byte(`{"type":"response.x_search_call.in_progress","item_id":"s1","query":"news"}`),
		[]byte(`{"type":"response.output_text.annotation.added","annotation":{"type":"url_citation","url":"https://x.com/a"}}`),
		[]byte(`{"type":"response.unknown.future","payload":{"a":1}}`),
		[]byte(`{"type":"response.completed","response":{"id":"r1","output":[{"type":"x_search_call","id":"s1"},{"type":"message","content":[{"type":"output_text","text":"answer","annotations":[{"type":"url_citation","url":"https://x.com/a"}]}]}],"usage":{"input_tokens":1,"output_tokens":2}}}`),
	}
	for _, event := range events {
		out, err := Stream(append([]byte("data: "), event...))
		if err != nil || len(out) != 1 || string(out[0]) != string(event) {
			t.Fatalf("event changed: %q err=%v", out, err)
		}
	}
	out, err := Response(events)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"x_search_call", "annotations", "https://x.com/a", "r1"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("%q missing: %s", want, out)
		}
	}
	if strings.Contains(string(out), "[DONE]") {
		t.Fatalf("chat sentinel leaked: %s", out)
	}
}
