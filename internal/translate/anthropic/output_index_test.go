package anthropic

import (
	"strings"
	"testing"
)

func TestStreamParallelFunctionsResolveOutputIndexInBlockOrder(t *testing.T) {
	original := []byte(`{"messages":[],"tools":[{"name":"first","input_schema":{}},{"name":"second","input_schema":{}}]}`)
	state := (*StreamState)(nil)
	var stream strings.Builder
	events := [][]byte{
		[]byte(`{"type":"response.created","response":{"id":"r","model":"grok"}}`),
		[]byte(`{"type":"response.output_item.added","output_index":2,"item":{"type":"function_call","call_id":"c1","name":"first"}}`),
		[]byte(`{"type":"response.output_item.added","output_index":5,"item":{"type":"function_call","call_id":"c2","name":"second"}}`),
		[]byte(`{"type":"response.function_call_arguments.delta","output_index":5,"delta":"{\"second\":"}`),
		[]byte(`{"type":"response.function_call_arguments.done","output_index":5,"arguments":"ignored"}`),
		[]byte(`{"type":"response.function_call_arguments.done","output_index":2,"arguments":"{\"first\":1}"}`),
		[]byte(`{"type":"response.completed","response":{"status":"completed","usage":{}}}`),
	}
	for _, event := range events {
		chunks, next, err := Stream("grok", original, event, state)
		if err != nil {
			t.Fatal(err)
		}
		state = next
		for _, chunk := range chunks {
			stream.Write(chunk)
		}
	}
	got := stream.String()
	firstStart := strings.Index(got, `"id":"c1"`)
	firstArgs := strings.Index(got, `{\"first\":1}`)
	firstStop := strings.Index(got, `"index":0,"type":"content_block_stop"`)
	secondStart := strings.Index(got, `"id":"c2"`)
	secondArgs := strings.Index(got, `{\"second\":`)
	secondStop := strings.Index(got, `"index":1,"type":"content_block_stop"`)
	if !(firstStart >= 0 && firstArgs > firstStart && firstStop > firstArgs && secondStart > firstStop && secondArgs > secondStart && secondStop > secondArgs) {
		t.Fatalf("invalid parallel block ordering:\n%s", got)
	}
}

func TestAnthropicStopReasonsStreamAndNonStream(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     string
	}{
		{"stop sequence", `{"id":"r","status":"completed","stop_sequence":"END","output":[],"usage":{}}`, "stop_sequence"},
		{"max tokens", `{"id":"r","status":"incomplete","incomplete_details":{"reason":"max_output_tokens"},"output":[],"usage":{}}`, "max_tokens"},
		{"refusal", `{"id":"r","status":"completed","output":[{"type":"message","content":[{"type":"refusal","refusal":"no"}]}],"usage":{}}`, "refusal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			terminal := []byte(`{"type":"response.completed","response":` + test.response + `}`)
			nonstream, err := Response("grok", []byte(`{"messages":[]}`), [][]byte{terminal})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(nonstream), `"stop_reason":"`+test.want+`"`) {
				t.Fatalf("nonstream=%s", nonstream)
			}
			chunks, _, err := Stream("grok", nil, terminal, nil)
			if err != nil {
				t.Fatal(err)
			}
			var joined strings.Builder
			for _, chunk := range chunks {
				joined.Write(chunk)
			}
			if !strings.Contains(joined.String(), `"stop_reason":"`+test.want+`"`) {
				t.Fatalf("stream=%s", joined.String())
			}
		})
	}
}
