package chatcompletions

import (
	"encoding/json"
	"testing"
)

func TestStreamFunctionArgumentsResolveOutputIndexWithoutCallID(t *testing.T) {
	original := []byte(`{"messages":[],"tools":[{"type":"function","function":{"name":"first","parameters":{}}},{"type":"function","function":{"name":"second","parameters":{}}}]}`)
	state := (*StreamState)(nil)
	events := [][]byte{
		[]byte(`{"type":"response.output_item.added","output_index":3,"item":{"type":"function_call","call_id":"c1","name":"first"}}`),
		[]byte(`{"type":"response.output_item.added","output_index":7,"item":{"type":"function_call","call_id":"c2","name":"second"}}`),
		[]byte(`{"type":"response.function_call_arguments.done","output_index":7,"arguments":"{\"n\":2}"}`),
		[]byte(`{"type":"response.function_call_arguments.delta","output_index":3,"delta":"{\"n\":"}`),
	}
	var outputs []map[string]any
	for _, event := range events {
		chunks, next, err := Stream("grok", original, event, state)
		if err != nil {
			t.Fatal(err)
		}
		state = next
		for _, chunk := range chunks {
			var value map[string]any
			if json.Unmarshal(chunk, &value) != nil {
				t.Fatal(string(chunk))
			}
			outputs = append(outputs, value)
		}
	}
	toolIndex := func(output map[string]any) int {
		return int(output["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)["tool_calls"].([]any)[0].(map[string]any)["index"].(float64))
	}
	if got := toolIndex(outputs[2]); got != 1 {
		t.Fatalf("output_index 7 mapped to tool index %d", got)
	}
	if got := toolIndex(outputs[3]); got != 0 {
		t.Fatalf("output_index 3 mapped to tool index %d", got)
	}
}
