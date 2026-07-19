package search

import (
	"encoding/json"
	"strings"
	"testing"
)

func decodeRequest(t *testing.T, input string) map[string]any {
	t.Helper()
	var request map[string]any
	decoder := json.NewDecoder(strings.NewReader(input))
	decoder.UseNumber()
	if err := decoder.Decode(&request); err != nil {
		t.Fatal(err)
	}
	return request
}

func TestInjectMutatesStructuredRequestWithoutEncoding(t *testing.T) {
	tests := []struct {
		name, input string
		choice      any
		filters     bool
		wantErr     bool
	}{
		{"absent", `{"model":"grok-4.5","large":9007199254740993}`, nil, false, false},
		{"none", `{"tools":[],"tool_choice":"none"}`, "auto", false, false},
		{"existing filters", `{"tools":[{"type":"x_search","allowed_x_handles":["xai"],"from_date":"2026-01-01","enable_image_understanding":true}],"tool_choice":"required"}`, "required", true, false},
		{"function choice", `{"tools":[{"type":"function","name":"lookup"}],"tool_choice":{"type":"function","name":"lookup"}}`, map[string]any{"type": "function", "name": "lookup"}, false, false},
		{"duplicate", `{"tools":[{"type":"x_search"},{"type":"x_search"}]}`, nil, false, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := decodeRequest(t, test.input)
			err := Inject(request)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(request); err != nil {
				t.Fatal(err)
			}
			if test.choice != nil {
				actual, _ := json.Marshal(request["tool_choice"])
				expected, _ := json.Marshal(test.choice)
				if string(actual) != string(expected) {
					t.Fatalf("tool_choice=%s want %s", actual, expected)
				}
			}
			if test.filters {
				tool := request["tools"].([]any)[0].(map[string]any)
				if tool["from_date"] != "2026-01-01" || tool["enable_image_understanding"] != true {
					t.Fatalf("filters lost: %v", tool)
				}
			}
			if number, ok := request["large"].(json.Number); test.name == "absent" && (!ok || number.String() != "9007199254740993") {
				t.Fatalf("number changed type or value: %#v", request["large"])
			}
		})
	}
}

func TestValidateRejectsMissingSearch(t *testing.T) {
	if err := Validate(decodeRequest(t, `{"tools":[{"type":"function"}]}`)); err == nil {
		t.Fatal("missing search accepted")
	}
}

func TestValidateRejectsDisabledSearch(t *testing.T) {
	if err := Validate(decodeRequest(t, `{"tools":[{"type":"x_search"}],"tool_choice":"none"}`)); err == nil {
		t.Fatal("disabled search accepted")
	}
}

func TestInjectRejectsNullRequest(t *testing.T) {
	if err := Inject(nil); err == nil {
		t.Fatal("null canonical request accepted")
	}
}
