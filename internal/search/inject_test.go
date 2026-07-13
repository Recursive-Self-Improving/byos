package search

import (
	"encoding/json"
	"testing"
)

func TestInject(t *testing.T) {
	tests := []struct {
		name, input string
		choice      any
		filters     bool
		wantErr     bool
	}{{"absent", `{"model":"grok-4.5"}`, nil, false, false}, {"none", `{"tools":[],"tool_choice":"none"}`, "auto", false, false}, {"existing filters", `{"tools":[{"type":"x_search","allowed_x_handles":["xai"],"from_date":"2026-01-01","enable_image_understanding":true}],"tool_choice":"required"}`, "required", true, false}, {"function choice", `{"tools":[{"type":"function","name":"lookup"}],"tool_choice":{"type":"function","name":"lookup"}}`, map[string]any{"type": "function", "name": "lookup"}, false, false}, {"duplicate", `{"tools":[{"type":"x_search"},{"type":"x_search"}]}`, nil, false, true}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Inject([]byte(test.input))
			if test.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(got); err != nil {
				t.Fatal(err)
			}
			var body map[string]any
			if err := json.Unmarshal(got, &body); err != nil {
				t.Fatal(err)
			}
			if test.choice != nil {
				actual, _ := json.Marshal(body["tool_choice"])
				expected, _ := json.Marshal(test.choice)
				if string(actual) != string(expected) {
					t.Fatalf("tool_choice=%s want %s", actual, expected)
				}
			}
			if test.filters {
				tool := body["tools"].([]any)[0].(map[string]any)
				if tool["from_date"] != "2026-01-01" || tool["enable_image_understanding"] != true {
					t.Fatalf("filters lost: %v", tool)
				}
			}
		})
	}
}
func TestValidateRejectsMissingSearch(t *testing.T) {
	if err := Validate([]byte(`{"tools":[{"type":"function"}]}`)); err == nil {
		t.Fatal("missing search accepted")
	}
}

func TestValidateRejectsDisabledSearch(t *testing.T) {
	if err := Validate([]byte(`{"tools":[{"type":"x_search"}],"tool_choice":"none"}`)); err == nil {
		t.Fatal("disabled search accepted")
	}
}

func TestInjectRejectsNullRequest(t *testing.T) {
	if _, err := Inject([]byte("null")); err == nil {
		t.Fatal("null canonical request accepted")
	}
}
