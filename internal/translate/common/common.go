package common

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

func DecodeObject(body []byte) (map[string]any, error) {
	var value map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.New("malformed JSON request")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("malformed JSON request")
	}
	if value == nil {
		return nil, errors.New("request body must be a JSON object")
	}
	return value, nil
}

func Marshal(value any) ([]byte, error) { return json.Marshal(value) }

func Object(value any) map[string]any {
	object, _ := value.(map[string]any)
	return object
}

func Array(value any) []any {
	array, _ := value.([]any)
	return array
}

func String(value any) string {
	text, _ := value.(string)
	return text
}

func Number(value any) int64 {
	switch n := value.(type) {
	case json.Number:
		result, _ := n.Int64()
		return result
	case float64:
		return int64(n)
	case int:
		return int64(n)
	case int64:
		return n
	}
	return 0
}

func CopyFields(dst, src map[string]any, fields ...string) {
	for _, field := range fields {
		if value, ok := src[field]; ok {
			dst[field] = value
		}
	}
}

func ShortName(name string) string {
	if len(name) <= 64 {
		return name
	}
	hash := sha256.Sum256([]byte(name))
	return name[:51] + "_" + hex.EncodeToString(hash[:6])
}

func ToolNames(request map[string]any, anthropic bool) (map[string]string, map[string]string) {
	forward := make(map[string]string)
	reverse := make(map[string]string)
	for _, value := range Array(request["tools"]) {
		tool := Object(value)
		name := String(tool["name"])
		if !anthropic {
			name = String(Object(tool["function"])["name"])
		}
		if name == "" {
			continue
		}
		short := ShortName(name)
		forward[name] = short
		reverse[short] = name
	}
	return forward, reverse
}

func ContentText(content any) string {
	if text, ok := content.(string); ok {
		return text
	}
	var builder strings.Builder
	for _, value := range Array(content) {
		part := Object(value)
		if String(part["type"]) == "text" || String(part["type"]) == "input_text" || String(part["type"]) == "output_text" {
			builder.WriteString(String(part["text"]))
		}
	}
	return builder.String()
}

func Usage(response map[string]any) (input, output, total, cached, reasoning int64) {
	usage := Object(response["usage"])
	input = Number(usage["input_tokens"])
	output = Number(usage["output_tokens"])
	total = Number(usage["total_tokens"])
	if total == 0 {
		total = input + output
	}
	cached = Number(Object(usage["input_tokens_details"])["cached_tokens"])
	reasoning = Number(Object(usage["output_tokens_details"])["reasoning_tokens"])
	return
}

func TerminalResponse(events [][]byte) (map[string]any, error) {
	for i := len(events) - 1; i >= 0; i-- {
		var event map[string]any
		data := events[i]
		if len(data) >= 5 && string(data[:5]) == "data:" {
			data = []byte(strings.TrimSpace(string(data[5:])))
		}
		if json.Unmarshal(data, &event) == nil && (String(event["type"]) == "response.completed" || String(event["type"]) == "response.incomplete") {
			response := Object(event["response"])
			if response != nil {
				return response, nil
			}
		}
	}
	return nil, fmt.Errorf("canonical event stream has no terminal response")
}

func StopReason(response map[string]any, hasTool bool) string {
	if hasTool {
		return "tool_calls"
	}
	if String(response["status"]) == "incomplete" {
		reason := String(Object(response["incomplete_details"])["reason"])
		switch reason {
		case "max_output_tokens", "max_tokens":
			return "length"
		case "content_filter":
			return "content_filter"
		}
	}
	return "stop"
}
