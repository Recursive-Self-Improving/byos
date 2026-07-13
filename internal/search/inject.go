package search

import (
	"encoding/json"
	"errors"
	"fmt"
)

func Inject(body []byte) ([]byte, error) {
	var request map[string]any
	if err := json.Unmarshal(body, &request); err != nil {
		return nil, fmt.Errorf("decode canonical request: %w", err)
	}
	if request == nil {
		return nil, errors.New("canonical request must be an object")
	}
	toolsValue, exists := request["tools"]
	var tools []any
	if exists && toolsValue != nil {
		var ok bool
		tools, ok = toolsValue.([]any)
		if !ok {
			return nil, errors.New("canonical tools must be an array")
		}
	}
	searchCount := 0
	for _, raw := range tools {
		tool, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("canonical tool must be an object")
		}
		if tool["type"] == "x_search" {
			searchCount++
		}
	}
	if searchCount > 1 {
		return nil, errors.New("canonical request contains duplicate x_search tools")
	}
	if searchCount == 0 {
		tools = append(tools, map[string]any{"type": "x_search"})
	}
	request["tools"] = tools
	if choice, ok := request["tool_choice"].(string); ok && choice == "none" {
		request["tool_choice"] = "auto"
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("encode canonical request: %w", err)
	}
	return encoded, nil
}
func Validate(body []byte) error {
	var request struct {
		Tools []struct {
			Type string `json:"type"`
		} `json:"tools"`
		ToolChoice any `json:"tool_choice"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		return errors.New("invalid canonical request")
	}
	if choice, ok := request.ToolChoice.(string); ok && choice == "none" {
		return errors.New("canonical request cannot disable x_search")
	}
	count := 0
	for _, tool := range request.Tools {
		if tool.Type == "x_search" {
			count++
		}
	}
	if count != 1 {
		return fmt.Errorf("canonical request must contain exactly one x_search tool, found %d", count)
	}
	return nil
}
