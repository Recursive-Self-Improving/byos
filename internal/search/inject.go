package search

import (
	"errors"
	"fmt"
)

func Inject(request map[string]any) error {
	if request == nil {
		return errors.New("canonical request must be an object")
	}
	toolsValue, exists := request["tools"]
	var tools []any
	if exists && toolsValue != nil {
		var ok bool
		tools, ok = toolsValue.([]any)
		if !ok {
			return errors.New("canonical tools must be an array")
		}
	}
	searchCount := 0
	for _, raw := range tools {
		tool, ok := raw.(map[string]any)
		if !ok {
			return errors.New("canonical tool must be an object")
		}
		if tool["type"] == "x_search" {
			searchCount++
		}
	}
	if searchCount > 1 {
		return errors.New("canonical request contains duplicate x_search tools")
	}
	if searchCount == 0 {
		tools = append(tools, map[string]any{"type": "x_search"})
	}
	request["tools"] = tools
	if choice, ok := request["tool_choice"].(string); ok && choice == "none" {
		request["tool_choice"] = "auto"
	}
	return Validate(request)
}
func Validate(request map[string]any) error {
	if request == nil {
		return errors.New("canonical request must be an object")
	}
	if choice, ok := request["tool_choice"].(string); ok && choice == "none" {
		return errors.New("canonical request cannot disable x_search")
	}
	toolsValue, exists := request["tools"]
	if !exists {
		return errors.New("canonical request must contain exactly one x_search tool, found 0")
	}
	tools, ok := toolsValue.([]any)
	if !ok {
		return errors.New("canonical tools must be an array")
	}
	count := 0
	for _, raw := range tools {
		tool, ok := raw.(map[string]any)
		if !ok {
			return errors.New("canonical tool must be an object")
		}
		if tool["type"] == "x_search" {
			count++
		}
	}
	if count != 1 {
		return fmt.Errorf("canonical request must contain exactly one x_search tool, found %d", count)
	}
	return nil
}
