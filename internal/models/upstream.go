package models

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"supergrok-api/internal/xai"
)

type Upstream struct {
	client *xai.Client
}

func NewUpstream(client *xai.Client) *Upstream { return &Upstream{client: client} }

func (u *Upstream) Discover(ctx context.Context, token string) ([]Model, error) {
	models, fallback, err := u.fetch(ctx, token, "models-v2")
	if err == nil && !fallback {
		return models, nil
	}
	if err != nil && !fallback {
		return nil, err
	}
	models, _, err = u.fetch(ctx, token, "models")
	return models, err
}

func (u *Upstream) fetch(ctx context.Context, token, endpoint string) ([]Model, bool, error) {
	response, err := u.client.Do(ctx, http.MethodGet, endpoint, token, "", "application/json", nil)
	if err != nil {
		return nil, false, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return nil, false, errors.Join(ErrCredential, &HTTPError{Status: response.StatusCode})
	}
	if response.StatusCode == http.StatusNotFound && endpoint == "models-v2" {
		return nil, true, nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, false, &HTTPError{Status: response.StatusCode}
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return nil, false, err
	}
	models, err := parseCatalog(payload)
	if errors.Is(err, ErrSchema) && endpoint == "models-v2" {
		return nil, true, nil
	}
	return models, false, err
}

func parseCatalog(payload []byte) ([]Model, error) {
	var raw json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, ErrSchema
	}
	var entries []json.RawMessage
	if len(raw) > 0 && raw[0] == '[' {
		if err := json.Unmarshal(raw, &entries); err != nil {
			return nil, ErrSchema
		}
	} else {
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return nil, ErrSchema
		}
		modelsRaw, ok := envelope["models"]
		if !ok || json.Unmarshal(modelsRaw, &entries) != nil {
			return nil, ErrSchema
		}
	}
	if entries == nil {
		return nil, ErrSchema
	}
	result := make([]Model, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		model, err := parseModel(entry)
		if err != nil {
			return nil, ErrSchema
		}
		if _, exists := seen[model.ID]; exists {
			continue
		}
		seen[model.ID] = struct{}{}
		result = append(result, model)
	}
	return result, nil
}

func parseModel(payload json.RawMessage) (Model, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		return Model{}, err
	}
	var model Model
	if err := firstString(fields, &model.ID, "id", "model"); err != nil || strings.TrimSpace(model.ID) == "" {
		return Model{}, ErrSchema
	}
	model.ID = strings.TrimSpace(model.ID)
	if err := optionalString(fields, &model.DisplayName, "displayName", "display_name", "name"); err != nil {
		return Model{}, err
	}
	if err := optionalInt(fields, &model.ContextWindow, "contextWindow", "context_window"); err != nil {
		return Model{}, err
	}
	if err := optionalInt(fields, &model.MaxOutputTokens, "maxCompletionTokens", "max_completion_tokens", "maxOutputTokens", "max_output_tokens"); err != nil {
		return Model{}, err
	}
	if err := optionalStrings(fields, &model.ReasoningEfforts, "reasoningEfforts", "reasoning_efforts"); err != nil {
		return Model{}, err
	}
	if err := optionalBool(fields, &model.SupportsBackendSearch, "supportsBackendSearch", "supports_backend_search"); err != nil {
		return Model{}, err
	}
	return model, nil
}

func firstField(fields map[string]json.RawMessage, names ...string) (json.RawMessage, bool) {
	for _, name := range names {
		if value, ok := fields[name]; ok {
			return value, true
		}
	}
	return nil, false
}
func firstString(fields map[string]json.RawMessage, target *string, names ...string) error {
	value, ok := firstField(fields, names...)
	if !ok || json.Unmarshal(value, target) != nil {
		return ErrSchema
	}
	return nil
}
func optionalString(fields map[string]json.RawMessage, target *string, names ...string) error {
	value, ok := firstField(fields, names...)
	if !ok || string(value) == "null" {
		return nil
	}
	if err := json.Unmarshal(value, target); err != nil {
		return ErrSchema
	}
	return nil
}
func optionalInt(fields map[string]json.RawMessage, target *int64, names ...string) error {
	value, ok := firstField(fields, names...)
	if !ok || string(value) == "null" {
		return nil
	}
	if err := json.Unmarshal(value, target); err != nil || *target < 0 {
		return ErrSchema
	}
	return nil
}
func optionalStrings(fields map[string]json.RawMessage, target *[]string, names ...string) error {
	value, ok := firstField(fields, names...)
	if !ok || string(value) == "null" {
		return nil
	}
	if err := json.Unmarshal(value, target); err != nil {
		return ErrSchema
	}
	for _, item := range *target {
		if strings.TrimSpace(item) == "" {
			return ErrSchema
		}
	}
	return nil
}
func optionalBool(fields map[string]json.RawMessage, target **bool, names ...string) error {
	value, ok := firstField(fields, names...)
	if !ok || string(value) == "null" {
		return nil
	}
	var parsed bool
	if err := json.Unmarshal(value, &parsed); err != nil {
		return fmt.Errorf("%w: invalid boolean", ErrSchema)
	}
	*target = &parsed
	return nil
}
