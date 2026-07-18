package anthropic

import (
	"encoding/json"
	"net/http"

	"byoo/internal/api"
	translateanthropic "byoo/internal/translate/anthropic"
)

func CountTokensHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("anthropic-version") == "" {
		api.AnthropicError(w, api.Invalid(&translateanthropic.ValidationError{Message: "anthropic-version header is required"}))
		return
	}
	body, err := api.ReadJSONBody(w, r)
	if err != nil {
		api.AnthropicError(w, err)
		return
	}
	var metadata struct {
		Model string `json:"model"`
	}
	if json.Unmarshal(body, &metadata) != nil || metadata.Model == "" {
		api.AnthropicError(w, api.Invalid(&translateanthropic.ValidationError{Message: "model is required"}))
		return
	}
	response, err := translateanthropic.CountTokens(metadata.Model, body)
	if err != nil {
		if validation, ok := err.(*translateanthropic.ValidationError); ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(validation.Body())
			return
		}
		api.AnthropicError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(response)
}
