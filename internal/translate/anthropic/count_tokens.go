package anthropic

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/tiktoken-go/tokenizer"

	"byoo/internal/search"
)

type ValidationError struct{ Message string }

func (e *ValidationError) Error() string { return e.Message }
func (e *ValidationError) Body() []byte {
	body, _ := json.Marshal(map[string]any{"type": "error", "error": map[string]any{"type": "invalid_request_error", "message": e.Message}})
	return body
}

var codecState struct {
	sync.Once
	codec tokenizer.Codec
	err   error
}

// CountTokens returns an Anthropic-compatible token-count response. The value
// is a deterministic cl100k_base compatibility estimate over the canonical
// Responses request (including mandatory x_search), not a billing authority.
func CountTokens(model string, body []byte) ([]byte, error) {
	canonical, err := Request(model, body, false)
	if err != nil {
		return nil, validation(err)
	}
	canonical, err = search.Inject(canonical)
	if err != nil {
		return nil, validation(err)
	}
	codecState.Do(func() { codecState.codec, codecState.err = tokenizer.Get(tokenizer.Cl100kBase) })
	if codecState.err != nil {
		return nil, codecState.err
	}
	count, err := codecState.codec.Count(string(canonical))
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"input_tokens": count})
}
func validation(err error) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	if message == "malformed JSON request" {
		message = "Invalid request: malformed JSON"
	}
	return &ValidationError{Message: message}
}
func ClaudeTokenCount(_ context.Context, count int64) []byte {
	body, _ := json.Marshal(map[string]any{"input_tokens": count})
	return body
}
