package anthropic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/tiktoken-go/tokenizer"

	"byos/internal/provider"
	"byos/internal/search"
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
	canonical, err := countTokenRequest(model, body)
	if err != nil {
		return nil, validation(err)
	}
	canonicalBody, err := json.Marshal(canonical)
	if err != nil {
		return nil, err
	}
	codecState.Do(func() { codecState.codec, codecState.err = tokenizer.Get(tokenizer.Cl100kBase) })
	if codecState.err != nil {
		return nil, codecState.err
	}
	count, err := codecState.codec.Count(string(canonicalBody))
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"input_tokens": count})
}

func countTokenRequest(model string, body []byte) (provider.CanonicalRequest, error) {
	canonicalBody, err := Request(model, body, false)
	if err != nil {
		return nil, err
	}
	canonical, err := decodeCanonicalRequest(canonicalBody)
	if err != nil {
		return nil, err
	}
	if err := search.Inject(canonical); err != nil {
		return nil, err
	}
	return canonical, nil
}

func decodeCanonicalRequest(body []byte) (provider.CanonicalRequest, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var request provider.CanonicalRequest
	if err := decoder.Decode(&request); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("canonical request contains multiple JSON values")
		}
		return nil, err
	}
	return request, nil
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
