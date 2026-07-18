package sessions

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"byoo/internal/store"
)

const (
	MaxChainNodes = 256
	MaxChainBytes = 64 << 20
)

var ErrPreviousResponseNotFound = errors.New("previous_response_not_found")
var ErrContextLengthExceeded = errors.New("context_length_exceeded")

type Reconstruction struct {
	Body               []byte
	PreferredAccountID string
}
type historyBuilder struct {
	items        []any
	references   map[string]any
	encodedBytes int
}

func newHistoryBuilder() *historyBuilder {
	return &historyBuilder{references: make(map[string]any), encodedBytes: 2}
}
func (b *historyBuilder) append(items []any, strict bool) error {
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok {
			return errors.New("invalid canonical continuity item")
		}
		kind, _ := item["type"].(string)
		if kind == "item_reference" {
			id, _ := item["item_id"].(string)
			resolved, ok := b.references[id]
			if !ok {
				return ErrPreviousResponseNotFound
			}
			item = resolved.(map[string]any)
			kind, _ = item["type"].(string)
		}
		switch kind {
		case "message", "function_call", "function_call_output", "reasoning":
		default:
			if strict {
				return fmt.Errorf("unsupported canonical continuity item %q", kind)
			}
			continue
		}
		encoded, err := json.Marshal(item)
		if err != nil {
			return err
		}
		additional := len(encoded)
		if len(b.items) > 0 {
			additional++
		}
		if b.encodedBytes+additional > MaxChainBytes {
			return ErrContextLengthExceeded
		}
		b.encodedBytes += additional
		b.items = append(b.items, item)
		if id, _ := item["id"].(string); id != "" {
			b.references[id] = item
		}
	}
	return nil
}
func Reconstruct(ctx context.Context, repo *store.ResponseRepository, current []byte, previousID string, now time.Time) (Reconstruction, error) {
	builder := newHistoryBuilder()
	if previousID == "" {
		return normalizeCurrent(current, builder)
	}
	var reverseIDs []string
	seen := map[string]bool{}
	id := previousID
	preferredAccountID := ""
	for id != "" {
		if seen[id] || len(reverseIDs) >= MaxChainNodes {
			return Reconstruction{}, ErrContextLengthExceeded
		}
		seen[id] = true
		previous, preferred, err := repo.GetLink(ctx, id, now)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return Reconstruction{}, ErrPreviousResponseNotFound
			}
			return Reconstruction{}, err
		}
		if len(reverseIDs) == 0 {
			preferredAccountID = preferred
		}
		reverseIDs = append(reverseIDs, id)
		id = previous
	}
	for index := len(reverseIDs) - 1; index >= 0; index-- {
		node, err := repo.Get(ctx, reverseIDs[index], now)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return Reconstruction{}, ErrPreviousResponseNotFound
			}
			return Reconstruction{}, err
		}
		inputs, err := extractInput(node.Input)
		if err != nil {
			return Reconstruction{}, err
		}
		if err := builder.append(inputs, true); err != nil {
			return Reconstruction{}, err
		}
		outputs, err := extractOutput(node.Output)
		if err != nil {
			return Reconstruction{}, err
		}
		if err := builder.append(outputs, false); err != nil {
			return Reconstruction{}, err
		}
	}
	result, err := normalizeCurrent(current, builder)
	if err != nil {
		return Reconstruction{}, err
	}
	result.PreferredAccountID = preferredAccountID
	return result, nil
}
func normalizeCurrent(current []byte, builder *historyBuilder) (Reconstruction, error) {
	var request map[string]any
	if err := json.Unmarshal(current, &request); err != nil || request == nil {
		return Reconstruction{}, errors.New("invalid canonical request")
	}
	items, err := inputItems(request["input"])
	if err != nil {
		return Reconstruction{}, err
	}
	if err := builder.append(items, true); err != nil {
		return Reconstruction{}, err
	}
	request["input"] = builder.items
	delete(request, "previous_response_id")
	request["store"] = false
	body, err := json.Marshal(request)
	if err != nil {
		return Reconstruction{}, err
	}
	if len(body) > MaxChainBytes {
		return Reconstruction{}, ErrContextLengthExceeded
	}
	return Reconstruction{Body: body}, nil
}
func extractInput(raw []byte) ([]any, error) {
	var request map[string]any
	if err := json.Unmarshal(raw, &request); err != nil {
		return nil, err
	}
	return inputItems(request["input"])
}
func inputItems(value any) ([]any, error) {
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case string:
		return []any{map[string]any{"type": "message", "role": "user", "content": typed}}, nil
	case []any:
		return typed, nil
	default:
		return nil, fmt.Errorf("invalid canonical input")
	}
}
func extractOutput(raw []byte) ([]any, error) {
	var response map[string]any
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, err
	}
	values, ok := response["output"].([]any)
	if !ok {
		return nil, nil
	}
	return values, nil
}
