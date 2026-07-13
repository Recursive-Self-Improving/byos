// Package registry provides the protocol-neutral translator registry.
package registry

import (
	"encoding/json"
	"errors"
	"sync"
)

type Format string

const (
	OpenAIChat      Format = "openai.chat_completions"
	OpenAIResponses Format = "openai.responses"
	Anthropic       Format = "anthropic.messages"
)

type StreamState interface{}

type Transformer interface {
	Request(model string, body []byte, stream bool) ([]byte, error)
	Response(model string, originalRequest []byte, events [][]byte) ([]byte, error)
	Stream(model string, originalRequest, event []byte, state *StreamState) ([][]byte, error)
}

type Registry struct {
	mu         sync.RWMutex
	transforms map[Format]Transformer
}

func New() *Registry { return &Registry{transforms: make(map[Format]Transformer)} }

func (r *Registry) Register(format Format, transform Transformer) error {
	if format == "" || transform == nil {
		return errors.New("translator format and transform are required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.transforms[format]; exists {
		return errors.New("translator already registered: " + string(format))
	}
	r.transforms[format] = transform
	return nil
}

func (r *Registry) Get(format Format) (Transformer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	transform, ok := r.transforms[format]
	return transform, ok
}

func EventData(event []byte) []byte {
	if len(event) >= 5 && string(event[:5]) == "data:" {
		event = event[5:]
		for len(event) > 0 && (event[0] == ' ' || event[0] == '\t') {
			event = event[1:]
		}
	}
	for len(event) > 0 && (event[len(event)-1] == '\n' || event[len(event)-1] == '\r') {
		event = event[:len(event)-1]
	}
	return event
}

func SSE(event string, data []byte) []byte {
	out := make([]byte, 0, len(event)+len(data)+16)
	if event != "" {
		out = append(out, "event: "...)
		out = append(out, event...)
		out = append(out, '\n')
	}
	out = append(out, "data: "...)
	out = append(out, data...)
	out = append(out, '\n', '\n')
	return out
}

func JSONEventType(event []byte) string {
	var envelope struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(EventData(event), &envelope)
	return envelope.Type
}

func IsTerminalEvent(event []byte) bool {
	switch JSONEventType(event) {
	case "response.completed", "response.incomplete":
		return true
	default:
		return false
	}
}
