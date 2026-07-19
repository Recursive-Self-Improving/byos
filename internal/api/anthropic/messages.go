package anthropic

import (
	"encoding/json"
	"fmt"
	"net/http"

	"byos/internal/api"
	"byos/internal/routing"
	"byos/internal/translate/registry"
)

type MessagesHandler struct {
	Transform  registry.Transformer
	Execute    api.ExecuteFunc
	OpenStream api.StreamFunc
}

func (h MessagesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("anthropic-version") == "" {
		api.AnthropicError(w, api.Invalid(fmt.Errorf("missing anthropic-version")))
		return
	}
	body, err := api.ReadJSONBody(w, r)
	if err != nil {
		api.AnthropicError(w, err)
		return
	}
	var metadata struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	if json.Unmarshal(body, &metadata) != nil || metadata.Model == "" {
		api.AnthropicError(w, api.Invalid(fmt.Errorf("invalid request")))
		return
	}
	canonical, err := h.Transform.Request(metadata.Model, body, metadata.Stream)
	if err != nil {
		api.AnthropicError(w, api.Invalid(err))
		return
	}
	if !metadata.Stream {
		result, err := h.Execute(r.Context(), routing.Request{Model: metadata.Model, Body: canonical})
		if err != nil {
			api.AnthropicError(w, err)
			return
		}
		events := make([][]byte, len(result.Events))
		for i, event := range result.Events {
			events[i] = event.Data
		}
		response, err := h.Transform.Response(result.Model, body, events)
		if err != nil {
			api.AnthropicError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(response)
		return
	}
	stream, err := h.OpenStream(r.Context(), routing.Request{Model: metadata.Model, Body: canonical})
	if err != nil {
		api.AnthropicError(w, err)
		return
	}
	defer stream.Close()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	flusher, _ := w.(http.Flusher)
	var state registry.StreamState
	for {
		event, err := stream.Next(r.Context())
		if err != nil {
			return
		}
		chunks, err := h.Transform.Stream(stream.Model(), body, event.Data, &state)
		if err != nil {
			return
		}
		for _, chunk := range chunks {
			_, _ = w.Write(chunk)
		}
		if flusher != nil {
			flusher.Flush()
		}
		if registry.IsTerminalEvent(event.Data) {
			return
		}
	}
}
