package openai

import (
	"encoding/json"
	"fmt"
	"net/http"

	"supergrok-api/internal/api"
	"supergrok-api/internal/routing"
	"supergrok-api/internal/search"
	"supergrok-api/internal/sessions"
	"supergrok-api/internal/translate/registry"
)

type ResponsesHandler struct {
	Transform  registry.Transformer
	Execute    api.ExecuteFunc
	OpenStream api.StreamFunc
	Sessions   *sessions.Service
}
type responseMetadata struct {
	Model    string `json:"model"`
	Stream   bool   `json:"stream"`
	Store    *bool  `json:"store"`
	Previous string `json:"previous_response_id"`
}

func (h ResponsesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := api.ReadJSONBody(w, r)
	if err != nil {
		api.OpenAIError(w, err)
		return
	}
	var metadata responseMetadata
	if json.Unmarshal(body, &metadata) != nil || metadata.Model == "" {
		api.OpenAIError(w, api.Invalid(fmt.Errorf("invalid request")))
		return
	}
	canonical, err := h.Transform.Request(metadata.Model, body, metadata.Stream)
	if err != nil {
		api.OpenAIError(w, api.Invalid(err))
		return
	}
	currentCanonical := append([]byte(nil), canonical...)
	reconstructed, err := h.Sessions.Prepare(r.Context(), canonical)
	if err != nil {
		api.OpenAIError(w, err)
		return
	}
	prepared, err := search.Inject(reconstructed.Body)
	if err != nil {
		api.OpenAIError(w, api.Invalid(err))
		return
	}
	request := routing.Request{Model: metadata.Model, Body: prepared, PreferredAccountID: reconstructed.PreferredAccountID}
	if !metadata.Stream {
		result, err := h.Execute(r.Context(), request)
		if err != nil {
			api.OpenAIError(w, err)
			return
		}
		events := make([][]byte, len(result.Events))
		for i, event := range result.Events {
			events[i] = event.Data
		}
		response, err := h.Transform.Response(result.Model, body, events)
		if err != nil {
			api.OpenAIError(w, err)
			return
		}
		if id, terminal := completedResponse(result.Events[len(result.Events)-1].Data); id != "" {
			if err := h.Sessions.PersistCompleted(r.Context(), sessions.CompletedNode{ResponseID: id, UpstreamResponseID: id, PreviousResponseID: metadata.Previous, Model: result.Model, AccountID: result.AccountID, CanonicalInput: currentCanonical, TerminalOutput: terminal, Store: metadata.Store}, true); err != nil {
				api.OpenAIError(w, err)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(response)
		return
	}
	stream, err := h.OpenStream(r.Context(), request)
	if err != nil {
		api.OpenAIError(w, err)
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
		terminalEvent := registry.IsTerminalEvent(event.Data)
		if registry.JSONEventType(event.Data) == "response.completed" {
			id, terminal := completedResponse(event.Data)
			if err := h.Sessions.PersistCompleted(r.Context(), sessions.CompletedNode{ResponseID: id, UpstreamResponseID: id, PreviousResponseID: metadata.Previous, Model: stream.Model(), AccountID: stream.AccountID(), CanonicalInput: currentCanonical, TerminalOutput: terminal, Store: metadata.Store}, true); err != nil {
				return
			}
		}
		for _, chunk := range chunks {
			eventType := registry.JSONEventType(chunk)
			_, _ = w.Write(registry.SSE(eventType, chunk))
		}
		if terminalEvent {
			if flusher != nil {
				flusher.Flush()
			}
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}
func completedResponse(event []byte) (string, []byte) {
	var envelope struct {
		Type     string          `json:"type"`
		Response json.RawMessage `json:"response"`
	}
	if json.Unmarshal(event, &envelope) != nil || envelope.Type != "response.completed" || len(envelope.Response) == 0 {
		return "", nil
	}
	var response struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(envelope.Response, &response)
	return response.ID, envelope.Response
}
