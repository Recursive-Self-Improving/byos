package openai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"byos/internal/api"
	"byos/internal/provider"
	"byos/internal/routing"
	"byos/internal/sessions"
	"byos/internal/translate/registry"
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
	request := routing.Request{Model: metadata.Model, Body: reconstructed.Body, PreferredAccountID: reconstructed.PreferredAccountID}
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
	committed := false
	lastSequenceNumber := -1
	for {
		event, err := stream.Next(r.Context())
		if err != nil {
			if committed && r.Context().Err() == nil && !isStreamCancellation(err) {
				chunk, _ := json.Marshal(struct {
					Type           string `json:"type"`
					Code           string `json:"code"`
					Message        string `json:"message"`
					Param          any    `json:"param"`
					SequenceNumber int    `json:"sequence_number"`
				}{Type: "error", Code: "server_error", Message: "stream terminated", SequenceNumber: lastSequenceNumber + 1})
				_, _ = w.Write(registry.SSE("error", chunk))
				if flusher != nil {
					flusher.Flush()
				}
			}
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
			if sequenceNumber, ok := responseSequenceNumber(chunk); ok {
				lastSequenceNumber = sequenceNumber
			}
		}
		if len(chunks) > 0 {
			committed = true
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

func isStreamCancellation(err error) bool {
	if errors.Is(err, context.Canceled) {
		return true
	}
	var execution *routing.ExecutionError
	return errors.As(err, &execution) && execution.Classified.Class == provider.ClassCancelled
}

func responseSequenceNumber(event []byte) (int, bool) {
	var envelope struct {
		SequenceNumber *int `json:"sequence_number"`
	}
	if json.Unmarshal(event, &envelope) != nil || envelope.SequenceNumber == nil {
		return 0, false
	}
	return *envelope.SequenceNumber, true
}
