// Native Responses passthrough behavior is adapted in part from CLIProxyAPI v7.2.71
// internal/translator/codex/openai/responses/codex_openai-responses_response.go
// (MIT License, https://github.com/router-for-me/CLIProxyAPI/blob/v7.2.71/internal/translator/codex/openai/responses/codex_openai-responses_response.go).
package responses

import (
	"context"
	"encoding/json"
	"errors"

	"byoo/internal/translate/common"
	"byoo/internal/translate/registry"
)

type Transformer struct{}

func (Transformer) Request(model string, body []byte, stream bool) ([]byte, error) {
	return Request(model, body, stream)
}
func (Transformer) Response(_ string, _ []byte, events [][]byte) ([]byte, error) {
	return Response(events)
}
func (Transformer) Stream(_ string, _, event []byte, _ *registry.StreamState) ([][]byte, error) {
	return Stream(event)
}

func Stream(event []byte) ([][]byte, error) {
	data := registry.EventData(event)
	if !json.Valid(data) {
		return nil, errors.New("invalid canonical response event")
	}
	// Native Responses clients receive every event byte-for-byte, including
	// x_search_call, annotations, citations, and future server event types.
	return [][]byte{append([]byte(nil), data...)}, nil
}
func Response(events [][]byte) ([]byte, error) {
	response, err := common.TerminalResponse(events)
	if err != nil {
		return nil, err
	}
	return json.Marshal(response)
}
func ConvertCodexResponseToOpenAIResponses(_ context.Context, _ string, _, _, raw []byte, _ *any) [][]byte {
	out, _ := Stream(raw)
	return out
}
func ConvertCodexResponseToOpenAIResponsesNonStream(_ context.Context, _ string, _, _, raw []byte, _ *any) []byte {
	out, _ := Response([][]byte{raw})
	return out
}
