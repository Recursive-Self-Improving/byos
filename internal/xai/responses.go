// Portions adapted from CLIProxyAPI/v7 internal/runtime/executor/xai_executor.go (MIT): Responses execution and terminal SSE handling.
// Upstream: https://github.com/router-for-me/CLIProxyAPI/blob/v7.2.71/internal/runtime/executor/xai_executor.go

package xai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/tidwall/gjson"

	"supergrok-api/internal/search"
)

type UpstreamError struct {
	Status  int
	Body    string
	Headers http.Header
}

func (e *UpstreamError) Error() string { return fmt.Sprintf("xAI upstream returned HTTP %d", e.Status) }

type Stream struct {
	parser *SSEParser
	first  *Event
	body   io.Closer
	cancel context.CancelFunc
}

func (s *Stream) Next(ctx context.Context) (Event, error) {
	if err := ctx.Err(); err != nil {
		_ = s.Close()
		return Event{}, err
	}
	if s.first != nil {
		event := *s.first
		s.first = nil
		return event, nil
	}
	return s.parser.Next(ctx)
}
func (s *Stream) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	return s.body.Close()
}
func (c *Client) prepare(body []byte) ([]byte, error) {
	if err := search.Validate(body); err != nil {
		return nil, fmt.Errorf("x_search invariant: %w", err)
	}
	var request map[string]any
	if err := json.Unmarshal(body, &request); err != nil {
		return nil, errors.New("invalid canonical request")
	}
	request["stream"] = true
	request["store"] = false
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(request); err != nil {
		return nil, err
	}
	prepared := encoded.Bytes()
	if len(prepared) > 0 && prepared[len(prepared)-1] == '\n' {
		prepared = prepared[:len(prepared)-1]
	}
	return prepared, nil
}
func (c *Client) open(ctx context.Context, token, model string, body []byte) (*http.Response, *SSEParser, context.CancelFunc, error) {
	prepared, err := c.prepare(body)
	if err != nil {
		return nil, nil, nil, err
	}
	requestCtx := ctx
	cancel := func() {}
	if c.config.RequestTimeout > 0 {
		requestCtx, cancel = context.WithTimeout(ctx, c.config.RequestTimeout)
	}
	request, err := c.newRequest(requestCtx, http.MethodPost, "responses", token, model, bytes.NewReader(prepared))
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	response, err := c.http.Do(request)
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		defer response.Body.Close()
		defer cancel()
		payload, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		return nil, nil, nil, &UpstreamError{Status: response.StatusCode, Body: string(payload), Headers: response.Header.Clone()}
	}
	return response, NewSSEParser(response.Body, c.config.SSEIdleTimeout), cancel, nil
}
func (c *Client) Execute(ctx context.Context, token, model string, body []byte) ([]Event, error) {
	response, parser, cancel, err := c.open(ctx, token, model, body)
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer response.Body.Close()
	var events []Event
	for {
		event, err := parser.Next(ctx)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
		eventType := gjson.GetBytes(event.Data, "type").String()
		if eventType == "response.completed" || eventType == "response.incomplete" {
			return events, nil
		}
	}
}
func (c *Client) Stream(ctx context.Context, token, model string, body []byte) (*Stream, error) {
	response, parser, cancel, err := c.open(ctx, token, model, body)
	if err != nil {
		return nil, err
	}
	first, err := parser.Next(ctx)
	if err != nil {
		cancel()
		response.Body.Close()
		return nil, err
	}
	var envelope struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(first.Data, &envelope); err != nil || envelope.Type == "" {
		cancel()
		response.Body.Close()
		return nil, errors.New("upstream returned invalid first SSE event")
	}
	return &Stream{parser: parser, first: &first, body: response.Body, cancel: cancel}, nil
}
