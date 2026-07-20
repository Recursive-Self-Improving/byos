package devin

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	devinproto "byos/internal/devin/proto"
	"byos/internal/provider"
)

var (
	ErrMalformedStream       = errors.New("malformed Devin stream")
	ErrToolArgumentsTooLarge = errors.New("Devin tool arguments exceed configured limit")
)

type StreamMapper struct {
	selectedModel                                         string
	responseID                                            string
	actualModel                                           string
	maxToolBytes                                          int64
	created, terminal, reasoningOpen, reasoningDone       bool
	thinking, signature, text                             string
	stop                                                  devinproto.StopReason
	usage                                                 provider.Usage
	tools                                                 map[string]*mappedTool
	toolOrder                                             []string
	activeTool                                            string
	nextOutput, reasoningIndex, textIndex, sequenceNumber int
	outputItems                                           map[int]any
}

type mappedTool struct {
	id, name, arguments string
	outputIndex         int
	done                bool
}

func NewStreamMapper(selectedModel, responseID string, maxToolArgumentBytes int64) (*StreamMapper, error) {
	if strings.TrimSpace(selectedModel) == "" || maxToolArgumentBytes <= 0 {
		return nil, ErrInvalidClientConfig
	}
	if responseID == "" {
		responseID = "devin-response"
	}
	return &StreamMapper{selectedModel: selectedModel, responseID: responseID, maxToolBytes: maxToolArgumentBytes, tools: make(map[string]*mappedTool), reasoningIndex: -1, textIndex: -1, outputItems: make(map[int]any)}, nil
}

func (m *StreamMapper) Push(frame *devinproto.GetChatMessageResponse) ([]provider.Event, error) {
	if m == nil || frame == nil {
		return nil, ErrMalformedStream
	}
	if m.terminal {
		return nil, nil
	}
	var out []provider.Event
	if m.reasoningDone && (frame.DeltaThinking != "" || frame.DeltaSignature != "") {
		return nil, ErrMalformedStream
	}
	if !m.created && frame.MessageID != "" {
		m.responseID = frame.MessageID
	}
	if frame.ActualModelUID != nil && strings.TrimSpace(*frame.ActualModelUID) != "" {
		m.actualModel = *frame.ActualModelUID
	}
	if frame.DeltaSignature != "" {
		m.signature = frame.DeltaSignature
	}
	if !m.created {
		m.created = true
		ev, err := m.event("response.created", map[string]any{"response": map[string]any{"id": m.responseID, "object": "response", "status": "in_progress", "model": m.model()}})
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	if frame.StopReason != devinproto.StopReasonUnspecified {
		m.stop = frame.StopReason
	}
	if frame.Usage != nil {
		usage, err := checkedUsage(frame.Usage)
		if err != nil {
			return nil, err
		}
		m.usage = usage
	}
	if frame.DeltaThinking != "" {
		if m.reasoningIndex < 0 {
			m.reasoningIndex = m.nextOutput
			m.nextOutput++
		}
		m.reasoningOpen = true
		m.thinking += frame.DeltaThinking
		ev, err := m.event("response.reasoning_summary_text.delta", map[string]any{"delta": frame.DeltaThinking})
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	if frame.DeltaText != "" {
		if m.reasoningOpen && !m.reasoningDone {
			ev, err := m.finishReasoning()
			if err != nil {
				return nil, err
			}
			out = append(out, ev)
		}
		if m.textIndex < 0 {
			m.textIndex = m.nextOutput
			m.nextOutput++
		}
		m.text += frame.DeltaText
		ev, err := m.event("response.output_text.delta", map[string]any{"delta": frame.DeltaText})
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	for _, call := range frame.DeltaToolCalls {
		events, err := m.pushTool(call)
		if err != nil {
			return nil, err
		}
		out = append(out, events...)
	}
	return out, nil
}

func (m *StreamMapper) pushTool(call devinproto.ChatToolCall) ([]provider.Event, error) {
	id := call.ID
	if id == "" {
		id = m.activeTool
		if id == "" {
			return nil, ErrMalformedStream
		}
	}
	t := m.tools[id]
	var out []provider.Event
	if t == nil {
		if call.Name == "" {
			return nil, ErrMalformedStream
		}
		t = &mappedTool{id: id, name: call.Name, outputIndex: m.nextOutput}
		m.nextOutput++
		m.tools[id] = t
		m.toolOrder = append(m.toolOrder, id)
		ev, err := m.event("response.output_item.added", map[string]any{"output_index": t.outputIndex, "item": map[string]any{"type": "function_call", "id": id, "call_id": id, "name": t.name, "arguments": ""}})
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	} else if call.Name != "" && call.Name != t.name {
		return nil, ErrMalformedStream
	}
	m.activeTool = id
	if call.ArgumentsJSON != "" {
		delta := call.ArgumentsJSON
		if strings.HasPrefix(delta, t.arguments) {
			delta = delta[len(t.arguments):]
		}
		if delta != "" {
			if int64(len(t.arguments))+int64(len(delta)) > m.maxToolBytes {
				return nil, ErrToolArgumentsTooLarge
			}
			t.arguments += delta
			ev, err := m.event("response.function_call_arguments.delta", map[string]any{"output_index": t.outputIndex, "item_id": id, "delta": delta})
			if err != nil {
				return nil, err
			}
			out = append(out, ev)
		}
	}
	return out, nil
}

func (m *StreamMapper) Finalize() ([]provider.Event, error) {
	if m == nil {
		return nil, ErrMalformedStream
	}
	if m.terminal {
		return nil, nil
	}
	if m.stop == devinproto.StopReasonError {
		return nil, ErrMalformedStream
	}
	var out []provider.Event
	if !m.created {
		m.created = true
		ev, err := m.event("response.created", map[string]any{"response": map[string]any{"id": m.responseID, "object": "response", "status": "in_progress", "model": m.model()}})
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	if m.reasoningOpen && !m.reasoningDone {
		ev, err := m.finishReasoning()
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	if m.reasoningIndex >= 0 {
		m.outputItems[m.reasoningIndex] = m.reasoningItem()
	}
	if m.text != "" {
		item := map[string]any{"type": "message", "id": "message-0", "role": "assistant", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": m.text, "annotations": []any{}}}}
		m.outputItems[m.textIndex] = item
		ev, err := m.event("response.output_item.done", map[string]any{"output_index": m.textIndex, "item": item})
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	for _, id := range m.toolOrder {
		t := m.tools[id]
		if !json.Valid([]byte(t.arguments)) {
			return nil, ErrMalformedStream
		}
		done, err := m.event("response.function_call_arguments.done", map[string]any{"output_index": t.outputIndex, "item_id": id, "arguments": t.arguments})
		if err != nil {
			return nil, err
		}
		out = append(out, done)
		item := map[string]any{"type": "function_call", "id": id, "call_id": id, "name": t.name, "arguments": t.arguments, "status": "completed"}
		m.outputItems[t.outputIndex] = item
		itemDone, err := m.event("response.output_item.done", map[string]any{"output_index": t.outputIndex, "item": item})
		if err != nil {
			return nil, err
		}
		out = append(out, itemDone)
		t.done = true
	}
	output := make([]any, 0, len(m.outputItems))
	for index := range m.nextOutput {
		if item, ok := m.outputItems[index]; ok {
			output = append(output, item)
		}
	}
	status, reason := "completed", ""
	switch m.stop {
	case devinproto.StopReasonMaxTokens:
		status, reason = "incomplete", "max_output_tokens"
	case devinproto.StopReasonIncomplete, devinproto.StopReasonPartial:
		status, reason = "incomplete", "incomplete"
	case devinproto.StopReasonContentFilter:
		status, reason = "incomplete", "content_filter"
	}
	response := map[string]any{"id": m.responseID, "object": "response", "model": m.model(), "status": status, "output": output, "usage": map[string]any{"input_tokens": m.usage.InputTokens, "output_tokens": m.usage.OutputTokens, "total_tokens": m.usage.TotalTokens, "input_tokens_details": map[string]any{"cached_tokens": m.usage.CacheReadTokens}}}
	if reason != "" {
		response["incomplete_details"] = map[string]any{"reason": reason}
	}
	kind := "response.completed"
	if status == "incomplete" {
		kind = "response.incomplete"
	}
	terminal, err := m.event(kind, map[string]any{"response": response})
	if err != nil {
		return nil, err
	}
	terminal.Usage = m.usage
	out = append(out, terminal)
	m.terminal = true
	return out, nil
}

func (m *StreamMapper) reasoningItem() any {
	return map[string]any{"type": "reasoning", "id": "reasoning-0", "summary": []any{map[string]any{"type": "summary_text", "text": m.thinking}}, "encrypted_content": m.signature}
}
func (m *StreamMapper) finishReasoning() (provider.Event, error) {
	m.reasoningOpen = false
	m.reasoningDone = true
	item := m.reasoningItem()
	m.outputItems[m.reasoningIndex] = item
	return m.event("response.output_item.done", map[string]any{"output_index": m.reasoningIndex, "item": item})
}
func checkedUsage(usage *devinproto.ModelUsageStats) (provider.Usage, error) {
	if usage.InputTokens > math.MaxInt64 || usage.OutputTokens > math.MaxInt64 || usage.CacheReadTokens > math.MaxInt64 || usage.InputTokens > math.MaxInt64-usage.OutputTokens {
		return provider.Usage{}, ErrMalformedStream
	}
	return provider.Usage{InputTokens: int64(usage.InputTokens), OutputTokens: int64(usage.OutputTokens), TotalTokens: int64(usage.InputTokens + usage.OutputTokens), CacheReadTokens: int64(usage.CacheReadTokens)}, nil
}
func (m *StreamMapper) model() string {
	if m.actualModel != "" {
		return m.actualModel
	}
	return m.selectedModel
}
func (m *StreamMapper) event(kind string, fields map[string]any) (provider.Event, error) {
	fields["type"] = kind
	fields["sequence_number"] = m.sequenceNumber
	b, err := json.Marshal(fields)
	if err != nil {
		return provider.Event{}, fmt.Errorf("encode Devin event: %w", err)
	}
	m.sequenceNumber++
	return provider.Event{Event: kind, Data: b}, nil
}
