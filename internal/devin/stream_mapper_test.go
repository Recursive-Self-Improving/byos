package devin

import (
	"encoding/json"
	"errors"
	"math"
	"testing"

	devinproto "byos/internal/devin/proto"
	"byos/internal/provider"
)

func TestStreamMapperOrderedNeutralEvents(t *testing.T) {
	m, err := NewStreamMapper("requested", "r0", 64)
	if err != nil {
		t.Fatal(err)
	}
	actual := "actual"
	frames := []*devinproto.GetChatMessageResponse{
		{MessageID: "r1", DeltaThinking: "think", DeltaSignature: "sig"},
		{DeltaText: "answer", DeltaToolCalls: []devinproto.ChatToolCall{{ID: "c1", Name: "lookup", ArgumentsJSON: `{"q":`}}},
		{ActualModelUID: &actual, DeltaToolCalls: []devinproto.ChatToolCall{{ID: "c1", ArgumentsJSON: `{"q":"x"}`}}, Usage: &devinproto.ModelUsageStats{InputTokens: 2, OutputTokens: 3, CacheReadTokens: 1}, StopReason: devinproto.StopReasonFunctionCall},
	}
	var got []provider.Event
	for _, f := range frames {
		events, e := m.Push(f)
		if e != nil {
			t.Fatal(e)
		}
		got = append(got, events...)
	}
	events, err := m.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, events...)
	want := []string{"response.created", "response.reasoning_summary_text.delta", "response.output_item.done", "response.output_text.delta", "response.output_item.added", "response.function_call_arguments.delta", "response.function_call_arguments.delta", "response.output_item.done", "response.function_call_arguments.done", "response.output_item.done", "response.completed"}
	if len(got) != len(want) {
		t.Fatalf("events=%v", got)
	}
	for i := range want {
		if got[i].Event != want[i] {
			t.Fatalf("event %d=%q, want %q", i, got[i].Event, want[i])
		}
		assertSequenceNumber(t, got[i], i)
	}
	terminal := got[len(got)-1]
	if terminal.Usage.InputTokens != 2 || terminal.Usage.OutputTokens != 3 || terminal.Usage.TotalTokens != 5 || terminal.Usage.CacheReadTokens != 1 {
		t.Fatalf("usage=%+v", terminal.Usage)
	}
	var envelope map[string]any
	if json.Unmarshal(terminal.Data, &envelope) != nil {
		t.Fatal("invalid terminal JSON")
	}
	response := envelope["response"].(map[string]any)
	if response["model"] != "actual" {
		t.Fatalf("response=%s", terminal.Data)
	}
	again, err := m.Finalize()
	if err != nil || len(again) != 0 {
		t.Fatalf("duplicate terminal: %v %v", again, err)
	}
}

func TestStreamMapperToolArgumentRules(t *testing.T) {
	m, _ := NewStreamMapper("m", "r", 7)
	if _, err := m.Push(&devinproto.GetChatMessageResponse{DeltaToolCalls: []devinproto.ChatToolCall{{Name: "x", ArgumentsJSON: "{}"}}}); !errors.Is(err, ErrMalformedStream) {
		t.Fatalf("missing id error=%v", err)
	}
	m, _ = NewStreamMapper("m", "r", 7)
	if _, err := m.Push(&devinproto.GetChatMessageResponse{DeltaToolCalls: []devinproto.ChatToolCall{{ID: "c", Name: "x", ArgumentsJSON: `{"a":1}`}}}); err != nil {
		t.Fatal(err)
	}
	events, err := m.Push(&devinproto.GetChatMessageResponse{DeltaToolCalls: []devinproto.ChatToolCall{{ID: "c", ArgumentsJSON: `{"a":1}`}}})
	if err != nil || len(events) != 0 {
		t.Fatalf("identical cumulative=%v %v", events, err)
	}
	if _, err = m.Push(&devinproto.GetChatMessageResponse{DeltaToolCalls: []devinproto.ChatToolCall{{ID: "c", ArgumentsJSON: "x"}}}); !errors.Is(err, ErrToolArgumentsTooLarge) {
		t.Fatalf("limit error=%v", err)
	}
}

func TestStreamMapperStopAndCleanEOF(t *testing.T) {
	for _, tc := range []struct {
		reason devinproto.StopReason
		event  string
	}{{devinproto.StopReasonUnspecified, "response.completed"}, {devinproto.StopReasonMaxTokens, "response.incomplete"}, {devinproto.StopReasonContentFilter, "response.incomplete"}} {
		m, _ := NewStreamMapper("m", "r", 8)
		var events []provider.Event
		if tc.reason != 0 {
			pushed, err := m.Push(&devinproto.GetChatMessageResponse{StopReason: tc.reason})
			if err != nil {
				t.Fatal(err)
			}
			events = append(events, pushed...)
		}
		finalized, err := m.Finalize()
		events = append(events, finalized...)
		if err != nil {
			t.Fatal(err)
		}
		if events[len(events)-1].Event != tc.event {
			t.Fatalf("reason %v => %v", tc.reason, events)
		}
		for i, event := range events {
			assertSequenceNumber(t, event, i)
		}
	}
	m, _ := NewStreamMapper("m", "r", 8)
	_, _ = m.Push(&devinproto.GetChatMessageResponse{StopReason: devinproto.StopReasonError})
	if _, err := m.Finalize(); !errors.Is(err, ErrMalformedStream) {
		t.Fatalf("error stop=%v", err)
	}
}

func TestStreamMapperStableTerminalOutputFixture(t *testing.T) {
	m, err := NewStreamMapper("requested", "initial", 64)
	if err != nil {
		t.Fatal(err)
	}
	frames := []*devinproto.GetChatMessageResponse{
		{MessageID: "created-id", DeltaThinking: "first", DeltaSignature: "sig-old"},
		{MessageID: "ignored-late-id", DeltaThinking: " second", DeltaSignature: ""},
		{DeltaSignature: "sig-latest", DeltaToolCalls: []devinproto.ChatToolCall{{ID: "call-1", Name: "lookup", ArgumentsJSON: `{"q":"x"}`}}},
		{DeltaText: "answer"},
	}
	for _, frame := range frames {
		if _, err := m.Push(frame); err != nil {
			t.Fatal(err)
		}
	}
	events, err := m.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Response struct {
			ID     string            `json:"id"`
			Output []json.RawMessage `json:"output"`
		} `json:"response"`
	}
	if err := json.Unmarshal(events[len(events)-1].Data, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Response.ID != "created-id" {
		t.Fatalf("response id=%q", envelope.Response.ID)
	}
	got, err := json.Marshal(envelope.Response.Output)
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"encrypted_content":"sig-latest","id":"reasoning-0","summary":[{"text":"first second","type":"summary_text"}],"type":"reasoning"},{"arguments":"{\"q\":\"x\"}","call_id":"call-1","id":"call-1","name":"lookup","status":"completed","type":"function_call"},{"content":[{"annotations":[],"text":"answer","type":"output_text"}],"id":"message-0","role":"assistant","status":"completed","type":"message"}]`
	if string(got) != want {
		t.Fatalf("terminal output\n got: %s\nwant: %s", got, want)
	}
}

func TestStreamMapperRejectsReasoningAfterTextBoundary(t *testing.T) {
	m, _ := NewStreamMapper("m", "r", 64)
	for _, frame := range []*devinproto.GetChatMessageResponse{{DeltaThinking: "a", DeltaSignature: "one"}, {DeltaText: "b"}} {
		if _, err := m.Push(frame); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.Push(&devinproto.GetChatMessageResponse{DeltaThinking: "c", DeltaSignature: "two"}); !errors.Is(err, ErrMalformedStream) {
		t.Fatalf("reopened reasoning error=%v", err)
	}
	events, err := m.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Response struct {
			Output []struct {
				Type             string `json:"type"`
				EncryptedContent string `json:"encrypted_content"`
				Summary          []struct {
					Text string `json:"text"`
				} `json:"summary"`
			} `json:"output"`
		} `json:"response"`
	}
	if err := json.Unmarshal(events[len(events)-1].Data, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Response.Output[0].EncryptedContent != "one" || envelope.Response.Output[0].Summary[0].Text != "a" {
		t.Fatalf("reasoning=%s", events[len(events)-1].Data)
	}
}

func TestStreamMapperRejectsUsageOverflow(t *testing.T) {
	fixtures := []devinproto.ModelUsageStats{
		{InputTokens: math.MaxInt64 + 1},
		{OutputTokens: math.MaxInt64 + 1},
		{CacheReadTokens: math.MaxInt64 + 1},
		{InputTokens: math.MaxInt64, OutputTokens: 1},
	}
	for _, usage := range fixtures {
		m, _ := NewStreamMapper("m", "r", 8)
		if _, err := m.Push(&devinproto.GetChatMessageResponse{Usage: &usage}); !errors.Is(err, ErrMalformedStream) {
			t.Fatalf("usage=%+v error=%v", usage, err)
		}
	}
}

func assertSequenceNumber(t *testing.T, event provider.Event, want int) {
	t.Helper()
	var envelope struct {
		SequenceNumber *int `json:"sequence_number"`
	}
	if err := json.Unmarshal(event.Data, &envelope); err != nil {
		t.Fatalf("%s is not valid JSON: %v", event.Event, err)
	}
	if envelope.SequenceNumber == nil || *envelope.SequenceNumber != want {
		t.Fatalf("%s sequence_number=%v, want %d: %s", event.Event, envelope.SequenceNumber, want, event.Data)
	}
}
