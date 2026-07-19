package proto

import (
	"math"
	"reflect"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func bytesFixture(b []byte, field protowire.Number, value []byte) []byte {
	b = protowire.AppendTag(b, field, protowire.BytesType)
	return protowire.AppendBytes(b, value)
}

func stringFixture(b []byte, field protowire.Number, value string) []byte {
	return bytesFixture(b, field, []byte(value))
}

func varintFixture(b []byte, field protowire.Number, value uint64) []byte {
	b = protowire.AppendTag(b, field, protowire.VarintType)
	return protowire.AppendVarint(b, value)
}

func TestGetChatMessageResponseUnmarshalFixture(t *testing.T) {
	tool := stringFixture(nil, 1, "call-1")
	tool = stringFixture(tool, 2, "lookup")
	tool = stringFixture(tool, 3, `{"q":"go"}`)
	tool = varintFixture(tool, 31, 9)
	usage := varintFixture(nil, 2, 11)
	usage = varintFixture(usage, 3, 7)
	usage = varintFixture(usage, 4, 5)
	usage = varintFixture(usage, 5, 3)
	usage = stringFixture(usage, 7, "usage-message")
	usage = stringFixture(usage, 9, "actual")
	usage = stringFixture(usage, 10, "billing")
	usage = stringFixture(usage, 11, "requested")
	usage = stringFixture(usage, 30, "ignored")

	fixture := stringFixture(nil, 1, "message")
	fixture = stringFixture(fixture, 3, "delta")
	fixture = varintFixture(fixture, 4, 17)
	fixture = varintFixture(fixture, 5, uint64(StopReasonFunctionCall))
	fixture = bytesFixture(fixture, 6, tool)
	fixture = bytesFixture(fixture, 7, usage)
	fixture = stringFixture(fixture, 9, "thought")
	fixture = stringFixture(fixture, 10, "signature")
	fixture = stringFixture(fixture, 15, "output")
	fixture = stringFixture(fixture, 17, "request")
	fixture = stringFixture(fixture, 21, "sig-type")
	fixture = stringFixture(fixture, 23, "model")
	fixture = stringFixture(fixture, 25, "analysis")
	fixture = varintFixture(fixture, 99, 1)

	var got GetChatMessageResponse
	if err := got.Unmarshal(fixture); err != nil {
		t.Fatal(err)
	}
	want := GetChatMessageResponse{
		MessageID: "message", DeltaText: "delta", DeltaTokens: 17, StopReason: StopReasonFunctionCall,
		DeltaToolCalls: []ChatToolCall{{ID: "call-1", Name: "lookup", ArgumentsJSON: `{"q":"go"}`}},
		Usage:          &ModelUsageStats{ModelUID: "actual", BillingModelUID: "billing", RequestedModelUID: "requested", InputTokens: 11, OutputTokens: 7, CacheWriteTokens: 5, CacheReadTokens: 3, MessageID: "usage-message"},
		DeltaThinking:  "thought", DeltaSignature: "signature", OutputID: "output", RequestID: "request", DeltaSignatureType: "sig-type", ActualModelUID: new("model"), Phase: "analysis",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded response mismatch\n got: %#v\nwant: %#v", got, want)
	}

	for i := range fixture {
		fixture[i] = 0
	}
	if got.MessageID != "message" || got.DeltaToolCalls[0].ArgumentsJSON != `{"q":"go"}` || got.Usage.ModelUID != "actual" || *got.ActualModelUID != "model" {
		t.Fatalf("decoder retained input storage: %#v", got)
	}
}

func TestResponseUnmarshalRejectsMalformedWire(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{"known wire mismatch", varintFixture(nil, 1, 1)},
		{"truncated string", []byte{0x0a, 0x02, 'x'}},
		{"truncated nested", []byte{0x32, 0x02, 0x0a}},
		{"varint overflow", append([]byte{0x20}, []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02}...)},
		{"uint32 overflow", varintFixture(nil, 4, uint64(math.MaxUint32)+1)},
		{"enum overflow", varintFixture(nil, 5, uint64(math.MaxInt32)+1)},
		{"invalid unknown", []byte{0x7f}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var response GetChatMessageResponse
			if err := response.Unmarshal(test.payload); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestNestedUnmarshalRejectsWireMismatchAndCopies(t *testing.T) {
	toolPayload := stringFixture(nil, 1, "id")
	var tool ChatToolCall
	if err := tool.Unmarshal(toolPayload); err != nil {
		t.Fatal(err)
	}
	toolPayload[len(toolPayload)-1] = 'x'
	if tool.ID != "id" {
		t.Fatalf("tool call retained input: %q", tool.ID)
	}
	if err := tool.Unmarshal(varintFixture(nil, 2, 1)); err == nil {
		t.Fatal("expected tool wire mismatch")
	}

	usagePayload := stringFixture(nil, 9, "model")
	var usage ModelUsageStats
	if err := usage.Unmarshal(usagePayload); err != nil {
		t.Fatal(err)
	}
	usagePayload[len(usagePayload)-1] = 'x'
	if usage.ModelUID != "model" {
		t.Fatalf("usage retained input: %q", usage.ModelUID)
	}
	if err := usage.Unmarshal(stringFixture(nil, 2, "bad")); err == nil {
		t.Fatal("expected usage wire mismatch")
	}
}

func TestResponseUnmarshalBounds(t *testing.T) {
	var response GetChatMessageResponse
	if err := response.Unmarshal(make([]byte, maxUnmarshalBytes+1)); err == nil {
		t.Fatal("expected message size error")
	}
	payload := make([]byte, 0, maxDeltaToolCalls*2+2)
	for range maxDeltaToolCalls + 1 {
		payload = bytesFixture(payload, 6, nil)
	}
	if err := response.Unmarshal(payload); err == nil {
		t.Fatal("expected tool call count error")
	}
}
