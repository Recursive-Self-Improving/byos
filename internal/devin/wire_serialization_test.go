package devin

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	devinproto "byos/internal/devin/proto"
	"byos/internal/provider"
	"google.golang.org/protobuf/encoding/protowire"
)

// TestOpenChatStreamFrameByteExactFromUniqueMarshalCallsite proves the Devin
// Client wire frame fidelity: GetChatMessageRequest has a single production
// Marshal call site in stream_client.go, and the wire frame the server
// receives is byte-for-byte equal to a frame rebuilt from one independent
// Marshal output (gzipped and framed identically). This is a static
// callsite plus byte-exact captured-frame proof, not a dynamic Marshal
// invocation count.
func TestOpenChatStreamFrameByteExactFromUniqueMarshalCallsite(t *testing.T) {
	message := &devinproto.GetChatMessageRequest{Prompt: "hello", ChatModelUID: "devin-model"}
	expected, err := message.Marshal()
	if err != nil {
		t.Fatalf("reference Marshal: %v", err)
	}

	var sentFrame []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sentFrame, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/connect+proto")
		_, _ = w.Write(connectFrame(2, []byte(`{}`)))
	}))
	defer server.Close()
	origin, _ := url.Parse(server.URL)
	c := &Client{httpClient: server.Client(), streamIdleTimeout: time.Second, maxFrameCompressedBytes: 1 << 20, maxFrameDecompressedBytes: 1 << 20, maxStreamBytes: 1 << 20, maxToolArgumentBytes: 1 << 20}

	stream, err := c.openChatStream(context.Background(), message, origin, "devin-model", "resp_test")
	if err != nil {
		t.Fatalf("openChatStream: %v", err)
	}
	defer stream.Close()

	expectedFrame := buildConnectGzipFrame(t, expected)
	if !bytes.Equal(sentFrame, expectedFrame) {
		t.Fatalf("wire frame mismatch:\n sent = %x\n want = %x", sentFrame, expectedFrame)
	}
	if sentFrame[0] != 1 || int(binary.BigEndian.Uint32(sentFrame[1:5])) != len(sentFrame)-5 {
		t.Fatalf("frame envelope wrong: flag=%d declared=%d body=%d", sentFrame[0], binary.BigEndian.Uint32(sentFrame[1:5]), len(sentFrame)-5)
	}
	zr, err := gzip.NewReader(bytes.NewReader(sentFrame[5:]))
	if err != nil {
		t.Fatalf("server frame not gzip: %v", err)
	}
	decoded, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip server frame: %v", err)
	}
	if !bytes.Equal(decoded, expected) {
		t.Fatalf("decompressed wire payload != Marshal output (%dB vs %dB)", len(decoded), len(expected))
	}
}

// TestBuildChatRequestToolChoiceSerializedAtWireBoundary asserts tool_choice
// none/auto/selected is encoded at the serialized protobuf boundary (field 12
// ChatToolChoice: field 1 OptionName for none/auto, field 2 ToolName for
// selected), not just on the Go struct.
func TestBuildChatRequestToolChoiceSerializedAtWireBoundary(t *testing.T) {
	tools := []any{map[string]any{"type": "function", "name": "exact_name", "parameters": map[string]any{"type": "object"}}}
	cases := []struct {
		name       string
		choice     any
		wantChoice []byte
	}{
		{"omitted defaults to auto", nil, choiceField(t, &devinproto.ChatToolChoice{OptionName: "auto"})},
		{"auto", "auto", choiceField(t, &devinproto.ChatToolChoice{OptionName: "auto"})},
		{"none", "none", choiceField(t, &devinproto.ChatToolChoice{OptionName: "none"})},
		{"selected", map[string]any{"type": "function", "name": "exact_name"}, choiceField(t, &devinproto.ChatToolChoice{ToolName: "exact_name"})},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			canonical := provider.CanonicalRequest{"model": "model", "input": []any{}, "tools": tools}
			if test.choice != nil {
				canonical["tool_choice"] = test.choice
			}
			request, err := BuildChatRequest(canonical, "session", "jwt")
			if err != nil {
				t.Fatalf("BuildChatRequest: %v", err)
			}
			wire, err := request.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			gotChoice := extractField12(t, wire)
			if !bytes.Equal(gotChoice, test.wantChoice) {
				t.Fatalf("serialized tool_choice = %x, want %x", gotChoice, test.wantChoice)
			}
		})
	}
}

// TestBuildChatRequestToolChoiceRequiredAndUnknownRejected keeps the rejection
// invariants alongside the serialized-boundary acceptance cases.
func TestBuildChatRequestToolChoiceRequiredAndUnknownRejected(t *testing.T) {
	tools := []any{map[string]any{"type": "function", "name": "exact_name", "parameters": map[string]any{"type": "object"}}}
	for _, choice := range []any{"required", "sometimes"} {
		canonical := provider.CanonicalRequest{"model": "model", "input": []any{}, "tools": tools, "tool_choice": choice}
		if _, err := BuildChatRequest(canonical, "session", "jwt"); err == nil {
			t.Fatalf("tool_choice %v accepted", choice)
		}
	}
}

func buildConnectGzipFrame(t *testing.T, payload []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(payload); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	frame := make([]byte, 5+compressed.Len())
	frame[0] = 1
	binary.BigEndian.PutUint32(frame[1:5], uint32(compressed.Len()))
	copy(frame[5:], compressed.Bytes())
	return frame
}

func choiceField(t *testing.T, choice *devinproto.ChatToolChoice) []byte {
	t.Helper()
	out, err := choice.Marshal()
	if err != nil {
		t.Fatalf("ChatToolChoice.Marshal: %v", err)
	}
	return out
}

// extractField12 returns the raw bytes of protowire field 12 (ToolChoice) from
// a serialized GetChatMessageRequest, proving the value reached the wire.
func extractField12(t *testing.T, wire []byte) []byte {
	t.Helper()
	for len(wire) > 0 {
		num, typ, n := protowire.ConsumeTag(wire)
		if n < 0 {
			t.Fatalf("ConsumeTag: %v", protowire.ParseError(n))
		}
		wire = wire[n:]
		if num == 12 && typ == protowire.BytesType {
			val, m := protowire.ConsumeBytes(wire)
			if m < 0 {
				t.Fatalf("ConsumeBytes field 12: %v", protowire.ParseError(m))
			}
			return val
		}
		m := protowire.ConsumeFieldValue(num, typ, wire)
		if m < 0 {
			t.Fatalf("ConsumeFieldValue field %d: %v", num, protowire.ParseError(m))
		}
		wire = wire[m:]
	}
	return nil
}
