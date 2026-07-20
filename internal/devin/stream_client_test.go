package devin

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	devinproto "byos/internal/devin/proto"
	"byos/internal/provider"
	"google.golang.org/protobuf/encoding/protowire"
)

func connectFrame(flag byte, payload []byte) []byte {
	if flag&1 != 0 {
		var b bytes.Buffer
		z := gzip.NewWriter(&b)
		_, _ = z.Write(payload)
		_ = z.Close()
		payload = b.Bytes()
	}
	out := make([]byte, 5+len(payload))
	out[0] = flag
	binary.BigEndian.PutUint32(out[1:], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}
func decoder(data []byte) *connectStream {
	return &connectStream{body: io.NopCloser(bytes.NewReader(data)), cancel: func() {}, ctx: context.Background(), idle: time.Second, maxCompressed: 32, maxDecompressed: 32, maxTotal: 64}
}
func decoderBig(data []byte) *connectStream {
	return &connectStream{body: io.NopCloser(bytes.NewReader(data)), cancel: func() {}, ctx: context.Background(), idle: time.Second, maxCompressed: 1 << 20, maxDecompressed: 1 << 20, maxTotal: 1 << 20}
}

func TestConnectFrameRawGzipAndEOF(t *testing.T) {
	for _, flag := range []byte{0, 1, 2, 3} {
		s := decoder(connectFrame(flag, []byte("abc")))
		got, payload, eof, err := s.readFrame(context.Background())
		if err != nil || eof || got != flag || string(payload) != "abc" {
			t.Fatalf("flag %d: %d %q %v %v", flag, got, payload, eof, err)
		}
		_, _, eof, err = s.readFrame(context.Background())
		if err != nil || !eof {
			t.Fatalf("clean EOF: %v %v", eof, err)
		}
	}
}

func TestConnectFrameAdversarialMatrix(t *testing.T) {
	for n := 1; n <= 4; n++ {
		s := decoder(make([]byte, n))
		if _, _, _, err := s.readFrame(context.Background()); !errors.Is(err, ErrStreamTruncated) {
			t.Fatalf("header %d: %v", n, err)
		}
	}
	partial := []byte{0, 0, 0, 0, 3, 'x'}
	if _, _, _, err := decoder(partial).readFrame(context.Background()); !errors.Is(err, ErrStreamTruncated) {
		t.Fatalf("payload: %v", err)
	}
	invalid := connectFrame(4, nil)
	if _, _, _, err := decoder(invalid).readFrame(context.Background()); !errors.Is(err, ErrMalformedStream) {
		t.Fatalf("flag: %v", err)
	}
	over := connectFrame(0, bytes.Repeat([]byte{'x'}, 33))
	if _, _, _, err := decoder(over).readFrame(context.Background()); !errors.Is(err, ErrStreamFrameTooLarge) {
		t.Fatalf("raw limit: %v", err)
	}
	bomb := decoder(connectFrame(1, bytes.Repeat([]byte{'x'}, 33)))
	if _, _, _, err := bomb.readFrame(context.Background()); !errors.Is(err, ErrStreamFrameTooLarge) {
		t.Fatalf("gzip limit: %v", err)
	}
	s := decoder(append(connectFrame(0, bytes.Repeat([]byte{'x'}, 32)), connectFrame(0, bytes.Repeat([]byte{'y'}, 32))...))
	if _, _, _, err := s.readFrame(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.readFrame(context.Background()); err != nil {
		t.Fatal(err)
	}
	s = decoder(append(connectFrame(0, bytes.Repeat([]byte{'x'}, 32)), connectFrame(0, bytes.Repeat([]byte{'y'}, 33))...))
	if _, _, _, err := s.readFrame(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.readFrame(context.Background()); !errors.Is(err, ErrStreamFrameTooLarge) {
		t.Fatalf("total/individual limit: %v", err)
	}
}

func TestConnectStreamMapsAndRejectsMalformedTrailer(t *testing.T) {
	proto := protowire.AppendTag(nil, 3, protowire.BytesType)
	proto = protowire.AppendString(proto, "hi")
	mapper, _ := NewStreamMapper("m", "r", 32)
	s := decoder(append(connectFrame(0, proto), connectFrame(2, []byte(`{}`))...))
	s.mapper = mapper
	var kinds []string
	for {
		event, err := s.Next(context.Background())
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		kinds = append(kinds, event.Event)
	}
	if len(kinds) < 3 || kinds[0] != "response.created" || kinds[len(kinds)-1] != "response.completed" {
		t.Fatalf("events=%v", kinds)
	}
	mapper, _ = NewStreamMapper("m", "r", 32)
	s = decoder(connectFrame(2, []byte(`{`)))
	s.mapper = mapper
	if _, err := s.Next(context.Background()); !errors.Is(err, ErrMalformedStream) {
		t.Fatalf("trailer=%v", err)
	}
}

// TestConnectStreamRequiresEndStreamEnvelope asserts the final security
// invariant: a successful finalize requires a valid non-empty, parseable,
// error-free Connect EndStream envelope. Raw EOF before EndStream (whether a
// zero-byte fresh EOF or EOF after partial data delivery) is truncated; empty
// or malformed EndStream payloads are rejected; finalize happens exactly once.
func TestConnectStreamRequiresEndStreamEnvelope(t *testing.T) {
	// Zero-byte fresh EOF: no EndStream envelope at all.
	mapper, _ := NewStreamMapper("m", "r", 32)
	fresh := decoder(nil)
	fresh.mapper = mapper
	if _, err := fresh.Next(context.Background()); !errors.Is(err, ErrStreamTruncated) {
		t.Fatalf("fresh EOF = %v; want ErrStreamTruncated", err)
	}

	// Partial data delivery then EOF: data frames without a terminal envelope.
	proto := protowire.AppendTag(nil, 3, protowire.BytesType)
	proto = protowire.AppendString(proto, "hi")
	mapper, _ = NewStreamMapper("m", "r", 32)
	partial := decoder(connectFrame(0, proto))
	partial.mapper = mapper
	for {
		_, err := partial.Next(context.Background())
		if err != nil {
			if !errors.Is(err, ErrStreamTruncated) {
				t.Fatalf("EOF after partial data = %v; want ErrStreamTruncated", err)
			}
			break
		}
	}

	// Empty EndStream payload rejected.
	mapper, _ = NewStreamMapper("m", "r", 32)
	emptyEnd := decoder(connectFrame(2, nil))
	emptyEnd.mapper = mapper
	if _, err := emptyEnd.Next(context.Background()); !errors.Is(err, ErrMalformedStream) {
		t.Fatalf("empty EndStream = %v; want ErrMalformedStream", err)
	}

	// EndStream carrying a valid Connect error is classified, not rejected:
	// a recognized code maps to a typed provider.UpstreamError so routing can
	// fail over before any event is emitted. Finalize must not run.
	mapper, _ = NewStreamMapper("m", "r", 32)
	errEnd := decoderBig(connectFrame(2, []byte(`{"error":{"code":"unavailable","message":"boom"}}`)))
	errEnd.mapper = mapper
	_, err := errEnd.Next(context.Background())
	var upstream *provider.UpstreamError
	if !errors.As(err, &upstream) || upstream.Provider != provider.Devin || upstream.Classification.Class != provider.ClassTransient || !upstream.Classification.RetryNext {
		t.Fatalf("error EndStream = %v; want typed ClassTransient", err)
	}
	if mapper.terminal {
		t.Fatal("mapper finalized on error-bearing EndStream")
	}
	// A structurally invalid Connect error is still rejected as malformed.
	mapper, _ = NewStreamMapper("m", "r", 32)
	malformed := decoderBig(connectFrame(2, []byte(`{"error":null}`)))
	malformed.mapper = mapper
	if _, err := malformed.Next(context.Background()); !errors.Is(err, ErrMalformedStream) {
		t.Fatalf("null error EndStream = %v; want ErrMalformedStream", err)
	}

	// Finalize exactly once: after a valid EndStream, subsequent Next calls
	// return io.EOF without re-entering Finalize. Drain the whole stream and
	// confirm a follow-up call does not error with anything but io.EOF.
	mapper, _ = NewStreamMapper("m", "r", 32)
	valid := decoder(append(connectFrame(0, proto), connectFrame(2, []byte(`{}`))...))
	valid.mapper = mapper
	var count int
	for {
		_, err := valid.Next(context.Background())
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("drain: %v", err)
		}
		count++
	}
	if count == 0 {
		t.Fatal("no events emitted from valid stream")
	}
	// Repeated terminal reads must stay io.EOF and must not re-finalize.
	for i := 0; i < 3; i++ {
		if _, err := valid.Next(context.Background()); !errors.Is(err, io.EOF) {
			t.Fatalf("post-terminal call %d = %v; want io.EOF", i, err)
		}
	}
	if !mapper.terminal {
		t.Fatal("mapper not marked terminal after EndStream")
	}
}

// TestConnectEndStreamEnvelopeMatrix exercises the EndStream parsing rules as
// a table: a top-level JSON object is required; on success the error key must
// be omitted entirely and trailer metadata must be exactly
// map[string][]string (arrays of UTF-8 strings); a valid Connect error object
// is mapped to a typed provider.UpstreamError; and structurally invalid
// envelopes, error objects, and metadata are rejected as malformed. Finalize
// runs exactly once after a valid success envelope and never on an error or
// malformed envelope.
func TestConnectEndStreamEnvelopeMatrix(t *testing.T) {
	type metaExpect struct {
		present bool
		keys    []string
		values  map[string][]string
	}
	cases := []struct {
		name      string
		payload   []byte
		wantErr   error
		wantClass provider.ErrorClass
		finalized bool
		meta      metaExpect
	}{
		// Valid success envelopes: object with no error key.
		{
			name:      "empty object",
			payload:   []byte(`{}`),
			finalized: true,
		},
		{
			name:      "object with valid metadata",
			payload:   []byte(`{"metadata":{"x":["YWJj"],"trace-id":["ZGVm"]}}`),
			finalized: true,
			meta:      metaExpect{present: true, keys: []string{"x", "trace-id"}, values: map[string][]string{"x": {"YWJj"}, "trace-id": {"ZGVm"}}},
		},
		{
			name:      "metadata multi-value array preserved",
			payload:   []byte(`{"metadata":{"x":["a","b"]}}`),
			finalized: true,
			meta:      metaExpect{present: true, keys: []string{"x"}, values: map[string][]string{"x": {"a", "b"}}},
		},
		{
			name:      "metadata empty array preserved",
			payload:   []byte(`{"metadata":{"x":[]}}`),
			finalized: true,
			meta:      metaExpect{present: true, keys: []string{"x"}, values: map[string][]string{"x": {}}},
		},
		{
			name:      "metadata null treated as absent",
			payload:   []byte(`{"metadata":null}`),
			finalized: true,
		},
		{
			name:      "extra unknown keys tolerated",
			payload:   []byte(`{"foo":"bar","baz":42}`),
			finalized: true,
		},
		// Valid Connect error objects: mapped to a typed UpstreamError, not
		// rejected as malformed. Finalize must not run.
		{
			name:      "error unavailable transient",
			payload:   []byte(`{"error":{"code":"unavailable","message":"boom"}}`),
			wantClass: provider.ClassTransient,
		},
		{
			name:      "error internal transient",
			payload:   []byte(`{"error":{"code":"internal","message":"boom"}}`),
			wantClass: provider.ClassTransient,
		},
		{
			name:      "error resource_exhausted rate limit",
			payload:   []byte(`{"error":{"code":"resource_exhausted"}}`),
			wantClass: provider.ClassRateLimit,
		},
		{
			name:      "error unauthenticated relogin",
			payload:   []byte(`{"error":{"code":"unauthenticated"}}`),
			wantClass: provider.ClassUnauthorized,
		},
		{
			name:      "error permission_denied permission",
			payload:   []byte(`{"error":{"code":"permission_denied"}}`),
			wantClass: provider.ClassPermission,
		},
		{
			name:      "error invalid_argument validation",
			payload:   []byte(`{"error":{"code":"invalid_argument"}}`),
			wantClass: provider.ClassValidation,
		},
		{
			name:      "error unrecognized code typed upstream",
			payload:   []byte(`{"error":{"code":"data_loss","message":"x"}}`),
			wantClass: provider.ClassUpstream,
		},
		{
			name:      "error alongside valid metadata classifies and preserves metadata",
			payload:   []byte(`{"metadata":{"x":["YWJj"]},"error":{"code":"unavailable","message":"y"}}`),
			wantClass: provider.ClassTransient,
			meta:      metaExpect{present: true, keys: []string{"x"}, values: map[string][]string{"x": {"YWJj"}}},
		},
		// Rejected: a valid Connect error alongside malformed metadata is
		// rejected as ErrMalformedStream with no classification — metadata is
		// parsed and strictly validated before the error branch, so a
		// structurally invalid termination is never classified.
		{
			name:    "error alongside malformed metadata rejected no classification",
			payload: []byte(`{"metadata":{"x":"YWJj"},"error":{"code":"unavailable","message":"y"}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error alongside metadata non-array value rejected",
			payload: []byte(`{"metadata":{"x":[1]},"error":{"code":"unavailable"}}`),
			wantErr: ErrMalformedStream,
		},
		// Rejected: empty payload.
		{
			name:    "empty payload",
			payload: nil,
			wantErr: ErrMalformedStream,
		},
		// Rejected: top-level not an object.
		{
			name:    "null top-level",
			payload: []byte(`null`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "array top-level",
			payload: []byte(`[]`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "array with content",
			payload: []byte(`[1,2,3]`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "string scalar",
			payload: []byte(`"oops"`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "number scalar",
			payload: []byte(`42`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "bool scalar",
			payload: []byte(`true`),
			wantErr: ErrMalformedStream,
		},
		// Rejected: malformed JSON.
		{
			name:    "truncated json",
			payload: []byte(`{`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "garbage",
			payload: []byte(`not json`),
			wantErr: ErrMalformedStream,
		},
		// Rejected: structurally invalid error object.
		{
			name:    "error null",
			payload: []byte(`{"error":null}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error missing code",
			payload: []byte(`{"error":{"message":"boom"}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error empty code",
			payload: []byte(`{"error":{"code":""}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error null code",
			payload: []byte(`{"error":{"code":null}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error non-string code",
			payload: []byte(`{"error":{"code":5}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error string malformed type",
			payload: []byte(`{"error":"boom"}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error number malformed type",
			payload: []byte(`{"error":5}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error array malformed type",
			payload: []byte(`{"error":[]}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error invalid message field type",
			payload: []byte(`{"error":{"code":"internal","message":5}}`),
			wantErr: ErrMalformedStream,
		},
		// Rejected: a present-but-null message is structurally invalid. The
		// message key is optional, but when present it must be a JSON string;
		// null is not a string, so the termination is malformed and never
		// classified, regardless of an otherwise-valid code.
		{
			name:    "error null message rejected",
			payload: []byte(`{"error":{"code":"internal","message":null}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error bool message rejected",
			payload: []byte(`{"error":{"code":"internal","message":true}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error array message rejected",
			payload: []byte(`{"error":{"code":"internal","message":[]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error object message rejected",
			payload: []byte(`{"error":{"code":"internal","message":{}}}`),
			wantErr: ErrMalformedStream,
		},
		// Valid: an empty message string is allowed (the spec permits a
		// present-but-empty message) and still classified.
		{
			name:      "error empty message string allowed",
			payload:   []byte(`{"error":{"code":"internal","message":""}}`),
			wantClass: provider.ClassTransient,
		},
		// Valid: a missing message key is allowed (message is optional) and
		// the error is classified by code alone.
		{
			name:      "error absent message allowed",
			payload:   []byte(`{"error":{"code":"internal"}}`),
			wantClass: provider.ClassTransient,
		},
		{
			name:    "error invalid details field type",
			payload: []byte(`{"error":{"code":"internal","details":"x"}}`),
			wantErr: ErrMalformedStream,
		},
		// Valid Connect error details: a non-null details array of objects
		// with non-empty string type and a standard-base64 string value
		// (unpadded canonical, padded accepted, URL-safe rejected) is accepted
		// and classified, never finalized.
		{
			name:      "error valid details element",
			payload:   []byte(`{"error":{"code":"internal","details":[{"type":"google.rpc.BadRequest","value":"YWJj"}]}}`),
			wantClass: provider.ClassTransient,
		},
		{
			name:      "error details unpadded spec example CgIIPA",
			payload:   []byte(`{"error":{"code":"internal","details":[{"type":"google.rpc.BadRequest","value":"CgIIPA"}]}}`),
			wantClass: provider.ClassTransient,
		},
		{
			name:      "error details padded base64 accepted",
			payload:   []byte(`{"error":{"code":"internal","details":[{"type":"t","value":"YWJ="}]}}`),
			wantClass: provider.ClassTransient,
		},
		{
			name:      "error empty details array",
			payload:   []byte(`{"error":{"code":"internal","details":[]}}`),
			wantClass: provider.ClassTransient,
		},
		{
			name:      "error null details field treated as absent",
			payload:   []byte(`{"error":{"code":"internal","details":null}}`),
			wantClass: provider.ClassTransient,
		},
		{
			name:      "error details empty value is valid base64",
			payload:   []byte(`{"error":{"code":"internal","details":[{"type":"t","value":""}]}}`),
			wantClass: provider.ClassTransient,
		},
		{
			name:      "error details multiple valid elements",
			payload:   []byte(`{"error":{"code":"internal","details":[{"type":"a","value":"YWJj"},{"type":"b","value":"ZGVm"}]}}`),
			wantClass: provider.ClassTransient,
		},
		// Rejected: structurally invalid error details elements.
		{
			name:    "error details null element",
			payload: []byte(`{"error":{"code":"internal","details":[null]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error details scalar element",
			payload: []byte(`{"error":{"code":"internal","details":[5]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error details string element",
			payload: []byte(`{"error":{"code":"internal","details":["x"]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error details array element",
			payload: []byte(`{"error":{"code":"internal","details":[[]]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error details object missing both keys",
			payload: []byte(`{"error":{"code":"internal","details":[{}]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error details missing type",
			payload: []byte(`{"error":{"code":"internal","details":[{"value":"YWJj"}]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error details missing value",
			payload: []byte(`{"error":{"code":"internal","details":[{"type":"t"}]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error details empty type",
			payload: []byte(`{"error":{"code":"internal","details":[{"type":"","value":"YWJj"}]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error details null type",
			payload: []byte(`{"error":{"code":"internal","details":[{"type":null,"value":"YWJj"}]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error details null value",
			payload: []byte(`{"error":{"code":"internal","details":[{"type":"t","value":null}]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error details non-string type",
			payload: []byte(`{"error":{"code":"internal","details":[{"type":5,"value":"YWJj"}]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error details non-string value",
			payload: []byte(`{"error":{"code":"internal","details":[{"type":"t","value":5}]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error details invalid base64 value",
			payload: []byte(`{"error":{"code":"internal","details":[{"type":"t","value":"!!!"}]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "error details url-safe base64 rejected",
			payload: []byte(`{"error":{"code":"internal","details":[{"type":"t","value":"YWJ-_"}]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:      "error details unpadded base64 accepted",
			payload:   []byte(`{"error":{"code":"internal","details":[{"type":"t","value":"YWJ"}]}}`),
			wantClass: provider.ClassTransient,
		},
		{
			name:    "error details one invalid among valid",
			payload: []byte(`{"error":{"code":"internal","details":[{"type":"a","value":"YWJj"},{"type":"b","value":"!!!"}]}}`),
			wantErr: ErrMalformedStream,
		},
		// Rejected: metadata present but not a valid object.
		{
			name:    "metadata string",
			payload: []byte(`{"metadata":"x"}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "metadata array",
			payload: []byte(`{"metadata":[1]}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "metadata number",
			payload: []byte(`{"metadata":5}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "metadata bool",
			payload: []byte(`{"metadata":true}`),
			wantErr: ErrMalformedStream,
		},
		// Rejected: metadata values that are not arrays of UTF-8 strings.
		{
			name:    "metadata scalar string value",
			payload: []byte(`{"metadata":{"x":"YWJj"}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "metadata null value",
			payload: []byte(`{"metadata":{"x":null}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "metadata object value",
			payload: []byte(`{"metadata":{"x":{"a":"b"}}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "metadata number array",
			payload: []byte(`{"metadata":{"x":[1,2]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "metadata mixed non-string array",
			payload: []byte(`{"metadata":{"x":["a",1]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "metadata bool array",
			payload: []byte(`{"metadata":{"x":[true]}}`),
			wantErr: ErrMalformedStream,
		},
		// Rejected: metadata keys are parsed from raw JSON so encoding/json
		// cannot normalize them. Invalid raw UTF-8, lone surrogates, and
		// non-header-name keys are rejected as malformed.
		{
			name:    "metadata key raw invalid utf-8",
			payload: []byte("{\"metadata\":{\"\xc0y\":[\"a\"]}}"),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "metadata key lone surrogate",
			payload: []byte(`{"metadata":{"\ud800":["a"]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "metadata key high surrogate without low",
			payload: []byte(`{"metadata":{"\ud83d\":[\"a\"]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "metadata key empty string",
			payload: []byte(`{"metadata":{"":["a"]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "metadata key invalid header char space",
			payload: []byte(`{"metadata":{"a b":["a"]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "metadata key invalid header char colon",
			payload: []byte(`{"metadata":{"a:b":["a"]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "metadata key non-ascii literal",
			payload: []byte(`{"metadata":{"café":["a"]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "metadata key paired surrogate non-ascii",
			payload: []byte(`{"metadata":{"\ud83d\ude00":["a"]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "metadata duplicate exact key",
			payload: []byte(`{"metadata":{"x":["a"],"x":["b"]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "metadata key uppercase letter rejected",
			payload: []byte(`{"metadata":{"X":["a"]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "metadata key mixed case rejected",
			payload: []byte(`{"metadata":{"X-Trace-Id":["a"]}}`),
			wantErr: ErrMalformedStream,
		},
		{
			name:    "metadata key disallowed token punctuation rejected",
			payload: []byte(`{"metadata":{"a!b":["a"]}}`),
			wantErr: ErrMalformedStream,
		},
		// Accepted: valid Connect header names, exactly [0-9a-z_.-]+
		// (lowercase letters, digits, underscore, hyphen, dot).
		{
			name:      "metadata key full allowed charset",
			payload:   []byte(`{"metadata":{"0123456789abcxyz._-":["a"]}}`),
			finalized: true,
			meta:      metaExpect{present: true, keys: []string{"0123456789abcxyz._-"}, values: map[string][]string{"0123456789abcxyz._-": {"a"}}},
		},
		{
			name:      "metadata key lowercase with hyphens preserved",
			payload:   []byte(`{"metadata":{"trace-id":["a"]}}`),
			finalized: true,
			meta:      metaExpect{present: true, keys: []string{"trace-id"}, values: map[string][]string{"trace-id": {"a"}}},
		},
	}
	proto := protowire.AppendTag(nil, 3, protowire.BytesType)
	proto = protowire.AppendString(proto, "hi")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mapper, _ := NewStreamMapper("m", "r", 32)
			// Prepend one data frame so a valid envelope has something to
			// finalize; rejected and error cases still surface their EndStream
			// outcome because the data frame drains before the trailer is
			// parsed.
			frames := append(connectFrame(0, proto), connectFrame(2, tc.payload)...)
			s := decoderBig(frames)
			s.mapper = mapper
			var sawEvent bool
			for {
				_, err := s.Next(context.Background())
				if err == io.EOF {
					break
				}
				if err != nil {
					switch {
					case tc.wantErr != nil:
						if !errors.Is(err, tc.wantErr) {
							t.Fatalf("err = %v; want %v", err, tc.wantErr)
						}
					case tc.wantClass != "":
						var upstream *provider.UpstreamError
						if !errors.As(err, &upstream) || upstream.Provider != provider.Devin || upstream.Classification.Class != tc.wantClass {
							t.Fatalf("err = %v; want typed %s", err, tc.wantClass)
						}
					default:
						t.Fatalf("err = %v; want success", err)
					}
					if tc.finalized {
						t.Fatalf("expected finalization but got error %v", err)
					}
					// Error and malformed envelopes must not finalize. A typed
					// error alongside valid metadata preserves that metadata
					// on the stream; malformed envelopes (including a valid
					// error alongside malformed metadata) carry no metadata.
					if mapper.terminal {
						t.Fatal("mapper finalized on non-success envelope")
					}
					if tc.meta.present {
						for _, k := range tc.meta.keys {
							got, ok := s.trailerMetadata[k]
							if !ok {
								t.Fatalf("missing trailer metadata key %q in %v", k, s.trailerMetadata)
							}
							if tc.meta.values != nil {
								if len(got) != len(tc.meta.values[k]) {
									t.Fatalf("metadata %q = %v; want %v", k, got, tc.meta.values[k])
								}
								for i := range got {
									if got[i] != tc.meta.values[k][i] {
										t.Fatalf("metadata %q = %v; want %v", k, got, tc.meta.values[k])
									}
								}
							}
						}
					} else if len(s.trailerMetadata) != 0 {
						t.Fatalf("expected no trailer metadata, got %v", s.trailerMetadata)
					}
					return
				}
				sawEvent = true
			}
			if !tc.finalized {
				t.Fatalf("expected error or typed error but stream finalized cleanly")
			}
			if !sawEvent {
				t.Fatal("valid envelope emitted no events")
			}
			if !mapper.terminal {
				t.Fatal("mapper not finalized after valid envelope")
			}
			// Finalize exactly once: repeated reads stay io.EOF.
			for i := range 3 {
				if _, err := s.Next(context.Background()); !errors.Is(err, io.EOF) {
					t.Fatalf("post-terminal call %d = %v; want io.EOF", i, err)
				}
			}
			// Metadata preservation.
			if tc.meta.present {
				if s.trailerMetadata == nil {
					t.Fatal("expected trailer metadata preserved, got nil")
				}
				for _, k := range tc.meta.keys {
					got, ok := s.trailerMetadata[k]
					if !ok {
						t.Fatalf("missing trailer metadata key %q in %v", k, s.trailerMetadata)
					}
					if tc.meta.values != nil {
						if len(got) != len(tc.meta.values[k]) {
							t.Fatalf("metadata %q = %v; want %v", k, got, tc.meta.values[k])
						}
						for i := range got {
							if got[i] != tc.meta.values[k][i] {
								t.Fatalf("metadata %q = %v; want %v", k, got, tc.meta.values[k])
							}
						}
					}
				}
			} else if len(s.trailerMetadata) != 0 {
				t.Fatalf("expected no trailer metadata, got %v", s.trailerMetadata)
			}
		})
	}
}

// TestConnectEndStreamErrorClassification proves recognized Connect error
// codes map to the existing typed provider.UpstreamError classification so
// routing, cooldown, and relogin decisions match the HTTP status path. The
// error arrives before any data event, so failover can happen without ever
// emitting a partial response.
func TestConnectEndStreamErrorClassification(t *testing.T) {
	cases := []struct {
		code       string
		class      provider.ErrorClass
		status     int
		retryNext  bool
		relogin    bool
		disable    bool
		refresh    bool
		scope      provider.CooldownScope
		publicCode string
	}{
		{"unavailable", provider.ClassTransient, http.StatusServiceUnavailable, true, false, false, false, provider.CooldownModel, "provider_unavailable"},
		{"internal", provider.ClassTransient, http.StatusInternalServerError, true, false, false, false, provider.CooldownModel, "provider_unavailable"},
		{"resource_exhausted", provider.ClassRateLimit, http.StatusTooManyRequests, true, false, false, false, provider.CooldownModel, "rate_limit_exceeded"},
		{"unauthenticated", provider.ClassUnauthorized, http.StatusUnauthorized, true, true, true, true, provider.CooldownAccount, "provider_authentication_error"},
		{"permission_denied", provider.ClassPermission, http.StatusForbidden, false, false, false, false, provider.CooldownAccount, "provider_permission_error"},
		{"invalid_argument", provider.ClassValidation, http.StatusBadRequest, false, false, false, false, provider.CooldownNone, "invalid_request_error"},
		{"data_loss", provider.ClassUpstream, http.StatusBadGateway, true, false, false, false, provider.CooldownModel, "provider_error"},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			mapper, _ := NewStreamMapper("m", "r", 32)
			payload := []byte(`{"error":{"code":"` + tc.code + `","message":"detail"}}`)
			s := decoderBig(connectFrame(2, payload))
			s.mapper = mapper
			_, err := s.Next(context.Background())
			var upstream *provider.UpstreamError
			if !errors.As(err, &upstream) {
				t.Fatalf("err = %v; want typed UpstreamError", err)
			}
			c := upstream.Classification
			if upstream.Provider != provider.Devin || upstream.Status != tc.status || c.Class != tc.class || c.RetryNext != tc.retryNext || c.ReloginRequired != tc.relogin || c.DisableAccount != tc.disable || c.RefreshSame != tc.refresh || c.CooldownScope != tc.scope || c.PublicCode != tc.publicCode {
				t.Fatalf("%s: upstream=%+v", tc.code, upstream)
			}
			// A classified error must not carry the upstream message detail
			// into the sanitized public message.
			if c.PublicMessage == "detail" {
				t.Fatalf("%s: upstream detail leaked into public message %q", tc.code, c.PublicMessage)
			}
			if mapper.terminal {
				t.Fatalf("%s: mapper finalized on error EndStream", tc.code)
			}
		})
	}
}

// TestConnectEndStreamMetadataMapStringArray proves trailer metadata is
// validated exactly as map[string][]string (arrays of UTF-8 strings) and that
// valid metadata is preserved on a successful finalize.
func TestConnectEndStreamMetadataMapStringArray(t *testing.T) {
	valid := []byte(`{"metadata":{"x":["YWJj"],"trace-id":["ZGVm","YWJj"]}}`)
	mapper, _ := NewStreamMapper("m", "r", 32)
	proto := protowire.AppendTag(nil, 3, protowire.BytesType)
	proto = protowire.AppendString(proto, "hi")
	s := decoderBig(append(connectFrame(0, proto), connectFrame(2, valid)...))
	s.mapper = mapper
	for {
		_, err := s.Next(context.Background())
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("valid metadata rejected: %v", err)
		}
	}
	if !mapper.terminal {
		t.Fatal("mapper not finalized")
	}
	if got := s.trailerMetadata["x"]; len(got) != 1 || got[0] != "YWJj" {
		t.Fatalf("x = %v; want [YWJj]", got)
	}
	if got := s.trailerMetadata["trace-id"]; len(got) != 2 || got[0] != "ZGVm" || got[1] != "YWJj" {
		t.Fatalf("trace-id = %v; want [ZGVm YWJj]", got)
	}

	// A non-string array element is rejected (covered exhaustively in the
	// envelope matrix; this confirms the value-preserving path above does not
	// silently accept a scalar-shaped value).
	mapper, _ = NewStreamMapper("m", "r", 32)
	s = decoderBig(append(connectFrame(0, proto), connectFrame(2, []byte(`{"metadata":{"x":"YWJj"}}`))...))
	s.mapper = mapper
	var sawScalarErr bool
	for {
		_, e := s.Next(context.Background())
		if e != nil {
			if !errors.Is(e, ErrMalformedStream) {
				t.Fatalf("scalar metadata value = %v; want ErrMalformedStream", e)
			}
			sawScalarErr = true
			break
		}
	}
	if !sawScalarErr {
		t.Fatal("scalar metadata value finalized cleanly; want ErrMalformedStream")
	}
	if mapper.terminal {
		t.Fatal("mapper finalized on scalar metadata value")
	}
}

// TestConnectEndStreamMetadataStrictUTF8 proves the strict JSON string
// scanner rejects invalid UTF-8 and unpaired or malformed UTF-16 surrogate
// escapes in trailer metadata string arrays before encoding/json can silently
// replace them with U+FFFD. Every malformed case returns ErrMalformedStream
// and never finalizes or classifies; valid Unicode (including a proper
// surrogate pair and raw multibyte UTF-8) is accepted and preserved.
func TestConnectEndStreamMetadataStrictUTF8(t *testing.T) {
	proto := protowire.AppendTag(nil, 3, protowire.BytesType)
	proto = protowire.AppendString(proto, "hi")
	// Each rejected payload embeds a malformed string in a metadata value
	// array. Raw invalid UTF-8 bytes are injected directly; surrogate cases
	// use \u escapes that encoding/json would otherwise accept and corrupt.
	rejected := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "raw invalid utf-8 byte",
			payload: []byte(`{"metadata":{"x":["` + "\xff" + `"]}}`),
		},
		{
			name:    "raw invalid utf-8 sequence",
			payload: []byte(`{"metadata":{"x":["` + "\xc0\x80" + `"]}}`),
		},
		{
			name:    "raw truncated multibyte",
			payload: []byte(`{"metadata":{"x":["` + "\xe2\x82" + `"]}}`),
		},
		{
			name:    "lone high surrogate",
			payload: []byte(`{"metadata":{"x":["\uD800"]}}`),
		},
		{
			name:    "lone low surrogate",
			payload: []byte(`{"metadata":{"x":["\uDC00"]}}`),
		},
		{
			name:    "high surrogate followed by non-surrogate",
			payload: []byte(`{"metadata":{"x":["\uD800\u0041"]}}`),
		},
		{
			name:    "high surrogate followed by another high",
			payload: []byte(`{"metadata":{"x":["\uD800\uD800"]}}`),
		},
		{
			name:    "high surrogate at end of string",
			payload: []byte(`{"metadata":{"x":["ab\uD800"]}}`),
		},
		{
			name:    "low surrogate at start of string",
			payload: []byte(`{"metadata":{"x":["\uDC00ab"]}}`),
		},
		{
			name:    "valid string then lone surrogate",
			payload: []byte(`{"metadata":{"x":["ok","\uDEAD"]}}`),
		},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			mapper, _ := NewStreamMapper("m", "r", 32)
			s := decoderBig(append(connectFrame(0, proto), connectFrame(2, tc.payload)...))
			s.mapper = mapper
			var sawErr bool
			for {
				_, err := s.Next(context.Background())
				if err != nil {
					if !errors.Is(err, ErrMalformedStream) {
						t.Fatalf("err = %v; want ErrMalformedStream", err)
					}
					sawErr = true
					break
				}
			}
			if !sawErr {
				t.Fatal("malformed metadata finalized cleanly; want ErrMalformedStream")
			}
			if mapper.terminal {
				t.Fatal("mapper finalized on malformed metadata")
			}
			if len(s.trailerMetadata) != 0 {
				t.Fatalf("expected no trailer metadata, got %v", s.trailerMetadata)
			}
		})
	}

	// Valid Unicode must still be accepted and preserved: a proper surrogate
	// pair decodes to a single astral rune, and raw multibyte UTF-8 survives.
	valid := []struct {
		name    string
		payload []byte
		key     string
		want    string
	}{
		{
			name:    "valid surrogate pair",
			payload: []byte(`{"metadata":{"x":["\uD83D\uDE00"]}}`),
			key:     "x",
			want:    "\U0001F600",
		},
		{
			name:    "valid raw multibyte utf-8",
			payload: []byte(`{"metadata":{"x":["` + "\xc3\xa9" + `"]}}`),
			key:     "x",
			want:    "é",
		},
		{
			name:    "valid bmp escape",
			payload: []byte(`{"metadata":{"x":["\u00e9"]}}`),
			key:     "x",
			want:    "é",
		},
		{
			name:    "valid ascii unchanged",
			payload: []byte(`{"metadata":{"x":["YWJj"]}}`),
			key:     "x",
			want:    "YWJj",
		},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			mapper, _ := NewStreamMapper("m", "r", 32)
			s := decoderBig(append(connectFrame(0, proto), connectFrame(2, tc.payload)...))
			s.mapper = mapper
			for {
				_, err := s.Next(context.Background())
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("valid metadata rejected: %v", err)
				}
			}
			if !mapper.terminal {
				t.Fatal("mapper not finalized after valid metadata")
			}
			got := s.trailerMetadata[tc.key]
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("metadata %q = %v; want [%q]", tc.key, got, tc.want)
			}
		})
	}
}

func TestOpenChatStreamRequestWireAndHeaders(t *testing.T) {
	message := &devinproto.GetChatMessageRequest{}
	expected, _ := message.Marshal()
	checked := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/exa.api_server_pb.ApiServerService/GetChatMessage" {
			checked <- errors.New("wrong path")
			return
		}
		want := map[string]string{"Content-Type": "application/connect+proto", "Connect-Protocol-Version": "1", "Connect-Content-Encoding": "gzip", "Accept-Encoding": "identity", "User-Agent": "connect-go/1.18.1 (go1.26.3)", "Connect-Accept-Encoding": "gzip"}
		for k, v := range want {
			if r.Header.Get(k) != v {
				checked <- errors.New("wrong header " + k)
				return
			}
		}
		body, _ := io.ReadAll(r.Body)
		if len(body) < 5 || body[0] != 1 || int(binary.BigEndian.Uint32(body[1:5])) != len(body)-5 {
			checked <- errors.New("wrong frame")
			return
		}
		zr, err := gzip.NewReader(bytes.NewReader(body[5:]))
		if err != nil {
			checked <- err
			return
		}
		decoded, err := io.ReadAll(zr)
		if err != nil || !bytes.Equal(decoded, expected) {
			checked <- errors.New("wrong protobuf payload")
			return
		}
		checked <- nil
		_, _ = w.Write(connectFrame(2, []byte(`{}`)))
	}))
	defer server.Close()
	origin, _ := url.Parse(server.URL)
	c := &Client{httpClient: server.Client(), streamIdleTimeout: time.Second, maxFrameCompressedBytes: 64, maxFrameDecompressedBytes: 64, maxStreamBytes: 64, maxToolArgumentBytes: 64}
	stream, err := c.openChatStream(context.Background(), message, origin, "m", "r")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if err := <-checked; err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOpenChatStreamRejectsDecompressedRequestBeforeSend(t *testing.T) {
	var calls int
	client := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("unexpected request") })}, maxFrameCompressedBytes: 1 << 20, maxFrameDecompressedBytes: 8, maxToolArgumentBytes: 1 << 10}
	origin, _ := url.Parse("https://chat.example.com")
	_, err := client.openChatStream(context.Background(), &devinproto.GetChatMessageRequest{Prompt: strings.Repeat("x", 64)}, origin, "m", "r")
	if !errors.Is(err, ErrStreamFrameTooLarge) || calls != 0 {
		t.Fatalf("error=%v calls=%d", err, calls)
	}
}
