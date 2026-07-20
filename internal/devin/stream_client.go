package devin

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
	"unicode/utf8"

	devinproto "byos/internal/devin/proto"
	"byos/internal/provider"
)

var (
	ErrStreamTruncated     = errors.New("truncated Devin stream")
	ErrStreamFrameTooLarge = errors.New("Devin stream frame exceeds configured limit")
	ErrStreamLimit         = errors.New("Devin stream exceeds configured limit")
	ErrStreamIdleTimeout   = errors.New("Devin stream idle timeout")
)

type connectStream struct {
	body                                     io.ReadCloser
	cancel                                   context.CancelFunc
	ctx                                      context.Context
	idle                                     time.Duration
	maxCompressed, maxDecompressed, maxTotal int64
	total                                    int64
	mapper                                   *StreamMapper
	queue                                    []provider.Event
	trailerMetadata                          map[string][]string
	ended                                    bool
	closeOnce                                sync.Once
}

// StreamChat performs a fresh bootstrap and opens one Connect server stream.
func (c *Client) StreamChat(ctx context.Context, sessionToken string, canonical provider.CanonicalRequest, selectedModel, responseID string) (provider.Stream, error) {
	if c == nil || c.httpClient == nil || c.streamIdleTimeout <= 0 || c.maxFrameCompressedBytes <= 0 || c.maxFrameDecompressedBytes <= 0 || c.maxStreamBytes <= 0 || c.maxToolArgumentBytes <= 0 {
		return nil, ErrInvalidClientConfig
	}
	wire, origin, err := c.PrepareChatRequest(ctx, sessionToken, canonical)
	if err != nil {
		return nil, err
	}
	return c.openChatStream(ctx, wire, origin, selectedModel, responseID)
}

func (c *Client) openChatStream(parent context.Context, message *devinproto.GetChatMessageRequest, origin *url.URL, selectedModel, responseID string) (provider.Stream, error) {
	payload, err := message.Marshal()
	if err != nil {
		return nil, ErrMalformedResponse
	}
	if int64(len(payload)) > c.maxFrameDecompressedBytes {
		return nil, ErrStreamFrameTooLarge
	}
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err = zw.Write(payload); err == nil {
		err = zw.Close()
	} else {
		_ = zw.Close()
	}
	if err != nil {
		return nil, ErrMalformedResponse
	}
	if int64(compressed.Len()) > c.maxFrameCompressedBytes {
		return nil, ErrStreamFrameTooLarge
	}
	frame := make([]byte, 5+compressed.Len())
	frame[0] = 1
	binary.BigEndian.PutUint32(frame[1:5], uint32(compressed.Len()))
	copy(frame[5:], compressed.Bytes())
	ctx, cancel := context.WithCancel(parent)
	if c.streamDeadline > 0 {
		ctx, cancel = context.WithTimeout(parent, c.streamDeadline)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin.String()+devinproto.APIServiceGetChatMessagePath, bytes.NewReader(frame))
	if err != nil {
		cancel()
		return nil, ErrMalformedResponse
	}
	req.Header.Set("Content-Type", "application/connect+proto")
	req.Header.Set("Connect-Protocol-Version", "1")
	req.Header.Set("Connect-Content-Encoding", "gzip")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "connect-go/1.18.1 (go1.26.3)")
	req.Header.Set("Connect-Accept-Encoding", "gzip")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		cancel()
		if errors.Is(err, context.Canceled) {
			return nil, context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = resp.Body.Close()
		cancel()
		return nil, classifyStatus(resp.StatusCode, resp.Header, time.Now())
	}
	mapper, err := NewStreamMapper(selectedModel, responseID, c.maxToolArgumentBytes)
	if err != nil {
		_ = resp.Body.Close()
		cancel()
		return nil, err
	}
	return &connectStream{body: resp.Body, cancel: cancel, ctx: ctx, idle: c.streamIdleTimeout, maxCompressed: c.maxFrameCompressedBytes, maxDecompressed: c.maxFrameDecompressedBytes, maxTotal: c.maxStreamBytes, mapper: mapper}, nil
}

func (s *connectStream) Next(ctx context.Context) (provider.Event, error) {
	for {
		if len(s.queue) > 0 {
			ev := s.queue[0]
			s.queue = s.queue[1:]
			return ev, nil
		}
		if s.ended {
			return provider.Event{}, io.EOF
		}
		flag, payload, eof, err := s.readFrame(ctx)
		if err != nil {
			return provider.Event{}, err
		}
		if eof {
			// Raw EOF before a Connect EndStream envelope: the server closed
			// the body without emitting the required terminal frame. This
			// covers both a zero-byte fresh EOF and EOF after partial data
			// frames; either way the stream is truncated, not complete.
			return provider.Event{}, ErrStreamTruncated
		}
		if flag&2 != 0 {
			// Connect EndStream envelope. A successful finalize requires a
			// top-level JSON object that omits the error key entirely; a
			// present error key is parsed as a Connect error and mapped to a
			// typed provider.UpstreamError so routing can classify, cool down,
			// and fail over before any event is emitted. Raw null, arrays,
			// scalars, a structurally invalid error object (null, missing,
			// empty, or non-string code, or invalid fields), and malformed
			// trailer metadata are all rejected as a malformed termination.
			// Valid trailer metadata, when present, is preserved.
			if len(payload) == 0 {
				return provider.Event{}, ErrMalformedStream
			}
			var raw json.RawMessage
			if json.Unmarshal(payload, &raw) != nil {
				return provider.Event{}, ErrMalformedStream
			}
			if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '{' {
				return provider.Event{}, ErrMalformedStream
			}
			var envelope map[string]json.RawMessage
			if json.Unmarshal(payload, &envelope) != nil {
				return provider.Event{}, ErrMalformedStream
			}
			// Parse and strictly validate trailer metadata BEFORE branching on
			// the error key, for both success and error envelopes. A malformed
			// metadata field rejects the whole envelope as ErrMalformedStream
			// even when a valid Connect error is present: no classification
			// runs on a structurally invalid termination. Valid metadata is
			// preserved on the stream regardless of whether the envelope is a
			// success or a typed error, so a classified error still carries
			// its trailers.
			if rawMeta, ok := envelope["metadata"]; ok {
				meta, merr := parseTrailerMetadata(rawMeta)
				if merr != nil {
					return provider.Event{}, ErrMalformedStream
				}
				s.trailerMetadata = meta
			}
			if rawErr, ok := envelope["error"]; ok {
				// A valid Connect error object is mapped to a typed
				// provider.UpstreamError; a structurally invalid error is a
				// malformed termination, not a classified upstream failure.
				// Metadata parsed above is already preserved on the stream.
				return provider.Event{}, classifyConnectEndStreamError(rawErr)
			}
			// Finalize exactly once: mark the stream ended before draining the
			// terminal events so a subsequent Next never re-enters Finalize.
			s.ended = true
			s.queue, err = s.mapper.Finalize()
			if err != nil {
				return provider.Event{}, err
			}
			continue
		}
		var frame devinproto.GetChatMessageResponse
		if frame.Unmarshal(payload) != nil {
			return provider.Event{}, ErrMalformedStream
		}
		s.queue, err = s.mapper.Push(&frame)
		if err != nil {
			return provider.Event{}, err
		}
	}
}

func (s *connectStream) readFrame(caller context.Context) (byte, []byte, bool, error) {
	type result struct {
		flag    byte
		payload []byte
		eof     bool
		err     error
	}
	ch := make(chan result, 1)
	go func() {
		var h [5]byte
		n, err := io.ReadFull(s.body, h[:])
		if err == io.EOF && n == 0 {
			ch <- result{eof: true}
			return
		}
		if err != nil {
			ch <- result{err: ErrStreamTruncated}
			return
		}
		flag := h[0]
		if flag > 3 {
			ch <- result{err: ErrMalformedStream}
			return
		}
		size := int64(binary.BigEndian.Uint32(h[1:]))
		if size > s.maxCompressed {
			ch <- result{err: ErrStreamFrameTooLarge}
			return
		}
		if flag&1 == 0 && size > s.maxDecompressed {
			ch <- result{err: ErrStreamFrameTooLarge}
			return
		}
		raw := make([]byte, size)
		if _, err = io.ReadFull(s.body, raw); err != nil {
			ch <- result{err: ErrStreamTruncated}
			return
		}
		decoded := raw
		if flag&1 != 0 {
			zr, e := gzip.NewReader(bytes.NewReader(raw))
			if e != nil {
				ch <- result{err: ErrMalformedStream}
				return
			}
			decoded, e = io.ReadAll(io.LimitReader(zr, s.maxDecompressed+1))
			closeErr := zr.Close()
			if e != nil || closeErr != nil {
				ch <- result{err: ErrMalformedStream}
				return
			}
			if int64(len(decoded)) > s.maxDecompressed {
				ch <- result{err: ErrStreamFrameTooLarge}
				return
			}
		}
		if int64(len(decoded)) > s.maxTotal-s.total {
			ch <- result{err: ErrStreamLimit}
			return
		}
		s.total += int64(len(decoded))
		ch <- result{flag: flag, payload: decoded}
	}()
	timer := time.NewTimer(s.idle)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.flag, r.payload, r.eof, r.err
	case <-caller.Done():
		_ = s.Close()
		return 0, nil, false, caller.Err()
	case <-s.ctx.Done():
		_ = s.Close()
		return 0, nil, false, s.ctx.Err()
	case <-timer.C:
		_ = s.Close()
		return 0, nil, false, ErrStreamIdleTimeout
	}
}

func (s *connectStream) Close() error {
	if s == nil {
		return nil
	}
	var err error
	s.closeOnce.Do(func() { s.cancel(); err = s.body.Close() })
	return err
}

// parseTrailerMetadata decodes the Connect EndStream metadata field. The
// metadata must be exactly a JSON object mapping header names to arrays of
// UTF-8 strings, matching HTTP trailer semantics. A null metadata field is
// treated as absent (no metadata); any other non-object value is malformed.
//
// Object members are parsed directly from the raw JSON bytes so that keys are
// never normalized by encoding/json (which silently replaces invalid UTF-8 and
// lone UTF-16 surrogates with U+FFFD). Each raw key JSON string is strictly
// validated for UTF-8 and surrogate pairing, then decoded, then checked
// against the Connect header-name grammar (exactly [0-9a-z_.-]+, non-empty:
// lowercase letters, digits, underscore, hyphen, and dot; uppercase and all
// other punctuation are rejected). Header names are lowercase-only, so
// duplicate keys are rejected exactly. Values remain arrays of strict UTF-8
// strings (see parseTrailerMetadataValue).
func parseTrailerMetadata(raw json.RawMessage) (map[string][]string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, ErrMalformedStream
	}
	if string(trimmed) == "null" {
		return nil, nil
	}
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return nil, ErrMalformedStream
	}
	// Structural grammar gate. json.Valid does not catch lone surrogates or
	// raw invalid UTF-8 in strings (it is lenient on both), so it is only a
	// first-pass grammar check; strict key/value validation below rejects the
	// encoding/json normalization that json.Valid permits.
	if !json.Valid(trimmed) {
		return nil, ErrMalformedStream
	}
	members, err := splitRawJSONObjectMembers(trimmed)
	if err != nil {
		return nil, ErrMalformedStream
	}
	out := make(map[string][]string, len(members))
	seen := make(map[string]struct{}, len(members))
	for _, m := range members {
		keyRaw, valRaw := m[0], m[1]
		if !strictJSONStringValid(keyRaw) {
			return nil, ErrMalformedStream
		}
		var key string
		if json.Unmarshal(keyRaw, &key) != nil {
			return nil, ErrMalformedStream
		}
		if !validConnectHeaderName(key) {
			return nil, ErrMalformedStream
		}
		if _, dup := seen[key]; dup {
			return nil, ErrMalformedStream
		}
		seen[key] = struct{}{}
		values, err := parseTrailerMetadataValue(valRaw)
		if err != nil {
			return nil, err
		}
		out[key] = values
	}
	return out, nil
}

// splitRawJSONObjectMembers scans a raw JSON object (opening '{' through
// closing '}') and returns each member as a [2]json.RawMessage pair holding the
// raw key token (including quotes) and the raw value token, in source order.
// It tracks string escapes and nested structures so values are split at the
// correct boundary without decoding keys through encoding/json. It does not
// validate UTF-8 or surrogate pairing; strictJSONStringValid handles that for
// keys and parseTrailerMetadataValue for values.
func splitRawJSONObjectMembers(raw []byte) ([][2]json.RawMessage, error) {
	b := bytes.TrimSpace(raw)
	i := skipJSONWhitespace(b, 1) // past opening '{'
	var members [][2]json.RawMessage
	if i < len(b) && b[i] == '}' {
		return members, nil
	}
	for {
		if i >= len(b) || b[i] != '"' {
			return nil, ErrMalformedStream
		}
		keyStart := i
		keyEnd, ok := scanJSONString(b, i)
		if !ok {
			return nil, ErrMalformedStream
		}
		i = skipJSONWhitespace(b, keyEnd)
		if i >= len(b) || b[i] != ':' {
			return nil, ErrMalformedStream
		}
		i = skipJSONWhitespace(b, i+1)
		valStart := i
		valEnd, ok := scanJSONValue(b, i)
		if !ok {
			return nil, ErrMalformedStream
		}
		members = append(members, [2]json.RawMessage{b[keyStart:keyEnd], b[valStart:valEnd]})
		i = skipJSONWhitespace(b, valEnd)
		if i >= len(b) {
			return nil, ErrMalformedStream
		}
		switch b[i] {
		case ',':
			i = skipJSONWhitespace(b, i+1)
		case '}':
			return members, nil
		default:
			return nil, ErrMalformedStream
		}
	}
}

// scanJSONValue returns the index just past the JSON value starting at b[i].
// It handles strings, objects, arrays, literals, and numbers, tracking nested
// delimiters with a stack so mismatched or unbalanced structures are rejected.
func scanJSONValue(b []byte, i int) (int, bool) {
	if i >= len(b) {
		return 0, false
	}
	switch b[i] {
	case '"':
		return scanJSONString(b, i)
	case '{', '[':
		var stack []byte
		stack = append(stack, b[i])
		i++
		for len(stack) > 0 {
			if i >= len(b) {
				return 0, false
			}
			c := b[i]
			if c == '"' {
				ni, ok := scanJSONString(b, i)
				if !ok {
					return 0, false
				}
				i = ni
				continue
			}
			switch c {
			case '{', '[':
				stack = append(stack, c)
			case '}', ']':
				if len(stack) == 0 {
					return 0, false
				}
				top := stack[len(stack)-1]
				if (c == '}' && top != '{') || (c == ']' && top != '[') {
					return 0, false
				}
				stack = stack[:len(stack)-1]
			}
			i++
		}
		return i, true
	case 't':
		return matchJSONLiteral(b, i, "true")
	case 'f':
		return matchJSONLiteral(b, i, "false")
	case 'n':
		return matchJSONLiteral(b, i, "null")
	default:
		return scanJSONNumber(b, i)
	}
}

// scanJSONString returns the index just past the closing quote of the JSON
// string starting at b[i] (which must be '"'), tracking escape sequences so an
// escaped quote does not terminate the string. It does not validate UTF-8 or
// surrogate pairing.
func scanJSONString(b []byte, i int) (int, bool) {
	if i >= len(b) || b[i] != '"' {
		return 0, false
	}
	i++
	for i < len(b) {
		switch b[i] {
		case '"':
			return i + 1, true
		case '\\':
			i++
			if i >= len(b) {
				return 0, false
			}
			if b[i] == 'u' {
				if i+4 >= len(b) {
					return 0, false
				}
				i += 5
			} else {
				i++
			}
		default:
			i++
		}
	}
	return 0, false
}

// scanJSONNumber returns the index just past a JSON number starting at b[i].
func scanJSONNumber(b []byte, i int) (int, bool) {
	start := i
	if i < len(b) && b[i] == '-' {
		i++
	}
	digits := false
	for i < len(b) && b[i] >= '0' && b[i] <= '9' {
		i++
		digits = true
	}
	if i < len(b) && b[i] == '.' {
		i++
		frac := false
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			i++
			frac = true
		}
		if !frac {
			return 0, false
		}
	}
	if i < len(b) && (b[i] == 'e' || b[i] == 'E') {
		i++
		if i < len(b) && (b[i] == '+' || b[i] == '-') {
			i++
		}
		exp := false
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			i++
			exp = true
		}
		if !exp {
			return 0, false
		}
	}
	if !digits || i == start {
		return 0, false
	}
	return i, true
}

// matchJSONLiteral reports whether the JSON literal lit starts at b[i] and
// returns the index just past it.
func matchJSONLiteral(b []byte, i int, lit string) (int, bool) {
	if i+len(lit) <= len(b) && string(b[i:i+len(lit)]) == lit {
		return i + len(lit), true
	}
	return 0, false
}

// skipJSONWhitespace advances i past JSON insignificant whitespace.
func skipJSONWhitespace(b []byte, i int) int {
	for i < len(b) {
		switch b[i] {
		case ' ', '\t', '\n', '\r':
			i++
		default:
			return i
		}
	}
	return i
}

// validConnectHeaderName reports whether s is a non-empty Connect trailer
// header name. The grammar is exactly [0-9a-z_.-]+: lowercase letters,
// digits, underscore, hyphen, and dot. Uppercase letters and all other
// punctuation (the rest of the RFC 7230 token set) are rejected, as are
// non-ASCII bytes (from decoded \u escapes or literal UTF-8) and empty
// strings.
func validConnectHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for i := range s {
		if !isHeaderTokenChar(s[i]) {
			return false
		}
	}
	return true
}

// isHeaderTokenChar reports whether c is one of the allowed Connect trailer
// header-name bytes: [0-9a-z_.-].
func isHeaderTokenChar(c byte) bool {
	switch {
	case c >= '0' && c <= '9',
		c >= 'a' && c <= 'z':
		return true
	}
	switch c {
	case '_', '-', '.':
		return true
	}
	return false
}

// parseTrailerMetadataValue decodes one Connect trailer metadata value. Each
// value must be a JSON array of UTF-8 strings; scalars, null, nested objects,
// and arrays containing non-string elements are malformed. Each string element
// is strictly validated against the raw JSON bytes before Go's encoding/json
// replacement: raw invalid UTF-8 and unpaired or malformed UTF-16 surrogate
// \u escapes are rejected as malformed so silent U+FFFD substitution can never
// corrupt trailer metadata.
func parseTrailerMetadataValue(raw json.RawMessage) ([]string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, ErrMalformedStream
	}
	if trimmed[0] != '[' {
		return nil, ErrMalformedStream
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) != nil {
		return nil, ErrMalformedStream
	}
	values := make([]string, 0, len(arr))
	for _, elem := range arr {
		if !strictJSONStringValid(elem) {
			return nil, ErrMalformedStream
		}
		var s string
		if json.Unmarshal(elem, &s) != nil {
			return nil, ErrMalformedStream
		}
		values = append(values, s)
	}
	return values, nil
}

// strictJSONStringValid reports whether raw is a JSON string token whose
// content is valid UTF-8 with no unpaired or malformed UTF-16 surrogate \u
// escapes. It scans the raw bytes directly, before encoding/json decodes the
// string and silently replaces invalid sequences with U+FFFD, so callers can
// reject malformed trailer metadata instead of accepting corrupted values. It
// performs no heap allocations: bytes.TrimSpace returns a sub-slice and the
// hex/surrogate state is kept on the stack.
func strictJSONStringValid(raw []byte) bool {
	raw = bytes.TrimSpace(raw)
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return false
	}
	i, end := 1, len(raw)-1
	for i < end {
		if raw[i] != '\\' {
			// Raw (non-escaped) bytes must form valid UTF-8. DecodeRune
			// returns (RuneError, 1) only for an invalid byte; a genuinely
			// encoded U+FFFD decodes with size 3 and is accepted here.
			r, size := utf8.DecodeRune(raw[i:end])
			if r == utf8.RuneError && size == 1 {
				return false
			}
			i += size
			continue
		}
		// Escape sequence: \\ followed by one of " \ / b f n r t or uXXXX.
		i++
		if i >= end {
			return false
		}
		if raw[i] != 'u' {
			i++
			continue
		}
		// \u escape: require four hex digits.
		if i+5 > end {
			return false
		}
		r, ok := parseHex4(raw[i+1:])
		if !ok {
			return false
		}
		i += 5
		switch {
		case r >= 0xD800 && r <= 0xDBFF:
			// High surrogate: must be immediately followed by a \u low
			// surrogate escape. Anything else (end of string, non-escape,
			// non-u escape, non-low \u, or bad hex) is malformed.
			if i+6 > end || raw[i] != '\\' || raw[i+1] != 'u' {
				return false
			}
			lo, ok2 := parseHex4(raw[i+2:])
			if !ok2 || lo < 0xDC00 || lo > 0xDFFF {
				return false
			}
			i += 6
		case r >= 0xDC00 && r <= 0xDFFF:
			// Low surrogate without a preceding high surrogate.
			return false
		}
	}
	return true
}

// parseHex4 decodes four hexadecimal digits at the start of b into a rune. It
// returns false if b is shorter than four bytes or contains a non-hex digit.
func parseHex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var r rune
	for j := range 4 {
		c := b[j]
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v = c - 'A' + 10
		default:
			return 0, false
		}
		r = r<<4 | rune(v)
	}
	return r, true
}

// connectErrorObject mirrors the Connect EndStream error object. The code
// field is required and must be a non-empty string; message and details are
// optional. When message is present it must be a JSON string (the empty
// string is allowed); a null or non-string message is structurally invalid
// and rejected before classification. The details field, when present and
// non-null, must be a JSON array of ErrorDetail objects, each an object with
// a non-empty string type and a string value that is valid standard base64
// (unpadded canonical, padded accepted, URL-safe rejected); null, scalar,
// array, missing, empty, wrong-type, or invalid-base64 elements make the
// error structurally invalid. Message is decoded as json.RawMessage so the
// presence of the key can be distinguished from its absence and its JSON
// type validated independently of the surrounding unmarshal.
type connectErrorObject struct {
	Code    string            `json:"code"`
	Message json.RawMessage   `json:"message,omitempty"`
	Details []json.RawMessage `json:"details,omitempty"`
}

// classifyConnectEndStreamError parses a Connect EndStream error value and
// returns a typed provider.UpstreamError for valid error objects, mapping
// recognized codes to the existing classification metadata so routing,
// cooldown, and relogin behavior matches the HTTP status path. A structurally
// invalid error (null, non-object, missing/empty/null/non-string code, a
// present-but-null or non-string message, an invalid details field type, or
// any invalid details element) is rejected as a malformed stream and never
// classified or finalized.
func classifyConnectEndStreamError(raw json.RawMessage) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return ErrMalformedStream
	}
	if trimmed[0] != '{' {
		return ErrMalformedStream
	}
	var obj connectErrorObject
	if json.Unmarshal(raw, &obj) != nil {
		return ErrMalformedStream
	}
	if obj.Code == "" {
		return ErrMalformedStream
	}
	if err := validateConnectErrorMessage(obj.Message); err != nil {
		return err
	}
	if err := validateConnectErrorDetails(obj.Details); err != nil {
		return err
	}
	return &provider.UpstreamError{Provider: provider.Devin, Status: connectHTTPStatus(obj.Code), Classification: classifyConnectError(obj.Code)}
}

// validateConnectErrorMessage strictly validates the optional Connect error
// message field. A missing message key (a nil json.RawMessage) is allowed,
// matching the optional-field semantics of the Connect error object. When the
// key is present the value must be a JSON string; the empty string is allowed,
// but null, booleans, numbers, arrays, and objects are structurally invalid
// and rejected as a malformed stream before the error is classified, so a
// malformed termination is never routed or finalized.
func validateConnectErrorMessage(msg json.RawMessage) error {
	if len(msg) == 0 {
		return nil
	}
	trimmed := bytes.TrimSpace(msg)
	if string(trimmed) == "null" || len(trimmed) == 0 || trimmed[0] != '"' {
		return ErrMalformedStream
	}
	var s string
	if json.Unmarshal(trimmed, &s) != nil {
		return ErrMalformedStream
	}
	return nil
}

// validateConnectErrorDetails strictly validates every element of a Connect
// error details array. Each element must be a JSON object with a non-empty
// string type and a string value that is valid standard base64 (unpadded
// canonical base64.RawStdEncoding, or padded base64.StdEncoding for
// compatibility; URL-safe base64 is rejected). A null, scalar, array,
// missing-key, wrong-type, empty-type, or invalid-base64 element makes the
// whole error malformed. A nil or empty details slice (including a JSON null
// details field) is valid, matching the optional-field semantics of the
// Connect error object.
func validateConnectErrorDetails(details []json.RawMessage) error {
	for _, d := range details {
		trimmed := bytes.TrimSpace(d)
		if len(trimmed) == 0 || string(trimmed) == "null" || trimmed[0] != '{' {
			return ErrMalformedStream
		}
		var detail struct {
			Type  *string `json:"type"`
			Value *string `json:"value"`
		}
		if json.Unmarshal(d, &detail) != nil {
			return ErrMalformedStream
		}
		if detail.Type == nil || *detail.Type == "" {
			return ErrMalformedStream
		}
		if detail.Value == nil {
			return ErrMalformedStream
		}
		if !isValidStandardBase64(*detail.Value) {
			return ErrMalformedStream
		}
	}
	return nil
}

// isValidStandardBase64 reports whether s is a valid standard base64 encoding
// of bytes, as used for Connect error detail values. The canonical encoding is
// unpadded standard base64 (base64.RawStdEncoding: A-Z, a-z, 0-9, +, /, no =
// padding); padded standard base64 (base64.StdEncoding, with = padding to a
// multiple of four) is also accepted for compatibility. URL-safe base64
// (using - and _) is rejected, since the standard alphabet is required.
func isValidStandardBase64(s string) bool {
	if _, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return true
	}
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

// classifyConnectError maps a Connect EndStream error code to the existing
// typed provider.ErrorClassification metadata. Recognized codes mirror the
// HTTP status mapper so routing, cooldown, and relogin decisions are
// consistent; any other valid code falls back to the generic upstream
// classification so a valid error object is never classified as malformed.
func classifyConnectError(code string) provider.ErrorClassification {
	switch code {
	case "invalid_argument":
		return provider.ErrorClassification{
			Class:         provider.ClassValidation,
			PublicStatus:  http.StatusBadRequest,
			PublicCode:    "invalid_request_error",
			PublicMessage: "invalid model or request payload",
		}
	case "unauthenticated":
		return provider.ErrorClassification{
			Class: provider.ClassUnauthorized, RetryNext: true, RefreshSame: true, DisableAccount: true, ReloginRequired: true, CooldownScope: provider.CooldownAccount,
			PublicStatus:  http.StatusUnauthorized,
			PublicCode:    "provider_authentication_error",
			PublicMessage: "provider authentication is required",
		}
	case "permission_denied":
		return provider.ErrorClassification{
			Class: provider.ClassPermission, CooldownScope: provider.CooldownAccount,
			PublicStatus:  http.StatusForbidden,
			PublicCode:    "provider_permission_error",
			PublicMessage: "provider permission denied",
		}
	case "resource_exhausted":
		return provider.ErrorClassification{
			Class: provider.ClassRateLimit, RetryNext: true, CooldownScope: provider.CooldownModel,
			PublicStatus:  http.StatusTooManyRequests,
			PublicCode:    "rate_limit_exceeded",
			PublicMessage: "all available accounts are rate limited",
		}
	case "unavailable", "internal":
		return provider.ErrorClassification{
			Class: provider.ClassTransient, RetryNext: true, CooldownScope: provider.CooldownModel, Cooldown: time.Minute,
			PublicStatus:  http.StatusServiceUnavailable,
			PublicCode:    "provider_unavailable",
			PublicMessage: "upstream provider error",
		}
	default:
		return upstreamClassification()
	}
}

// connectHTTPStatus maps a Connect EndStream error code to its canonical HTTP
// status, matching the Connect protocol specification so the UpstreamError
// Status field is consistent with the HTTP status classification path.
func connectHTTPStatus(code string) int {
	switch code {
	case "invalid_argument":
		return http.StatusBadRequest
	case "unauthenticated":
		return http.StatusUnauthorized
	case "permission_denied":
		return http.StatusForbidden
	case "resource_exhausted":
		return http.StatusTooManyRequests
	case "internal":
		return http.StatusInternalServerError
	case "unavailable":
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadGateway
	}
}
