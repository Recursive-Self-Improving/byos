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
