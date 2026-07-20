package devin

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testClient(t *testing.T, rt http.RoundTripper, compressed, decompressed int64) *Client {
	t.Helper()
	client, err := NewClient(ClientConfig{HTTPClient: &http.Client{Transport: rt}, Timeout: time.Second, MaxCompressedBytes: compressed, MaxDecompressedBytes: decompressed})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func response(status int, body []byte, encoding string) *http.Response {
	header := make(http.Header)
	if encoding != "" {
		header.Set("Content-Encoding", encoding)
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(body))}
}

func TestExchangeExactRequest(t *testing.T) {
	const code, verifier = "CALLBACK-CODE-SENTINEL", "PKCE-VERIFIER-SENTINEL"
	client := testClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.URL.String() != ExchangeEndpoint {
			t.Fatalf("request=%s %s", r.Method, r.URL)
		}
		if r.Header.Get("Accept") != "application/json" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("headers=%v", r.Header)
		}
		body, _ := io.ReadAll(r.Body)
		if got, want := string(body), `{"code":"CALLBACK-CODE-SENTINEL","code_verifier":"PKCE-VERIFIER-SENTINEL"}`; got != want {
			t.Fatalf("body=%s", got)
		}
		return response(200, []byte(`{"token":"opaque-token"}`), ""), nil
	}), 1024, 1024)
	token, err := client.Exchange(context.Background(), code, verifier)
	if err != nil || token != "opaque-token" {
		t.Fatalf("token=%q err=%v", token, err)
	}
}

func TestExchangeRefusesRedirectAndSanitizes(t *testing.T) {
	calls := 0
	client := testClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://capture.invalid/CALLBACK-CODE-SENTINEL"}}, Body: io.NopCloser(strings.NewReader("BODY-SENTINEL")), Request: r}, nil
	}), 1024, 1024)
	_, err := client.Exchange(context.Background(), "CALLBACK-CODE-SENTINEL", "VERIFIER-SENTINEL")
	if !errors.Is(err, ErrExchangeRedirect) || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	for _, secret := range []string{"CALLBACK-CODE", "VERIFIER", "BODY-SENTINEL", "capture.invalid"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("leaked %q: %v", secret, err)
		}
	}
}

func TestExchangeSchemaStatusAndTransportErrors(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		status int
		want   error
	}{
		{"missing", `{}`, 200, ErrExchangeTokenRequired}, {"empty", `{"token":"  "}`, 200, ErrExchangeTokenRequired},
		{"wrong type", `{"token":42}`, 200, ErrExchangeTokenRequired}, {"malformed", `{`, 200, ErrExchangeProtocol},
		{"multiple", `{"token":"ok"}{}`, 200, ErrExchangeProtocol}, {"status", `SECRET`, 503, ErrExchangeStatus},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := testClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) { return response(tc.status, []byte(tc.body), ""), nil }), 1024, 1024)
			_, err := client.Exchange(context.Background(), "code", "verifier")
			if !errors.Is(err, tc.want) || strings.Contains(err.Error(), tc.body) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	secretErr := errors.New("transport CALLBACK-CODE-SENTINEL VERIFIER-SENTINEL")
	client := testClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, secretErr }), 1024, 1024)
	_, err := client.Exchange(context.Background(), "code", "verifier")
	if !errors.Is(err, ErrExchangeTransport) || strings.Contains(err.Error(), "SENTINEL") {
		t.Fatalf("err=%v", err)
	}
}

func TestExchangeIdentityAndGzipLimits(t *testing.T) {
	valid := []byte(`{"token":"x"}`)
	for _, encoding := range []string{"", "identity", "gzip"} {
		payload := valid
		if encoding == "gzip" {
			var b bytes.Buffer
			w := gzip.NewWriter(&b)
			_, _ = w.Write(valid)
			_ = w.Close()
			payload = b.Bytes()
		}
		client := testClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) { return response(200, payload, encoding), nil }), int64(len(payload)), int64(len(valid)))
		if token, err := client.Exchange(context.Background(), "code", "verifier"); err != nil || token != "x" {
			t.Fatalf("encoding=%q token=%q err=%v", encoding, token, err)
		}
		client.maxCompressedBytes = int64(len(payload) - 1)
		if _, err := client.Exchange(context.Background(), "code", "verifier"); !errors.Is(err, ErrExchangeTooLarge) {
			t.Fatalf("compressed encoding=%q err=%v", encoding, err)
		}
	}
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write(valid)
	_ = w.Close()
	client := testClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) { return response(200, b.Bytes(), "gzip"), nil }), 1024, int64(len(valid)-1))
	if _, err := client.Exchange(context.Background(), "code", "verifier"); !errors.Is(err, ErrExchangeTooLarge) {
		t.Fatalf("decompressed err=%v", err)
	}
	for _, encoding := range []string{"br", "gzip"} {
		t.Run(encoding, func(t *testing.T) {
			client := testClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) { return response(200, []byte("not gzip"), encoding), nil }), 1024, 1024)
			if _, err := client.Exchange(context.Background(), "code", "verifier"); !errors.Is(err, ErrExchangeEncoding) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestExchangeRejectsTrailingGzipContent(t *testing.T) {
	compress := func(body []byte) []byte {
		t.Helper()
		var buffer bytes.Buffer
		writer := gzip.NewWriter(&buffer)
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return buffer.Bytes()
	}

	valid := compress([]byte(`{"token":"x"}`))
	cases := []struct {
		name    string
		payload []byte
	}{
		{name: "single trailing byte", payload: append(append([]byte(nil), valid...), 0)},
		{name: "concatenated member", payload: append(append([]byte(nil), valid...), compress([]byte(`{"token":"second"}`))...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := testClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				return response(http.StatusOK, tc.payload, "gzip"), nil
			}), int64(len(tc.payload)), 1024)
			if _, err := client.Exchange(context.Background(), "code", "verifier"); !errors.Is(err, ErrExchangeEncoding) {
				t.Fatalf("err=%v", err)
			}

			client.maxCompressedBytes = int64(len(tc.payload) - 1)
			if _, err := client.Exchange(context.Background(), "code", "verifier"); !errors.Is(err, ErrExchangeTooLarge) {
				t.Fatalf("compressed boundary err=%v", err)
			}
		})
	}
}

func TestExchangeCancellationAndTimeout(t *testing.T) {
	client := testClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() }), 1024, 1024)
	client.timeout = 10 * time.Millisecond
	if _, err := client.Exchange(context.Background(), "code", "verifier"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout err=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Exchange(ctx, "code", "verifier"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel err=%v", err)
	}
}
