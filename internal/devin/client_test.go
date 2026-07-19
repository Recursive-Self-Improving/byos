package devin

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	devinproto "byos/internal/devin/proto"
	"byos/internal/provider"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(status int, body []byte, encoding string) *http.Response {
	h := make(http.Header)
	if encoding != "" {
		h.Set("Content-Encoding", encoding)
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(bytes.NewReader(body))}
}
func directClient(rt http.RoundTripper) *Client {
	return &Client{httpClient: &http.Client{Transport: rt}, allowedHosts: []string{"chat.example.com"}, timeout: time.Second, maxCompressedBytes: 1024, maxDecompressedBytes: 1024}
}
func jwtPayload(t *testing.T, jwt, base string) []byte {
	t.Helper()
	b, err := (&devinproto.GetUserJWTResponse{UserJWT: jwt, CustomAPIServerURL: base}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGetUserJWTExactRequestAndFreshCall(t *testing.T) {
	var calls atomic.Int32
	client := directClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.String() != DefaultBaseURL+devinproto.AuthServiceGetUserJWTPath {
			t.Errorf("request = %s %s", r.Method, r.URL)
		}
		if r.Header.Get("Content-Type") != "application/proto" || r.Header.Get("Connect-Protocol-Version") != "1" || r.Header.Get("Accept") != "*/*" {
			t.Errorf("headers = %v", r.Header)
		}
		got, _ := io.ReadAll(r.Body)
		metadata, _ := SourceMetadata("secret")
		want, _ := (&devinproto.GetUserJWTRequest{Metadata: metadata}).Marshal()
		if !bytes.Equal(got, want) {
			t.Errorf("request body = %x; want %x", got, want)
		}
		return response(200, jwtPayload(t, "jwt", "https://chat.example.com"), ""), nil
	}))
	for range 2 {
		got, err := client.GetUserJWT(context.Background(), "secret")
		if err != nil || got.UserJWT != "jwt" || got.APIBaseURL != "https://chat.example.com" || got.SessionToken != SessionTokenPrefix+"secret" {
			t.Fatalf("session = %+v, %v", got, err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d; want 2", calls.Load())
	}
}

func TestGetUserJWTRawAndGzipResponses(t *testing.T) {
	payload := jwtPayload(t, "jwt", "")
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, encoding string
		body           []byte
	}{
		{"raw", "", payload}, {"gzip-header", "gzip", compressed.Bytes()}, {"gzip-sniffed", "", compressed.Bytes()},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := directClient(roundTripFunc(func(*http.Request) (*http.Response, error) { return response(200, test.body, test.encoding), nil }))
			if got, err := client.GetUserJWT(context.Background(), "secret"); err != nil || got.UserJWT != "jwt" {
				t.Fatalf("session = %+v, %v", got, err)
			}
		})
	}
}

func TestGetUserJWTStatusEmptyMalformedAndLimits(t *testing.T) {
	for _, status := range []int{401, 403} {
		client := directClient(roundTripFunc(func(*http.Request) (*http.Response, error) { return response(status, nil, ""), nil }))
		_, err := client.GetUserJWT(context.Background(), "secret")
		var upstream *provider.UpstreamError
		if !errors.As(err, &upstream) || upstream.Status != status || !upstream.Classification.ReloginRequired || !upstream.Classification.DisableAccount {
			t.Errorf("status %d: %v", status, err)
		}
	}
	client := directClient(roundTripFunc(func(*http.Request) (*http.Response, error) { return response(500, nil, ""), nil }))
	var statusErr *HTTPStatusError
	if _, err := client.GetUserJWT(context.Background(), "secret"); !errors.As(err, &statusErr) || statusErr.StatusCode != 500 {
		t.Errorf("500 = %v", err)
	}
	for _, test := range []struct {
		name     string
		body     []byte
		encoding string
		limit    int64
		want     error
	}{
		{"empty-jwt", jwtPayload(t, " ", ""), "", 1024, ErrEmptyUserJWT},
		{"malformed-proto", []byte{0x0a, 0xff}, "", 1024, ErrMalformedResponse},
		{"malformed-gzip", []byte("not gzip"), "gzip", 1024, ErrMalformedResponse},
		{"unknown-encoding", jwtPayload(t, "jwt", ""), "br", 1024, ErrMalformedResponse},
		{"compressed-oversize", bytes.Repeat([]byte("x"), 9), "", 8, ErrResponseTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := directClient(roundTripFunc(func(*http.Request) (*http.Response, error) { return response(200, test.body, test.encoding), nil }))
			c.maxCompressedBytes = test.limit
			if _, err := c.GetUserJWT(context.Background(), "secret"); !errors.Is(err, test.want) {
				t.Fatalf("got %v; want %v", err, test.want)
			}
		})
	}
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	_, _ = zw.Write(bytes.Repeat([]byte("x"), 20))
	_ = zw.Close()
	c := directClient(roundTripFunc(func(*http.Request) (*http.Response, error) { return response(200, compressed.Bytes(), "gzip"), nil }))
	c.maxDecompressedBytes = 8
	if _, err := c.GetUserJWT(context.Background(), "secret"); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("decompressed oversize = %v", err)
	}
}

func TestGetUserJWTTimeoutAndCancellation(t *testing.T) {
	blocking := roundTripFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
	client := directClient(blocking)
	client.timeout = time.Millisecond
	if _, err := client.GetUserJWT(context.Background(), "secret"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := directClient(blocking).GetUserJWT(ctx, "secret"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel = %v", err)
	}
}

func TestPrepareChatRequestBootstrapsEveryCallAndSelectsOrigin(t *testing.T) {
	var calls atomic.Int32
	client := directClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		call := calls.Add(1)
		if call == 1 {
			return response(http.StatusOK, jwtPayload(t, "jwt-one", "https://chat.example.com"), ""), nil
		}
		return response(http.StatusOK, jwtPayload(t, "jwt-two", ""), ""), nil
	}))
	canonical := provider.CanonicalRequest{"model": "model", "input": []any{}}

	first, firstOrigin, err := client.PrepareChatRequest(context.Background(), "  secret  ", canonical)
	if err != nil {
		t.Fatal(err)
	}
	second, secondOrigin, err := client.PrepareChatRequest(context.Background(), SessionTokenPrefix+"secret", canonical)
	if err != nil {
		t.Fatal(err)
	}

	if calls.Load() != 2 {
		t.Fatalf("bootstrap calls = %d; want 2", calls.Load())
	}
	if first.Metadata.APIKey != SessionTokenPrefix+"secret" || second.Metadata.APIKey != SessionTokenPrefix+"secret" {
		t.Fatalf("session tokens = %q, %q", first.Metadata.APIKey, second.Metadata.APIKey)
	}
	if first.Metadata.UserJWT != "jwt-one" || second.Metadata.UserJWT != "jwt-two" {
		t.Fatalf("fresh JWTs = %q, %q", first.Metadata.UserJWT, second.Metadata.UserJWT)
	}
	if firstOrigin.String() != "https://chat.example.com" {
		t.Fatalf("custom origin = %q", firstOrigin)
	}
	if secondOrigin.String() != DefaultBaseURL {
		t.Fatalf("fallback origin = %q", secondOrigin)
	}

	clientType := reflect.TypeOf(*client)
	for i := range clientType.NumField() {
		if strings.Contains(strings.ToLower(clientType.Field(i).Name), "jwt") {
			t.Fatalf("Client retains JWT field %q", clientType.Field(i).Name)
		}
	}
}

func TestPrepareChatRequestBootstrapFailurePrecedesBuild(t *testing.T) {
	client := directClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusUnauthorized, nil, ""), nil
	}))
	request, origin, err := client.PrepareChatRequest(context.Background(), "secret", provider.CanonicalRequest{})
	var upstream *provider.UpstreamError
	if request != nil || origin != nil || !errors.As(err, &upstream) || upstream.Status != http.StatusUnauthorized {
		t.Fatalf("request=%v origin=%v err=%v", request, origin, err)
	}
}

func TestPrepareChatRequestCancellationStopsBootstrap(t *testing.T) {
	var calls atomic.Int32
	client := directClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		<-r.Context().Done()
		return nil, r.Context().Err()
	}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request, origin, err := client.PrepareChatRequest(ctx, "secret", provider.CanonicalRequest{"model": "model", "input": []any{}})
	if request != nil || origin != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("request=%v origin=%v err=%v", request, origin, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("bootstrap calls = %d; want 1", calls.Load())
	}
}

func TestRedirectBlockedBeforeCredentialCanReachDestination(t *testing.T) {
	var destinationCalls atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { destinationCalls.Add(1) }))
	defer destination.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	httpClient := origin.Client()
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrRedirect }
	client := directClient(httpClient.Transport)
	client.httpClient = httpClient
	_, err := client.postUnaryProto(context.Background(), origin.URL, []byte("credential-material"))
	if !errors.Is(err, ErrRedirect) || destinationCalls.Load() != 0 {
		t.Fatalf("redirect = %v; destination calls = %d", err, destinationCalls.Load())
	}
}

func TestNewClientDisablesProxyAndRejectsUnsafeTransport(t *testing.T) {
	config := ClientConfig{HTTPClient: &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}, AllowedChatHosts: []string{"chat.example.com"}, UnaryTimeout: time.Second, MaxCompressedBytes: 10, MaxDecompressedBytes: 10}
	client, err := NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatalf("transport = %#v", client.httpClient.Transport)
	}
	if config.HTTPClient.Transport.(*http.Transport).Proxy == nil {
		t.Fatal("mutated caller transport")
	}
	config.HTTPClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil })
	if _, err := NewClient(config); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("unsafe transport = %v", err)
	}
}

func TestNewClientRejectsTLSDialHooksBeforeUse(t *testing.T) {
	tests := []struct {
		name      string
		transport *http.Transport
	}{
		{
			name: "context",
			transport: &http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("DialTLSContext executed")
				return nil, errors.New("unreachable")
			}},
		},
		{
			name: "legacy",
			transport: &http.Transport{DialTLS: func(string, string) (net.Conn, error) {
				t.Fatal("DialTLS executed")
				return nil, errors.New("unreachable")
			}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewClient(ClientConfig{HTTPClient: &http.Client{Transport: test.transport}, AllowedChatHosts: []string{"chat.example.com"}, UnaryTimeout: time.Second, MaxCompressedBytes: 10, MaxDecompressedBytes: 10})
			if client != nil || !errors.Is(err, ErrUnsafeTLSDialHooks) || err.Error() != ErrUnsafeTLSDialHooks.Error() {
				t.Fatalf("client=%v error=%v; want deterministic TLS hook rejection", client, err)
			}
		})
	}
}

func TestNewClientRejectsTLSNextProtoBeforeCredentialRequest(t *testing.T) {
	var hookCalls atomic.Int32
	var requestCalls atomic.Int32
	transport := &http.Transport{TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{
		"h2": func(string, *tls.Conn) http.RoundTripper {
			hookCalls.Add(1)
			return roundTripFunc(func(*http.Request) (*http.Response, error) {
				requestCalls.Add(1)
				return nil, errors.New("credential request leaked")
			})
		},
	}}
	client, err := NewClient(ClientConfig{HTTPClient: &http.Client{Transport: transport}, AllowedChatHosts: []string{"chat.example.com"}, UnaryTimeout: time.Second, MaxCompressedBytes: 10, MaxDecompressedBytes: 10})
	if client != nil || !errors.Is(err, ErrUnsafeTLSNextProto) || err.Error() != ErrUnsafeTLSNextProto.Error() {
		t.Fatalf("client=%v error=%v; want deterministic TLS protocol hook rejection", client, err)
	}
	if hookCalls.Load() != 0 || requestCalls.Load() != 0 {
		t.Fatalf("TLSNextProto calls=%d request calls=%d; credential request leaked", hookCalls.Load(), requestCalls.Load())
	}
}

func TestNewClientSanitizesTLSClientConfig(t *testing.T) {
	var verifyPeerCalls atomic.Int32
	var verifyConnectionCalls atomic.Int32
	var clientCertificateCalls atomic.Int32
	roots := x509.NewCertPool()
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:            roots,
		MinVersion:         tls.VersionTLS10,
		InsecureSkipVerify: true,
		ServerName:         "attacker.example",
		Certificates:       []tls.Certificate{{Certificate: [][]byte{{1, 2, 3}}}},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			clientCertificateCalls.Add(1)
			return &tls.Certificate{}, nil
		},
		VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error {
			verifyPeerCalls.Add(1)
			return nil
		},
		VerifyConnection: func(tls.ConnectionState) error {
			verifyConnectionCalls.Add(1)
			return nil
		},
		KeyLogWriter: io.Discard,
	}}
	client, err := NewClient(ClientConfig{HTTPClient: &http.Client{Transport: transport}, AllowedChatHosts: []string{"chat.example.com"}, UnaryTimeout: time.Second, MaxCompressedBytes: 10, MaxDecompressedBytes: 10})
	if err != nil {
		t.Fatal(err)
	}
	got := client.httpClient.Transport.(*http.Transport).TLSClientConfig
	if got.MinVersion != tls.VersionTLS12 || got.RootCAs == nil {
		t.Fatalf("sanitized TLS config = %#v", got)
	}
	if got.RootCAs == roots {
		t.Fatal("caller RootCAs was not cloned")
	}
	if got.InsecureSkipVerify || got.ServerName != "" || len(got.Certificates) != 0 || got.GetClientCertificate != nil || got.VerifyPeerCertificate != nil || got.VerifyConnection != nil || got.KeyLogWriter != nil {
		t.Fatalf("unsafe TLS fields survived sanitization: %#v", got)
	}
	if verifyPeerCalls.Load() != 0 || verifyConnectionCalls.Load() != 0 || clientCertificateCalls.Load() != 0 {
		t.Fatalf("TLS hooks ran during construction: peer=%d connection=%d client-certificate=%d", verifyPeerCalls.Load(), verifyConnectionCalls.Load(), clientCertificateCalls.Load())
	}
}
