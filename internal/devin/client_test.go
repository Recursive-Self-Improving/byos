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
func validTestClientConfig() ClientConfig {
	return ClientConfig{AllowedChatHosts: []string{"chat.example.com"}, UnaryTimeout: time.Second, MaxCompressedBytes: 1 << 10, MaxDecompressedBytes: 1 << 10, StreamIdleTimeout: 5 * time.Second, MaxFrameCompressedBytes: 1 << 10, MaxFrameDecompressedBytes: 1 << 10, MaxStreamBytes: 1 << 20, MaxToolArgumentBytes: 1 << 10, MaxNonStreamBytes: 1 << 20}
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

func TestStatusClassificationAndRetryAfter(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		status           int
		class            provider.ErrorClass
		retry            bool
		scope            provider.CooldownScope
		disable, relogin bool
	}{
		{400, provider.ClassValidation, false, provider.CooldownNone, false, false},
		{404, provider.ClassValidation, false, provider.CooldownNone, false, false},
		{401, provider.ClassUnauthorized, true, provider.CooldownAccount, true, true},
		{403, provider.ClassUnauthorized, true, provider.CooldownAccount, true, true},
		{408, provider.ClassTransient, true, provider.CooldownModel, false, false},
		{429, provider.ClassRateLimit, true, provider.CooldownModel, false, false},
		{500, provider.ClassTransient, true, provider.CooldownModel, false, false},
		{502, provider.ClassTransient, true, provider.CooldownModel, false, false},
		{503, provider.ClassTransient, true, provider.CooldownModel, false, false},
		{504, provider.ClassTransient, true, provider.CooldownModel, false, false},
		{418, provider.ClassUpstream, false, provider.CooldownNone, false, false},
	}
	for _, test := range tests {
		var upstream *provider.UpstreamError
		if !errors.As(classifyStatus(test.status, nil, now), &upstream) {
			t.Fatalf("status %d not classified", test.status)
		}
		got := upstream.Classification
		if got.Class != test.class || got.RetryNext != test.retry || got.CooldownScope != test.scope || got.DisableAccount != test.disable || got.ReloginRequired != test.relogin {
			t.Fatalf("status %d: %+v", test.status, got)
		}
	}
	for _, value := range []string{"120", now.Add(2 * time.Minute).Format(http.TimeFormat)} {
		var upstream *provider.UpstreamError
		errors.As(classifyStatus(429, http.Header{"Retry-After": []string{value}}, now), &upstream)
		if !upstream.Classification.ExplicitRetryAfter || upstream.Classification.Cooldown != 2*time.Minute || !upstream.Classification.RetryAfter.Equal(now.Add(2*time.Minute)) {
			t.Fatalf("retry-after %q: %+v", value, upstream.Classification)
		}
	}
	var invalid *provider.UpstreamError
	errors.As(classifyStatus(429, http.Header{"Retry-After": []string{"secret invalid"}}, now), &invalid)
	if invalid.Classification.ExplicitRetryAfter || invalid.Classification.Cooldown != 0 {
		t.Fatalf("invalid retry-after: %+v", invalid.Classification)
	}
}

func TestGetUserJWTEmptyMalformedAndLimits(t *testing.T) {
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
	config := validTestClientConfig()
	config.HTTPClient = &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
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
			config := validTestClientConfig()
			config.HTTPClient = &http.Client{Transport: test.transport}
			client, err := NewClient(config)
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
	config := validTestClientConfig()
	config.HTTPClient = &http.Client{Transport: transport}
	client, err := NewClient(config)
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
	config := validTestClientConfig()
	config.HTTPClient = &http.Client{Transport: transport}
	client, err := NewClient(config)
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

func TestNewClientConfigBoundaries(t *testing.T) {
	valid := validTestClientConfig()
	if _, err := NewClient(valid); err != nil {
		t.Fatalf("valid minimum config: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*ClientConfig)
	}{
		{"unary-low", func(c *ClientConfig) { c.UnaryTimeout = time.Second - time.Nanosecond }}, {"unary-high", func(c *ClientConfig) { c.UnaryTimeout = time.Minute + time.Nanosecond }},
		{"idle-low", func(c *ClientConfig) { c.StreamIdleTimeout = 5*time.Second - time.Nanosecond }}, {"idle-high", func(c *ClientConfig) { c.StreamIdleTimeout = 5*time.Minute + time.Nanosecond }},
		{"deadline-negative", func(c *ClientConfig) { c.StreamDeadline = -time.Nanosecond }}, {"deadline-low", func(c *ClientConfig) { c.StreamDeadline = 30*time.Second - time.Nanosecond }}, {"deadline-high", func(c *ClientConfig) { c.StreamDeadline = 30*time.Minute + time.Nanosecond }},
		{"unary-compressed-low", func(c *ClientConfig) { c.MaxCompressedBytes = (1 << 10) - 1 }}, {"unary-decompressed-high", func(c *ClientConfig) { c.MaxDecompressedBytes = (32 << 20) + 1 }},
		{"frame-compressed-high", func(c *ClientConfig) { c.MaxFrameCompressedBytes = (16 << 20) + 1 }}, {"frame-decompressed-low", func(c *ClientConfig) { c.MaxFrameDecompressedBytes = (1 << 10) - 1 }},
		{"stream-low", func(c *ClientConfig) { c.MaxStreamBytes = (1 << 20) - 1 }}, {"tool-high", func(c *ClientConfig) { c.MaxToolArgumentBytes = (16 << 20) + 1 }}, {"nonstream-high", func(c *ClientConfig) { c.MaxNonStreamBytes = (128 << 20) + 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if _, err := NewClient(config); !errors.Is(err, ErrInvalidClientConfig) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}
