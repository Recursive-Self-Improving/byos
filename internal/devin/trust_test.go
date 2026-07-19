package devin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func TestValidateAPIOriginFormsAndAllowlist(t *testing.T) {
	allowed := []string{"chat.example.com"}
	for _, test := range []struct{ raw, want string }{
		{"", DefaultBaseURL},
		{"https://server.codeium.com", "https://server.codeium.com"},
		{"https://server.codeium.com/", "https://server.codeium.com"},
		{"https://chat.example.com", "https://chat.example.com"},
	} {
		got, err := ValidateAPIOrigin(test.raw, allowed)
		if err != nil || got.String() != test.want {
			t.Errorf("%q = %v, %v; want %q", test.raw, got, err, test.want)
		}
	}
	for _, raw := range []string{
		"http://server.codeium.com", "//server.codeium.com", "server.codeium.com",
		"https://evil.example.com", "https://server.codeium.com.evil.example",
		"https://user:pass@server.codeium.com", "https://server.codeium.com:443",
		"https://server.codeium.com/path", "https://server.codeium.com?x=1", "https://server.codeium.com#x",
		"https://127.0.0.1", "https://[2001:db8::1]",
	} {
		if _, err := ValidateAPIOrigin(raw, allowed); !errors.Is(err, ErrUntrustedOrigin) {
			t.Errorf("accepted %q: %v", raw, err)
		}
	}
}

func TestPublicAddressesRejectsNonPublicOrMixedResults(t *testing.T) {
	bad := []netip.Addr{
		netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("169.254.1.1"), netip.MustParseAddr("224.0.0.1"), netip.MustParseAddr("::1"),
		netip.MustParseAddr("fc00::1"), netip.MustParseAddr("fe80::1"), netip.MustParseAddr("ff02::1"),
	}
	for _, address := range bad {
		resolver := resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8"), address}, nil
		})
		if _, err := publicAddresses(context.Background(), resolver, "example.com"); !errors.Is(err, ErrUntrustedOrigin) {
			t.Errorf("accepted %v: %v", address, err)
		}
	}
	for _, resolver := range []Resolver{
		resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) { return nil, errors.New("dns failed") }),
		resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) { return nil, nil }),
	} {
		if _, err := publicAddresses(context.Background(), resolver, "example.com"); !errors.Is(err, ErrUntrustedOrigin) {
			t.Errorf("resolver failure = %v", err)
		}
	}
}

func TestTrustedDialerRevalidatesDNSOnEveryConnection(t *testing.T) {
	calls := 0
	resolver := resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		calls++
		if calls == 1 {
			return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	dial := trustedDialer(resolver, &net.Dialer{Timeout: time.Nanosecond})
	_, _ = dial(context.Background(), "tcp", "server.codeium.com:443")
	_, err := dial(context.Background(), "tcp", "server.codeium.com:443")
	if !errors.Is(err, ErrUntrustedOrigin) || calls != 2 {
		t.Fatalf("second dial = %v; resolver calls = %d", err, calls)
	}
}

func TestInjectedDialContextCannotBypassTrustedDialerOrSendCredential(t *testing.T) {
	var injectedDialCalls atomic.Int32
	transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		injectedDialCalls.Add(1)
		return nil, errors.New("injected dialer executed")
	}}
	resolver := resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	config := validTestClientConfig()
	config.HTTPClient = &http.Client{Transport: transport}
	config.Resolver = resolver
	client, err := NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetUserJWT(context.Background(), "credential-material")
	if !errors.Is(err, ErrUntrustedOrigin) {
		t.Fatalf("GetUserJWT error = %v; want untrusted origin", err)
	}
	if injectedDialCalls.Load() != 0 {
		t.Fatalf("injected DialContext calls = %d; credential could bypass trusted dialer", injectedDialCalls.Load())
	}
}

func TestInjectedTLSVerificationHooksCannotBypassHostnameOrSendCredential(t *testing.T) {
	var handlerCalls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		handlerCalls.Add(1)
	}))
	defer server.Close()

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	var verifyPeerCalls atomic.Int32
	var verifyConnectionCalls atomic.Int32
	injectedTLS := &tls.Config{
		RootCAs:            roots,
		InsecureSkipVerify: true,
		ServerName:         "example.com",
		VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error {
			verifyPeerCalls.Add(1)
			return nil
		},
		VerifyConnection: func(tls.ConnectionState) error {
			verifyConnectionCalls.Add(1)
			return nil
		},
	}
	config := validTestClientConfig()
	config.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: injectedTLS}}
	client, err := NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	transport := client.httpClient.Transport.(*http.Transport)
	serverAddress := strings.TrimPrefix(server.URL, "https://")
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, serverAddress)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://wrong-host.invalid/bootstrap", strings.NewReader("credential-material"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.httpClient.Do(req)
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("request succeeded despite certificate hostname mismatch")
	}
	if handlerCalls.Load() != 0 {
		t.Fatalf("handler calls = %d; credential reached server", handlerCalls.Load())
	}
	if verifyPeerCalls.Load() != 0 || verifyConnectionCalls.Load() != 0 {
		t.Fatalf("injected TLS hooks ran: peer=%d connection=%d", verifyPeerCalls.Load(), verifyConnectionCalls.Load())
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLS minimum = %#x; want TLS 1.2", transport.TLSClientConfig.MinVersion)
	}
}
