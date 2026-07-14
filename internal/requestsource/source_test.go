package requestsource

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIPTrustsOnlyConfiguredProxyChain(t *testing.T) {
	trusted, err := ParseTrustedProxies([]string{"10.0.0.0/8", "192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, remote, forwarded, want string
		wantErr                       bool
	}{
		{name: "direct peer ignores spoof", remote: "198.51.100.7:1234", forwarded: "203.0.113.9", want: "198.51.100.7"},
		{name: "trusted edge", remote: "10.0.0.4:1234", forwarded: "198.51.100.8", want: "198.51.100.8"},
		{name: "trusted chain", remote: "10.0.0.4:1234", forwarded: "198.51.100.8, 192.0.2.9", want: "198.51.100.8"},
		{name: "attacker prefix stops at first untrusted", remote: "10.0.0.4:1234", forwarded: "203.0.113.1, 198.51.100.8, 192.0.2.9", want: "198.51.100.8"},
		{name: "malformed trusted chain", remote: "10.0.0.4:1234", forwarded: "198.51.100.8, unknown", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://admin.test/", nil)
			request.RemoteAddr = test.remote
			if test.forwarded != "" {
				request.Header.Set("X-Forwarded-For", test.forwarded)
			}
			got, err := trusted.ClientIP(request)
			if test.wantErr {
				if err == nil {
					t.Fatalf("ClientIP = %v, want error", got)
				}
				return
			}
			if err != nil || got.String() != test.want {
				t.Fatalf("ClientIP = %v, %v; want %s", got, err, test.want)
			}
		})
	}
}

func TestRequestIsHTTPSPreservesFailClosedProxyRule(t *testing.T) {
	trusted, err := ParseTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://admin.test/", nil)
	request.RemoteAddr = "198.51.100.7:1234"
	request.Header.Set("X-Forwarded-Proto", "https")
	if trusted.RequestIsHTTPS(request) {
		t.Fatal("untrusted peer asserted HTTPS")
	}
	request.RemoteAddr = "10.0.0.4:1234"
	if !trusted.RequestIsHTTPS(request) {
		t.Fatal("trusted peer HTTPS assertion was ignored")
	}
	request.Header.Set("X-Forwarded-Proto", "https, http")
	if trusted.RequestIsHTTPS(request) {
		t.Fatal("rightmost forwarded protocol did not fail closed")
	}
}
