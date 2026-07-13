package xai

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func discoveryDocument(device string) string {
	return `{"issuer":"https://auth.x.ai","authorization_endpoint":"https://auth.x.ai/authorize","device_authorization_endpoint":"` + device + `","token_endpoint":"https://auth.x.ai/token","jwks_uri":"https://auth.x.ai/.well-known/jwks.json"}`
}
func TestDiscoverValidatesAndCaches(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(discoveryDocument("https://auth.x.ai/device"))), Header: make(http.Header)}, nil
	})}
	discovery := NewDiscoveryClient(client, DiscoveryURL)
	first, err := discovery.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := discovery.Discover(context.Background())
	if err != nil || first != second || calls.Load() != 1 {
		t.Fatalf("cache=%+v %+v calls=%d err=%v", first, second, calls.Load(), err)
	}
}
func TestDiscoverRejectsUnsafeDocuments(t *testing.T) {
	tests := []struct{ name, url, body string }{{"http discovery", "http://auth.x.ai/.well-known/openid-configuration", discoveryDocument("https://auth.x.ai/device")}, {"foreign device", DiscoveryURL, discoveryDocument("https://evil.example/device")}, {"http device", DiscoveryURL, discoveryDocument("http://auth.x.ai/device")}, {"empty device", DiscoveryURL, discoveryDocument("")}, {"malformed", DiscoveryURL, `{`}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(test.body)), Header: make(http.Header)}, nil
			})}
			if _, err := NewDiscoveryClient(client, test.url).Discover(context.Background()); err == nil {
				t.Fatal("unsafe discovery accepted")
			}
		})
	}
}

func TestDiscoveryRedirectPolicy(t *testing.T) {
	client := NewDiscoveryClient(&http.Client{}, DiscoveryURL)
	request, err := http.NewRequest(http.MethodGet, "https://evil.example/discovery", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.http.CheckRedirect(request, nil); err == nil {
		t.Fatal("foreign redirect accepted")
	}
	request, err = http.NewRequest(http.MethodGet, "https://login.x.ai/discovery", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.http.CheckRedirect(request, nil); err != nil {
		t.Fatalf("x.ai redirect rejected: %v", err)
	}
}

func TestDiscoveryAddsDeadlineForInjectedClient(t *testing.T) {
	remaining := make(chan time.Duration, 1)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		deadline, ok := request.Context().Deadline()
		if !ok {
			remaining <- 0
		} else {
			remaining <- time.Until(deadline)
		}
		return nil, context.Canceled
	})}
	_, _ = NewDiscoveryClient(client, DiscoveryURL).Discover(context.Background())
	got := <-remaining
	if got <= 0 || got > HTTPTimeout {
		t.Fatalf("injected client deadline remaining = %v", got)
	}
}
func TestDiscoveryHonorsCallerDeadlineWithInjectedClient(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := NewDiscoveryClient(client, DiscoveryURL).Discover(ctx); err == nil {
		t.Fatal("discovery ignored request deadline")
	}
}
func TestValidateEndpoint(t *testing.T) {
	for _, value := range []string{"https://x.ai/path", "https://auth.x.ai/path", "https://deep.auth.x.ai/path"} {
		if _, err := ValidateEndpoint(value, "test"); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{"", "http://auth.x.ai/path", "https://notx.ai/path", "https://x.ai.evil/path"} {
		if _, err := ValidateEndpoint(value, "test"); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}
