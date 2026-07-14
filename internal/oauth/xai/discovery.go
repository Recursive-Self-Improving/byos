// Portions adapted from CLIProxyAPI/v7 internal/auth/xai/xai.go (MIT): OIDC discovery and endpoint validation.
// Upstream: https://github.com/router-for-me/CLIProxyAPI/blob/main/internal/auth/xai/xai.go

package xai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
)

type Discovery struct {
	Issuer, AuthorizationEndpoint, DeviceAuthorizationEndpoint, TokenEndpoint, JWKSURI string
	IDTokenSigningAlgs                                                                 []string
}
type DiscoveryClient struct {
	http   *http.Client
	url    string
	mu     sync.RWMutex
	cached *Discovery
}

func NewDiscoveryClient(client *http.Client, discoveryURL string) *DiscoveryClient {
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = http.ProxyFromEnvironment
		client = &http.Client{Transport: transport, Timeout: HTTPTimeout}
	}
	copyClient := *client
	previousRedirect := copyClient.CheckRedirect
	copyClient.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if _, err := ValidateEndpoint(request.URL.String(), "redirect"); err != nil {
			return err
		}
		if previousRedirect != nil {
			return previousRedirect(request, via)
		}
		if len(via) >= 10 {
			return errors.New("too many xAI discovery redirects")
		}
		return nil
	}
	client = &copyClient
	if discoveryURL == "" {
		discoveryURL = DiscoveryURL
	}
	return &DiscoveryClient{http: client, url: discoveryURL}
}
func ValidateEndpoint(raw, field string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("xAI discovery %s is empty", field)
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return "", fmt.Errorf("xAI discovery %s must be an absolute HTTPS URL", field)
	}
	host := strings.ToLower(parsed.Hostname())
	if host != "x.ai" && !strings.HasSuffix(host, ".x.ai") {
		return "", fmt.Errorf("xAI discovery %s host is not on x.ai", field)
	}
	return raw, nil
}

func supportedIDTokenSigningAlgs(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		switch value {
		case oidc.RS256, oidc.RS384, oidc.RS512, oidc.ES256, oidc.ES384, oidc.ES512, oidc.PS256, oidc.PS384, oidc.PS512, oidc.EdDSA:
			result = append(result, value)
		}
	}
	return result
}

func cloneDiscovery(value Discovery) Discovery {
	value.IDTokenSigningAlgs = append([]string(nil), value.IDTokenSigningAlgs...)
	return value
}
func (c *DiscoveryClient) Discover(ctx context.Context) (Discovery, error) {
	c.mu.RLock()
	if c.cached != nil {
		value := cloneDiscovery(*c.cached)
		c.mu.RUnlock()
		return value, nil
	}
	c.mu.RUnlock()
	requestCtx, cancel := context.WithTimeout(ctx, HTTPTimeout)
	defer cancel()
	if _, err := ValidateEndpoint(c.url, "URL"); err != nil {
		return Discovery{}, err
	}
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, c.url, nil)
	if err != nil {
		return Discovery{}, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return Discovery{}, fmt.Errorf("xAI discovery request: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return Discovery{}, err
	}
	if response.StatusCode != http.StatusOK {
		return Discovery{}, fmt.Errorf("xAI discovery returned HTTP %d", response.StatusCode)
	}
	var raw struct {
		Issuer            string   `json:"issuer"`
		Authorization     string   `json:"authorization_endpoint"`
		Device            string   `json:"device_authorization_endpoint"`
		Token             string   `json:"token_endpoint"`
		JWKS              string   `json:"jwks_uri"`
		IDTokenSigningAlg []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return Discovery{}, errors.New("invalid xAI discovery document")
	}
	signingAlgs := supportedIDTokenSigningAlgs(raw.IDTokenSigningAlg)
	if len(signingAlgs) == 0 {
		return Discovery{}, errors.New("xAI discovery has no supported ID token signing algorithm")
	}
	values := []struct {
		value, field string
		target       *string
	}{{raw.Issuer, "issuer", &raw.Issuer}, {raw.Authorization, "authorization_endpoint", &raw.Authorization}, {raw.Device, "device_authorization_endpoint", &raw.Device}, {raw.Token, "token_endpoint", &raw.Token}, {raw.JWKS, "jwks_uri", &raw.JWKS}}
	for _, item := range values {
		validated, err := ValidateEndpoint(item.value, item.field)
		if err != nil {
			return Discovery{}, err
		}
		*item.target = validated
	}
	if raw.Issuer != Issuer {
		return Discovery{}, errors.New("xAI discovery issuer mismatch")
	}
	result := Discovery{Issuer: raw.Issuer, AuthorizationEndpoint: raw.Authorization, DeviceAuthorizationEndpoint: raw.Device, TokenEndpoint: raw.Token, JWKSURI: raw.JWKS, IDTokenSigningAlgs: signingAlgs}
	c.mu.Lock()
	if c.cached == nil {
		copy := cloneDiscovery(result)
		c.cached = &copy
	}
	result = cloneDiscovery(*c.cached)
	c.mu.Unlock()
	return result, nil
}
