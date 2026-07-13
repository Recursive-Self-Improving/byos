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
)

type Discovery struct{ Issuer, AuthorizationEndpoint, DeviceAuthorizationEndpoint, TokenEndpoint, JWKSURI string }
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
func (c *DiscoveryClient) Discover(ctx context.Context) (Discovery, error) {
	c.mu.RLock()
	if c.cached != nil {
		value := *c.cached
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
		Issuer        string `json:"issuer"`
		Authorization string `json:"authorization_endpoint"`
		Device        string `json:"device_authorization_endpoint"`
		Token         string `json:"token_endpoint"`
		JWKS          string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return Discovery{}, errors.New("invalid xAI discovery document")
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
	result := Discovery{Issuer: raw.Issuer, AuthorizationEndpoint: raw.Authorization, DeviceAuthorizationEndpoint: raw.Device, TokenEndpoint: raw.Token, JWKSURI: raw.JWKS}
	c.mu.Lock()
	if c.cached == nil {
		copy := result
		c.cached = &copy
	}
	result = *c.cached
	c.mu.Unlock()
	return result, nil
}
