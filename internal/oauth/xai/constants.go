// Portions adapted from CLIProxyAPI internal/auth/xai/types.go (MIT).
package xai

import (
	"errors"
	"net/http"
	"time"
)

const (
	Issuer              = "https://auth.x.ai"
	DiscoveryURL        = Issuer + "/.well-known/openid-configuration"
	DefaultClientID     = "b1a00492-073a-47ea-816f-4c329264a828"
	DefaultScopes       = "openid profile email offline_access grok-cli:access api:access"
	DeviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"
	MinimumPollInterval = 5 * time.Second
	RefreshLead         = 5 * time.Minute
	MaximumFlowDuration = 30 * time.Minute
	HTTPTimeout         = 30 * time.Second
)

type Options struct{ ClientID, Scopes string }

func DefaultOptions() Options { return Options{ClientID: DefaultClientID, Scopes: DefaultScopes} }
func (o Options) withDefaults() Options {
	defaults := DefaultOptions()
	if o.ClientID == "" {
		o.ClientID = defaults.ClientID
	}
	if o.Scopes == "" {
		o.Scopes = defaults.Scopes
	}
	return o
}

func secureOAuthClient(client *http.Client) *http.Client {
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = http.ProxyFromEnvironment
		client = &http.Client{Transport: transport, Timeout: HTTPTimeout}
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("OAuth credential endpoint redirects are not allowed")
	}
	if copyClient.Timeout == 0 || copyClient.Timeout > HTTPTimeout {
		copyClient.Timeout = HTTPTimeout
	}
	return &copyClient
}
