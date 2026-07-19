package models

import (
	"context"
	"fmt"

	"byos/internal/provider"
	"byos/internal/xai"
)

// Client is the provider-bound entry to the existing xAI model discovery
// transport. The provider check deliberately precedes credential use and HTTP
// dispatch.
type Client struct {
	upstream *Upstream
}

func NewClient(client *xai.Client) *Client {
	return &Client{upstream: NewUpstream(client)}
}

func (c *Client) Discover(ctx context.Context, accountProvider provider.Kind, credential provider.Credential) ([]Model, error) {
	if accountProvider != provider.XAI {
		return nil, fmt.Errorf("xAI model discovery: %w", provider.ErrProviderMismatch)
	}
	if c == nil || c.upstream == nil {
		return nil, fmt.Errorf("xAI model discovery is unavailable")
	}
	return c.upstream.Discover(ctx, credential.Value)
}
