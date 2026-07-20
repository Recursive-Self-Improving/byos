package usage

import (
	"context"
	"fmt"

	"byos/internal/provider"
	"byos/internal/xai"
)

// Client is the provider-bound entry to the existing xAI billing transport.
// The provider check deliberately precedes credential use and HTTP dispatch.
type Client struct {
	billing *BillingAdapter
}

func NewClient(client *xai.Client) *Client {
	return &Client{billing: NewBillingAdapter(client)}
}

func (c *Client) Fetch(ctx context.Context, accountProvider provider.Kind, credential provider.Credential) (BillingResult, error) {
	if accountProvider != provider.XAI {
		return BillingResult{}, fmt.Errorf("xAI usage: %w", provider.ErrProviderMismatch)
	}
	if c == nil || c.billing == nil {
		return BillingResult{}, fmt.Errorf("xAI usage is unavailable")
	}
	return c.billing.Fetch(ctx, credential.Value)
}
