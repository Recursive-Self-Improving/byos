package models

import (
	"context"
	"errors"
	"fmt"

	"byos/internal/provider"
)

// XAIProvider adapts the existing xAI model client to the optional provider
// discovery capability. Static catalog ownership remains outside this adapter.
type XAIProvider struct {
	client *Client
}

func NewXAIProvider(client *Client) *XAIProvider { return &XAIProvider{client: client} }

func (p *XAIProvider) Discover(ctx context.Context, credential provider.Credential) ([]provider.DiscoveredModel, error) {
	if p == nil || p.client == nil {
		return nil, errors.New("xAI model discovery is unavailable")
	}
	models, err := p.client.Discover(ctx, provider.XAI, credential)
	if err != nil {
		return nil, sanitizedDiscoveryError(err)
	}
	result := make([]provider.DiscoveredModel, 0, len(models))
	for _, model := range models {
		var supportsSearch *bool
		if model.SupportsBackendSearch != nil {
			value := *model.SupportsBackendSearch
			supportsSearch = &value
		}
		result = append(result, provider.DiscoveredModel{
			UpstreamName:          model.ID,
			DisplayName:           model.DisplayName,
			SupportsBackendSearch: supportsSearch,
			ContextWindow:         model.ContextWindow,
			MaxOutputTokens:       model.MaxOutputTokens,
			ReasoningEfforts:      append([]string(nil), model.ReasoningEfforts...),
		})
	}
	return result, nil
}

func sanitizedDiscoveryError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var status *HTTPError
	if errors.As(err, &status) {
		if errors.Is(err, ErrCredential) {
			return errors.Join(ErrCredential, &HTTPError{Status: status.Status})
		}
		return &HTTPError{Status: status.Status}
	}
	if errors.Is(err, ErrCredential) {
		return ErrCredential
	}
	if errors.Is(err, ErrSchema) {
		return ErrSchema
	}
	return fmt.Errorf("xAI model discovery failed")
}

var _ provider.ModelDiscoverer = (*XAIProvider)(nil)
