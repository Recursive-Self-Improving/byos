package usage

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"byos/internal/provider"
)

// XAIProvider adapts the existing xAI billing client to the optional provider
// usage capability. Raw remains the exact bounded billing representation used
// by the encrypted usage snapshot repository.
type XAIProvider struct {
	client *Client
	now    func() time.Time
}

func NewXAIProvider(client *Client) *XAIProvider {
	return &XAIProvider{client: client, now: time.Now}
}

func (p *XAIProvider) FetchUsage(ctx context.Context, credential provider.Credential) (provider.UsageSnapshot, error) {
	if p == nil || p.client == nil {
		return provider.UsageSnapshot{}, errors.New("xAI usage is unavailable")
	}
	result, err := p.client.Fetch(ctx, provider.XAI, credential)
	if err != nil {
		return provider.UsageSnapshot{}, sanitizedUsageError(err)
	}
	return provider.UsageSnapshot{
		Monthly:   monthlyToProvider(result.Monthly),
		Weekly:    weeklyToProvider(result.Weekly),
		FetchedAt: p.now().UTC(),
		Raw:       append([]byte(nil), result.Raw...),
	}, nil
}

func monthlyToProvider(value *Monthly) *provider.MonthlyUsage {
	if value == nil {
		return nil
	}
	return &provider.MonthlyUsage{Limit: value.Limit, Used: value.Used, Remaining: value.Remaining, ResetAt: value.ResetAt}
}

func weeklyToProvider(value *Weekly) *provider.WeeklyUsage {
	if value == nil {
		return nil
	}
	return &provider.WeeklyUsage{UsedPercent: value.UsedPercent, RemainingPercent: value.RemainingPercent, ResetAt: value.ResetAt, OnDemand: value.OnDemand, Prepaid: value.Prepaid}
}

func sanitizedUsageError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var status *HTTPError
	if errors.As(err, &status) {
		return &HTTPError{Status: status.Status, RetryAfter: status.RetryAfter}
	}
	var transport *url.Error
	if errors.As(err, &transport) {
		return fmt.Errorf("xAI usage refresh failed")
	}
	if errors.Is(err, ErrSchema) {
		return ErrSchema
	}
	if errors.Is(err, provider.ErrProviderMismatch) {
		return provider.ErrProviderMismatch
	}
	return fmt.Errorf("xAI usage refresh failed")
}

var _ provider.UsageFetcher = (*XAIProvider)(nil)
