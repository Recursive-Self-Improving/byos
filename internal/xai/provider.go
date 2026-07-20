package xai

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"byos/internal/provider"
	"byos/internal/search"
)

// RequestPolicy applies the xAI-only canonical request requirements.
type RequestPolicy struct{}

func (RequestPolicy) Prepare(_ context.Context, _ provider.ResolvedModel, request provider.CanonicalRequest) error {
	if err := search.Inject(request); err != nil {
		return invalidRequestError()
	}
	return nil
}

func invalidRequestError() error {
	return &provider.UpstreamError{Provider: provider.XAI, Status: http.StatusBadRequest, Classification: provider.ErrorClassification{
		Class: provider.ClassValidation, PublicStatus: http.StatusBadRequest,
		PublicCode: "invalid_request_error", PublicMessage: "invalid request",
	}}
}

// ProviderClient adapts the xAI Responses transport to the provider-neutral
// generation contract. The wrapped Client remains the sole wire encoder.
type ProviderClient struct {
	client  *Client
	now     func() time.Time
	encoder wireEncoder
}

func NewProviderClient(client *Client) *ProviderClient {
	return &ProviderClient{client: client, now: func() time.Time { return time.Now().UTC() }, encoder: encodeWireJSON}
}

func (c *ProviderClient) Execute(ctx context.Context, request provider.GenerationRequest) ([]provider.Event, error) {
	events, err := c.client.execute(ctx, request.Credential.Value, request.Model.UpstreamName, request.Canonical, c.encoder)
	if err != nil {
		return nil, c.adaptError(err)
	}
	return providerEvents(events), nil
}

func (c *ProviderClient) Stream(ctx context.Context, request provider.GenerationRequest) (provider.Stream, error) {
	stream, err := c.client.stream(ctx, request.Credential.Value, request.Model.UpstreamName, request.Canonical, c.encoder)
	if err != nil {
		return nil, c.adaptError(err)
	}
	return &providerStream{stream: stream, adaptError: c.adaptError}, nil
}

type providerStream struct {
	stream     *responseStream
	adaptError func(error) error
}

func (s *providerStream) Next(ctx context.Context) (provider.Event, error) {
	event, err := s.stream.Next(ctx)
	if err != nil {
		return provider.Event{}, s.adaptError(err)
	}
	return providerEvent(event), nil
}

func (s *providerStream) Close() error { return s.stream.Close() }

func providerEvents(events []Event) []provider.Event {
	result := make([]provider.Event, len(events))
	for i := range events {
		result[i] = providerEvent(events[i])
	}
	return result
}

func providerEvent(event Event) provider.Event {
	return provider.Event{Event: event.Event, Data: event.Data}
}

func (c *ProviderClient) adaptError(err error) error {
	if err == nil {
		return nil
	}
	now := c.now()
	classification := provider.ErrorClassification{
		Class:         provider.ClassUpstream,
		PublicStatus:  http.StatusBadGateway,
		PublicCode:    "provider_error",
		PublicMessage: "upstream provider error",
	}
	if errors.Is(err, context.Canceled) {
		return err
	}
	var upstream *UpstreamError
	if !errors.As(err, &upstream) {
		var networkError net.Error
		if errors.As(err, &networkError) {
			classification.Class = provider.ClassConnection
			classification.RetryNext = true
			classification.PublicStatus = http.StatusServiceUnavailable
			classification.PublicCode = "provider_unavailable"
		}
		return &provider.UpstreamError{Provider: provider.XAI, Classification: classification}
	}
	classification = classifyUpstream(upstream.Status, upstream.Headers, []byte(upstream.Body), now)
	return &provider.UpstreamError{Provider: provider.XAI, Status: upstream.Status, Classification: classification}
}

func classifyUpstream(status int, headers http.Header, body []byte, now time.Time) provider.ErrorClassification {
	result := provider.ErrorClassification{Class: provider.ClassUpstream, PublicStatus: http.StatusBadGateway, PublicCode: "provider_error", PublicMessage: "upstream provider error"}
	switch status {
	case http.StatusBadRequest, http.StatusNotFound:
		result.Class = provider.ClassValidation
		result.PublicStatus = http.StatusBadRequest
		result.PublicCode = "invalid_request_error"
		result.PublicMessage = "invalid model or request payload"
	case http.StatusUnauthorized:
		result.Class = provider.ClassUnauthorized
		result.RefreshSame = true
		result.RetryNext = true
		result.CooldownScope = provider.CooldownAccount
		result.PublicStatus = http.StatusUnauthorized
		result.PublicCode = "provider_authentication_error"
	case http.StatusPaymentRequired, http.StatusForbidden:
		result.Class = provider.ClassPermission
		result.CooldownScope = provider.CooldownAccount
		result.PublicStatus = http.StatusForbidden
		result.PublicCode = "provider_permission_error"
	case http.StatusRequestTimeout, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		result.Class = provider.ClassTransient
		result.RetryNext = true
		result.CooldownScope = provider.CooldownModel
		result.Cooldown = time.Minute
		result.PublicStatus = http.StatusServiceUnavailable
		result.PublicCode = "provider_unavailable"
	case http.StatusTooManyRequests:
		result.PublicStatus = http.StatusTooManyRequests
		result.PublicCode = "rate_limit_exceeded"
		result.PublicMessage = "all available accounts are rate limited"
		result.RetryNext = true
		result.CooldownScope = provider.CooldownModel
		if freeUsageExhausted(body) {
			result.Class = provider.ClassFreeUsageExhausted
			result.Cooldown = 24 * time.Hour
			result.RetryAfter = now.Add(result.Cooldown)
			return result
		}
		result.Class = provider.ClassRateLimit
		if retryAt, ok := parseRetryAfter(headers.Get("Retry-After"), now); ok {
			result.ExplicitRetryAfter = true
			result.RetryAfter = retryAt
			result.Cooldown = retryAt.Sub(now)
		}
	}
	return result
}

func freeUsageExhausted(body []byte) bool {
	var payload map[string]any
	return json.Unmarshal(body, &payload) == nil && exactErrorCode(payload) == "subscription:free-usage-exhausted"
}

func exactErrorCode(payload map[string]any) string {
	for _, key := range []string{"code", "type"} {
		if value, _ := payload[key].(string); value != "" {
			return value
		}
	}
	switch value := payload["error"].(type) {
	case string:
		return value
	case map[string]any:
		return exactErrorCode(value)
	default:
		return ""
	}
}

func parseRetryAfter(value string, now time.Time) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return now.Add(time.Duration(seconds) * time.Second), true
	}
	parsed, err := http.ParseTime(value)
	if err != nil {
		return time.Time{}, false
	}
	if parsed.Before(now) {
		parsed = now
	}
	return parsed, true
}

var _ provider.RequestPolicy = RequestPolicy{}
var _ provider.GenerationClient = (*ProviderClient)(nil)
var _ provider.Stream = (*providerStream)(nil)
