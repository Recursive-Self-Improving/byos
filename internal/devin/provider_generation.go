package devin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"

	"byos/internal/provider"
)

// ProviderClient adapts the Devin streaming transport to the provider-neutral
// generation contract. Execute consumes the same single upstream stream used by
// Stream; Devin has no separate non-stream generation operation.
type ProviderClient struct {
	client        *Client
	newResponseID func() (string, error)
}

func NewProviderClient(client *Client) *ProviderClient {
	return &ProviderClient{client: client, newResponseID: newResponseID}
}

// newResponseID is the production crypto-random response-ID generator. It is
// package-private; tests pin response IDs by setting ProviderClient.newResponseID
// directly within the devin package.

func (c *ProviderClient) Stream(ctx context.Context, request provider.GenerationRequest) (provider.Stream, error) {
	if c == nil || c.client == nil {
		return nil, ErrInvalidClientConfig
	}
	responseID, err := c.newResponseID()
	if err != nil {
		return nil, &provider.UpstreamError{Provider: provider.Devin, Classification: upstreamClassification()}
	}
	stream, err := c.client.StreamChat(ctx, request.Credential.Value, request.Canonical, request.Model.UpstreamName, responseID)
	if err != nil {
		return nil, adaptGenerationError(err)
	}
	return &generationStream{stream: stream}, nil
}

func (c *ProviderClient) Execute(ctx context.Context, request provider.GenerationRequest) ([]provider.Event, error) {
	stream, err := c.Stream(ctx, request)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	limit := c.client.maxNonStreamBytes
	if limit <= 0 {
		return nil, ErrInvalidClientConfig
	}
	var size int64
	events := make([]provider.Event, 0, 8)
	for {
		event, nextErr := stream.Next(ctx)
		if nextErr != nil {
			if errors.Is(nextErr, io.EOF) {
				return events, nil
			}
			return nil, nextErr
		}
		if int64(len(event.Data)) > limit-size {
			return nil, adaptGenerationError(ErrStreamLimit)
		}
		size += int64(len(event.Data))
		events = append(events, event)
	}
}

type generationStream struct{ stream provider.Stream }

func (s *generationStream) Next(ctx context.Context) (provider.Event, error) {
	event, err := s.stream.Next(ctx)
	if err != nil {
		return provider.Event{}, adaptGenerationError(err)
	}
	return event, nil
}
func (s *generationStream) Close() error { return s.stream.Close() }

func newResponseID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "resp_" + hex.EncodeToString(raw[:]), nil
}

func adaptGenerationError(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var classified *provider.UpstreamError
	if errors.As(err, &classified) {
		return err
	}
	classification := upstreamClassification()
	var status *HTTPStatusError
	if errors.As(err, &status) {
		classification = classifyGenerationStatus(status.StatusCode)
		return &provider.UpstreamError{Provider: provider.Devin, Status: status.StatusCode, Classification: classification}
	}
	var networkError net.Error
	if errors.As(err, &networkError) {
		classification.Class = provider.ClassConnection
		classification.RetryNext = true
		classification.PublicStatus = http.StatusServiceUnavailable
		classification.PublicCode = "provider_unavailable"
	}
	return &provider.UpstreamError{Provider: provider.Devin, Classification: classification}
}

func upstreamClassification() provider.ErrorClassification {
	return provider.ErrorClassification{Class: provider.ClassUpstream, RetryNext: true, CooldownScope: provider.CooldownModel, PublicStatus: http.StatusBadGateway, PublicCode: "provider_error", PublicMessage: "upstream provider error"}
}

func classifyGenerationStatus(status int) provider.ErrorClassification {
	result := upstreamClassification()
	switch status {
	case http.StatusBadRequest, http.StatusNotFound:
		result.Class = provider.ClassValidation
		result.RetryNext = false
		result.CooldownScope = ""
		result.PublicStatus = http.StatusBadRequest
		result.PublicCode = "invalid_request_error"
		result.PublicMessage = "invalid model or request payload"
	case http.StatusUnauthorized, http.StatusForbidden:
		result.Class = provider.ClassUnauthorized
		result.RefreshSame = true
		result.RetryNext = true
		result.DisableAccount = true
		result.ReloginRequired = true
		result.CooldownScope = provider.CooldownAccount
		result.PublicStatus = http.StatusUnauthorized
		result.PublicCode = "provider_authentication_error"
		result.PublicMessage = "provider authentication is required"
	case http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		result.Class = provider.ClassTransient
		result.RetryNext = true
		result.CooldownScope = provider.CooldownModel
		result.PublicStatus = http.StatusServiceUnavailable
		result.PublicCode = "provider_unavailable"
	}
	return result
}

var _ provider.GenerationClient = (*ProviderClient)(nil)
var _ provider.Stream = (*generationStream)(nil)
