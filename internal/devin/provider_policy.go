package devin

import (
	"context"
	"net/http"

	"byos/internal/provider"
)

// RequestPolicy applies the Devin pass-through canonical request requirements.
// Unlike xAI, Devin has no backend-search injection; the policy only validates
// that the canonical request is a non-nil JSON object before the executor
// overwrites the public model with the resolved upstream name. All request
// shaping is performed by the Devin wire encoder inside the generation client.
type RequestPolicy struct{}

func (RequestPolicy) Prepare(_ context.Context, _ provider.ResolvedModel, request provider.CanonicalRequest) error {
	if request == nil {
		return &provider.UpstreamError{Provider: provider.Devin, Status: http.StatusBadRequest, Classification: provider.ErrorClassification{
			Class: provider.ClassValidation, PublicStatus: http.StatusBadRequest, PublicCode: "invalid_request_error", PublicMessage: "invalid request",
		}}
	}
	return nil
}

var _ provider.RequestPolicy = RequestPolicy{}
