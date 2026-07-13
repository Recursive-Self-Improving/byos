package errors

import (
	"errors"
	"net/http"
	"time"

	"supergrok-api/internal/routing"
	"supergrok-api/internal/sessions"
)

type Kind string

const (
	Validation               Kind = "validation"
	Authentication           Kind = "authentication"
	ModelUnavailable         Kind = "model_unavailable"
	Cooldown                 Kind = "cooldown"
	ContextLimit             Kind = "context_limit"
	PreviousResponseNotFound Kind = "previous_response_not_found"
	UpstreamFailure          Kind = "upstream_failure"
	InternalFailure          Kind = "internal_failure"
)

func KindOf(err error) Kind {
	switch {
	case errors.Is(err, routing.ErrModelUnavailable), errors.Is(err, routing.ErrNoAvailableAccounts):
		return ModelUnavailable
	case errors.Is(err, sessions.ErrContextLengthExceeded):
		return ContextLimit
	case errors.Is(err, sessions.ErrPreviousResponseNotFound):
		return PreviousResponseNotFound
	default:
		return InternalFailure
	}
}
func FromClassified(value routing.ClassifiedError) Kind {
	switch value.Class {
	case routing.ClassValidation:
		return Validation
	case routing.ClassUnauthorized, routing.ClassInvalidGrant:
		return Authentication
	case routing.ClassRateLimit, routing.ClassFreeUsageExhausted:
		return Cooldown
	case routing.ClassPermission, routing.ClassTransient, routing.ClassConnection, routing.ClassUpstream:
		return UpstreamFailure
	case routing.ClassCancelled:
		return InternalFailure
	default:
		return InternalFailure
	}
}
func OpenAI(kind Kind, retry time.Duration) publicError {
	switch kind {
	case Validation:
		return publicError{Status: 400, Type: "invalid_request_error", Code: "invalid_request_error", Message: "invalid request"}
	case Authentication:
		return publicError{Status: 401, Type: "authentication_error", Code: "invalid_api_key", Message: "invalid authentication credentials"}
	case ModelUnavailable:
		return publicError{Status: 404, Type: "invalid_request_error", Code: "model_not_found", Message: "requested model is unavailable"}
	case Cooldown:
		return publicError{Status: 429, Type: "rate_limit_error", Code: "rate_limit_exceeded", Message: "all available accounts are rate limited", RetryAfter: retry}
	case ContextLimit:
		return publicError{Status: 400, Type: "invalid_request_error", Code: "context_length_exceeded", Message: "reconstructed context exceeds the allowed limit"}
	case PreviousResponseNotFound:
		return publicError{Status: 400, Type: "invalid_request_error", Code: "previous_response_not_found", Message: "previous response was not found or has expired"}
	case UpstreamFailure:
		return publicError{Status: 502, Type: "api_error", Code: "provider_error", Message: "upstream provider error"}
	default:
		return publicError{Status: 500, Type: "internal_error", Code: "internal_error", Message: "internal server error"}
	}
}
func Anthropic(kind Kind, retry time.Duration) publicError {
	switch kind {
	case Validation, ContextLimit, PreviousResponseNotFound:
		return publicError{Status: 400, Type: "invalid_request_error", Message: OpenAI(kind, retry).Message}
	case Authentication:
		return publicError{Status: 401, Type: "authentication_error", Message: "invalid authentication credentials"}
	case ModelUnavailable:
		return publicError{Status: 404, Type: "not_found_error", Message: "requested model is unavailable"}
	case Cooldown:
		return publicError{Status: 429, Type: "rate_limit_error", Message: "all available accounts are rate limited", RetryAfter: retry}
	case UpstreamFailure:
		return publicError{Status: 502, Type: "api_error", Message: "upstream provider error"}
	default:
		return publicError{Status: http.StatusInternalServerError, Type: "api_error", Message: "internal server error"}
	}
}
