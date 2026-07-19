package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	apierrors "byos/internal/api/errors"
	"byos/internal/provider"
	"byos/internal/routing"
)

const DefaultMaxBody = 16 << 20

type ValidationError struct{ Err error }

func (e *ValidationError) Error() string { return e.Err.Error() }
func Invalid(err error) error            { return &ValidationError{Err: err} }

func ReadJSONBody(_ http.ResponseWriter, r *http.Request) ([]byte, error) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, Invalid(errors.New("content-type must be application/json"))
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, Invalid(err)
	}
	if !json.Valid(body) {
		return nil, Invalid(errors.New("invalid JSON body"))
	}
	return body, nil
}

type RoutedStream interface {
	provider.Stream
	Model() string
	AccountID() string
}
type ExecuteFunc func(context.Context, routing.Request) (routing.Result, error)
type StreamFunc func(context.Context, routing.Request) (RoutedStream, error)

func OpenAIError(w http.ResponseWriter, err error) {
	var validation *ValidationError
	if errors.As(err, &validation) {
		apierrors.WriteOpenAI(w, apierrors.OpenAI(apierrors.Validation, 0))
		return
	}
	if classified, ok := errorClassification(err); ok {
		retry, present := retryDuration(classified)
		if present && retry == 0 {
			w.Header().Set("Retry-After", "0")
		}
		apierrors.WriteOpenAI(w, apierrors.OpenAIClassification(classified, retry))
		return
	}
	apierrors.WriteOpenAI(w, apierrors.OpenAI(apierrors.KindOf(err), 0))
}
func AnthropicError(w http.ResponseWriter, err error) {
	var validation *ValidationError
	if errors.As(err, &validation) {
		apierrors.WriteAnthropic(w, apierrors.Anthropic(apierrors.Validation, 0))
		return
	}
	if classified, ok := errorClassification(err); ok {
		retry, present := retryDuration(classified)
		if present && retry == 0 {
			w.Header().Set("Retry-After", "0")
		}
		apierrors.WriteAnthropic(w, apierrors.AnthropicClassification(classified, retry))
		return
	}
	apierrors.WriteAnthropic(w, apierrors.Anthropic(apierrors.KindOf(err), 0))
}

func errorClassification(err error) (provider.ErrorClassification, bool) {
	var execution *routing.ExecutionError
	if errors.As(err, &execution) {
		return execution.Classified, true
	}
	var upstream *provider.UpstreamError
	if errors.As(err, &upstream) {
		return upstream.Classification, true
	}
	return provider.ErrorClassification{}, false
}

func retryDuration(classified provider.ErrorClassification) (time.Duration, bool) {
	retry := classified.Cooldown
	present := classified.ExplicitRetryAfter || retry > 0
	if !classified.RetryAfter.IsZero() {
		present = true
		retry = time.Until(classified.RetryAfter)
		if retry < 0 {
			return 0, true
		}
	}
	return retry, present
}
