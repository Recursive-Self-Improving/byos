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
	"byos/internal/routing"
	"byos/internal/xai"
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
	Next(context.Context) (xai.Event, error)
	Close() error
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
	var execution *routing.ExecutionError
	if errors.As(err, &execution) {
		retry := execution.Classified.Cooldown
		if !execution.Classified.RetryAfter.IsZero() {
			retry = time.Until(execution.Classified.RetryAfter)
			if retry < 0 {
				retry = 0
			}
		}
		apierrors.WriteOpenAI(w, apierrors.OpenAI(apierrors.FromClassified(execution.Classified), retry))
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
	var execution *routing.ExecutionError
	if errors.As(err, &execution) {
		retry := execution.Classified.Cooldown
		if !execution.Classified.RetryAfter.IsZero() {
			retry = time.Until(execution.Classified.RetryAfter)
			if retry < 0 {
				retry = 0
			}
		}
		apierrors.WriteAnthropic(w, apierrors.Anthropic(apierrors.FromClassified(execution.Classified), retry))
		return
	}
	apierrors.WriteAnthropic(w, apierrors.Anthropic(apierrors.KindOf(err), 0))
}
