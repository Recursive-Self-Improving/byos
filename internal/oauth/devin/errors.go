package devin

import (
	"context"
	"errors"
	"fmt"
)

var (
	ErrRandomness            = errors.New("devin oauth randomness unavailable")
	ErrInvalidCallback       = errors.New("invalid Devin OAuth callback configuration")
	ErrInvalidAuthorization  = errors.New("invalid Devin OAuth authorization request")
	ErrInvalidClientConfig   = errors.New("invalid Devin OAuth exchange configuration")
	ErrExchangeTransport     = errors.New("Devin OAuth exchange transport failed")
	ErrExchangeRedirect      = errors.New("Devin OAuth exchange redirect refused")
	ErrExchangeStatus        = errors.New("Devin OAuth exchange rejected")
	ErrExchangeEncoding      = errors.New("Devin OAuth exchange response encoding invalid")
	ErrExchangeTooLarge      = errors.New("Devin OAuth exchange response too large")
	ErrExchangeProtocol      = errors.New("Devin OAuth exchange response invalid")
	ErrExchangeTokenRequired = errors.New("Devin OAuth exchange token missing")
)

// Error is a sanitized protocol error. It intentionally retains only a stable
// category and, for HTTP rejection, the status code. It never retains response
// bodies, URLs, callback codes, PKCE verifiers, or transport error text.
type Error struct {
	Kind   error
	Status int
	cause  error
}

func (e *Error) Error() string {
	if e == nil || e.Kind == nil {
		return "Devin OAuth exchange failed"
	}
	if e.Status != 0 {
		return fmt.Sprintf("%s (status %d)", e.Kind.Error(), e.Status)
	}
	return e.Kind.Error()
}

func (e *Error) Unwrap() []error {
	if e == nil {
		return nil
	}
	if e.cause != nil {
		return []error{e.Kind, e.cause}
	}
	return []error{e.Kind}
}

func protocolError(kind error) error { return &Error{Kind: kind} }
func statusError(status int) error   { return &Error{Kind: ErrExchangeStatus, Status: status} }
func transportError(cause error) error {
	return &Error{Kind: ErrExchangeTransport, cause: safeContextCause(cause)}
}

func safeContextCause(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	default:
		return nil
	}
}
