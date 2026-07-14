// Retry classification semantics adapted from CLIProxyAPI/v7 sdk/cliproxy/auth/conductor.go (MIT).
// Upstream: https://github.com/router-for-me/CLIProxyAPI/blob/v7.2.71/sdk/cliproxy/auth/conductor.go

package routing

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type ErrorClass string

const (
	ClassValidation         ErrorClass = "validation"
	ClassUnauthorized       ErrorClass = "unauthorized"
	ClassInvalidGrant       ErrorClass = "invalid_grant"
	ClassPermission         ErrorClass = "permission"
	ClassFreeUsageExhausted ErrorClass = "free_usage_exhausted"
	ClassRateLimit          ErrorClass = "rate_limit"
	ClassTransient          ErrorClass = "transient"
	ClassConnection         ErrorClass = "connection"
	ClassCancelled          ErrorClass = "cancelled"
	ClassUpstream           ErrorClass = "upstream"
)

type ClassifiedError struct {
	Class                                               ErrorClass
	RetryNext, RefreshSame, DisableAccount, AccountWide bool
	ExplicitRetryAfter                                  bool
	Cooldown                                            time.Duration
	RetryAfter                                          time.Time
	PublicStatus                                        int
	PublicCode, PublicMessage                           string
}

type ConnectionSetupError struct{ Err error }

func (e *ConnectionSetupError) Error() string { return e.Err.Error() }
func (e *ConnectionSetupError) Unwrap() error { return e.Err }

func Classify(status int, headers http.Header, body []byte, err error, billingReset *time.Time, now time.Time) ClassifiedError {
	base := ClassifiedError{Class: ClassUpstream, PublicStatus: http.StatusBadGateway, PublicCode: "provider_error", PublicMessage: "upstream provider error"}
	if errors.Is(err, context.Canceled) {
		base.Class = ClassCancelled
		base.PublicStatus = 499
		base.PublicCode = "request_cancelled"
		base.PublicMessage = "request cancelled"
		return base
	}
	if err != nil {
		var setup *ConnectionSetupError
		if errors.As(err, &setup) {
			base.Class = ClassConnection
			base.RetryNext = true
			base.PublicCode = "provider_unavailable"
			base.PublicStatus = http.StatusServiceUnavailable
		}
		return base
	}
	switch status {
	case 400, 404:
		base.Class = ClassValidation
		base.PublicStatus = http.StatusBadRequest
		base.PublicCode = "invalid_request_error"
		base.PublicMessage = "invalid model or request payload"
		return base
	case 401:
		base.Class = ClassUnauthorized
		base.RefreshSame = true
		base.RetryNext = true
		base.AccountWide = true
		base.PublicStatus = http.StatusUnauthorized
		base.PublicCode = "provider_authentication_error"
		return base
	case 402, 403:
		base.Class = ClassPermission
		base.AccountWide = true
		base.PublicStatus = http.StatusForbidden
		base.PublicCode = "provider_permission_error"
		return base
	case 408, 500, 502, 503, 504:
		base.Class = ClassTransient
		base.RetryNext = true
		base.Cooldown = time.Minute
		base.PublicStatus = http.StatusServiceUnavailable
		base.PublicCode = "provider_unavailable"
		return base
	case 429:
		base.PublicStatus = http.StatusTooManyRequests
		base.PublicCode = "rate_limit_exceeded"
		base.PublicMessage = "all available accounts are rate limited"
		if freeUsageExhausted(body) {
			base.Class = ClassFreeUsageExhausted
			base.RetryNext = true
			if billingReset != nil && billingReset.After(now) {
				base.RetryAfter = *billingReset
				base.Cooldown = billingReset.Sub(now)
			} else {
				base.Cooldown = 24 * time.Hour
				base.RetryAfter = now.Add(base.Cooldown)
			}
			return base
		}
		base.Class = ClassRateLimit
		base.RetryNext = true
		if retry, ok := parseRetryAfter(headers.Get("Retry-After"), now); ok {
			base.ExplicitRetryAfter = true
			base.RetryAfter = retry
			base.Cooldown = retry.Sub(now)
		}
		return base
	}
	return base
}
func InvalidGrant(description string) ClassifiedError {
	return ClassifiedError{Class: ClassInvalidGrant, RetryNext: true, DisableAccount: true, AccountWide: true, PublicStatus: http.StatusUnauthorized, PublicCode: "provider_authentication_error", PublicMessage: "account requires login"}
}
func freeUsageExhausted(body []byte) bool {
	var payload map[string]any
	if json.Unmarshal(body, &payload) != nil {
		return false
	}
	return exactErrorCode(payload) == "subscription:free-usage-exhausted"
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
