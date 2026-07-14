package middleware

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"supergrok-api/internal/auththrottle"
)

type AdminAttemptPolicy interface {
	Evaluate(context.Context, netip.Addr, auththrottle.Surface, func() bool) (auththrottle.Outcome, error)
}

type SourceResolver interface {
	ClientIP(*http.Request) (netip.Addr, error)
}

func AdminAuth(expected string, attempts AdminAttemptPolicy, sources SourceResolver) func(http.Handler) http.Handler {
	expectedHash := sha256.Sum256([]byte(expected))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			source, err := sources.ClientIP(r)
			if err != nil {
				writeAdminAuthError(w, http.StatusServiceUnavailable, "service_unavailable_error", "authentication is temporarily unavailable")
				return
			}
			outcome, err := attempts.Evaluate(r.Context(), source, auththrottle.SurfaceAdminBearer, func() bool {
				header := r.Header.Get("Authorization")
				scheme, token, ok := strings.Cut(header, " ")
				candidate := strings.TrimSpace(token)
				candidateHash := sha256.Sum256([]byte(candidate))
				return ok && strings.EqualFold(scheme, "Bearer") && subtle.ConstantTimeCompare(candidateHash[:], expectedHash[:]) == 1
			})
			if err != nil {
				writeAdminAuthError(w, http.StatusServiceUnavailable, "service_unavailable_error", "authentication is temporarily unavailable")
				return
			}
			switch outcome.Disposition {
			case auththrottle.Authenticated:
				next.ServeHTTP(w, r)
			case auththrottle.Blocked:
				w.Header().Set("Retry-After", strconv.FormatInt(adminRetryAfterSeconds(outcome.RetryAfter), 10))
				writeAdminAuthError(w, http.StatusTooManyRequests, "rate_limit_error", "too many authentication attempts")
			default:
				w.Header().Set("WWW-Authenticate", "Bearer")
				writeAdminAuthError(w, http.StatusUnauthorized, "authentication_error", "invalid authentication credentials")
			}
		})
	}
}

func writeAdminAuthError(w http.ResponseWriter, status int, kind, message string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"type": kind, "message": message}})
}

func adminRetryAfterSeconds(value time.Duration) int64 {
	seconds := int64((value + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}
