package middleware

import (
	"context"
	"net/http"
	"strings"

	"supergrok-api/internal/accounts"
	apierrors "supergrok-api/internal/api/errors"
)

type clientIdentity struct{ ID, Label string }
type contextKey string

const clientIdentityKey contextKey = "client_identity"

func ClientIdentity(ctx context.Context) (id, label string, ok bool) {
	value, ok := ctx.Value(clientIdentityKey).(clientIdentity)
	if !ok {
		return "", "", false
	}
	return value.ID, value.Label, true
}
func ClientAuth(service *accounts.APIKeyService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			scheme, token, bearer := strings.Cut(header, " ")
			if !bearer || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
				if strings.HasPrefix(r.URL.Path, "/v1/messages") {
					token = r.Header.Get("x-api-key")
				} else {
					token = ""
				}
			}
			token = strings.TrimSpace(token)
			if token == "" {
				writeClientUnauthorized(w, r)
				return
			}
			key, err := service.Authenticate(r.Context(), token)
			if err != nil {
				writeClientUnauthorized(w, r)
				return
			}
			ctx := context.WithValue(r.Context(), clientIdentityKey, clientIdentity{ID: key.ID, Label: key.Label})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
func writeClientUnauthorized(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	if strings.HasPrefix(r.URL.Path, "/v1/messages") {
		apierrors.WriteAnthropic(w, apierrors.Anthropic(apierrors.Authentication, 0))
		return
	}
	apierrors.WriteOpenAI(w, apierrors.OpenAI(apierrors.Authentication, 0))
}
