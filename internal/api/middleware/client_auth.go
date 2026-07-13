package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"supergrok-api/internal/accounts"
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
			scheme, token, ok := strings.Cut(header, " ")
			if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
				writeClientUnauthorized(w, r)
				return
			}
			key, err := service.Authenticate(r.Context(), strings.TrimSpace(token))
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
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", "Bearer")
	w.WriteHeader(http.StatusUnauthorized)
	if strings.HasPrefix(r.URL.Path, "/v1/messages") {
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]string{"type": "authentication_error", "message": "invalid authentication credentials"}})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"type": "authentication_error", "message": "invalid authentication credentials"}})
}
