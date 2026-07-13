package middleware

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
)

func AdminAuth(expected string) func(http.Handler) http.Handler {
	expectedHash := sha256.Sum256([]byte(expected))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			scheme, token, ok := strings.Cut(header, " ")
			candidate := strings.TrimSpace(token)
			candidateHash := sha256.Sum256([]byte(candidate))
			valid := ok && strings.EqualFold(scheme, "Bearer") && subtle.ConstantTimeCompare(candidateHash[:], expectedHash[:]) == 1
			if !valid {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("WWW-Authenticate", "Bearer")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"type": "authentication_error", "message": "invalid authentication credentials"}})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
