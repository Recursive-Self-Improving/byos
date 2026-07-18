package api

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"

	"byos/internal/accounts"
	"byos/internal/api/middleware"
)

type ServerHandlers struct{ Health, Ready, Models, Chat, Responses, Messages, CountTokens, Admin, Web http.Handler }
type ServerConfig struct {
	Handlers      ServerHandlers
	ClientKeys    *accounts.APIKeyService
	AdminAPIKey   string
	AdminAttempts middleware.AdminAttemptPolicy
	AdminSources  middleware.SourceResolver
	MaxBodyBytes  int64
	Logger        *slog.Logger
}

func NewServer(config ServerConfig) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", config.Handlers.Health)
	mux.Handle("GET /readyz", config.Handlers.Ready)
	clientAuth := middleware.ClientAuth(config.ClientKeys)
	mux.Handle("GET /v1/models", clientAuth(config.Handlers.Models))
	limit := func(handler http.Handler) http.Handler { return limitBody(config.MaxBodyBytes, handler) }
	mux.Handle("POST /v1/chat/completions", clientAuth(limit(config.Handlers.Chat)))
	mux.Handle("POST /v1/responses", clientAuth(limit(config.Handlers.Responses)))
	mux.Handle("POST /v1/messages", clientAuth(limit(config.Handlers.Messages)))
	mux.Handle("POST /v1/messages/count_tokens", clientAuth(limit(config.Handlers.CountTokens)))
	if config.Handlers.Admin != nil {
		mux.Handle("/admin/api/v1/", middleware.AdminAuth(config.AdminAPIKey, config.AdminAttempts, config.AdminSources)(config.Handlers.Admin))
	}
	if config.Handlers.Web != nil {
		mux.Handle("/admin/", config.Handlers.Web)
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return recovery(logger, securityHeaders(requestIDs(mux)))
}
func limitBody(max int64, next http.Handler) http.Handler {
	if max <= 0 {
		max = DefaultMaxBody
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, max)
		next.ServeHTTP(w, r)
	})
}
func requestIDs(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var raw [16]byte
		_, _ = rand.Read(raw[:])
		w.Header().Set("X-Request-Id", hex.EncodeToString(raw[:]))
		next.ServeHTTP(w, r)
	})
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
func recovery(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if value := recover(); value != nil {
				logger.Error("panic recovered", "request_id", w.Header().Get("X-Request-Id"))
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
