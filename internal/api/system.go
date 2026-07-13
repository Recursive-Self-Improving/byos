package api

import (
	"context"
	"encoding/json"
	"net/http"
)

type Liveness interface{ PingContext(context.Context) error }
type Readiness interface{ Ready(context.Context) bool }

func HealthHandler(database Liveness) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := database.PingContext(r.Context()); err != nil {
			http.Error(w, "unhealthy", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
}
func ReadyHandler(readiness Readiness) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ready := readiness.Ready(r.Context())
		w.Header().Set("Content-Type", "application/json")
		if !ready {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{"ready": false})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ready": true})
	})
}
