package errors

import (
	"encoding/json"
	"net/http"
	"strconv"
)

func WriteAnthropic(w http.ResponseWriter, value publicError) {
	if value.Status == 0 {
		value.Status = http.StatusInternalServerError
	}
	if value.Type == "" {
		value.Type = "api_error"
	}
	if value.Message == "" {
		value.Message = "internal server error"
	}
	w.Header().Set("Content-Type", "application/json")
	if value.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(value.RetryAfter)))
	}
	w.WriteHeader(value.Status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]string{"type": value.Type, "message": value.Message}})
}
