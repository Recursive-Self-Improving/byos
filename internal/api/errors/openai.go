package errors

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

type publicError struct {
	Status                     int
	Type, Code, Message, Param string
	RetryAfter                 time.Duration
}

func WriteOpenAI(w http.ResponseWriter, value publicError) {
	if value.Status == 0 {
		value.Status = http.StatusInternalServerError
	}
	if value.Type == "" {
		value.Type = "internal_error"
	}
	if value.Message == "" {
		value.Message = "internal server error"
	}
	w.Header().Set("Content-Type", "application/json")
	if value.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(value.RetryAfter)))
	}
	w.WriteHeader(value.Status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"type": value.Type, "code": nullable(value.Code), "message": value.Message, "param": nullable(value.Param)}})
}
func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func retryAfterSeconds(duration time.Duration) int {
	return int((duration + time.Second - 1) / time.Second)
}
