package usage

import (
	"fmt"
	"time"
)

type Monthly struct {
	Limit     float64   `json:"limit"`
	Used      float64   `json:"used"`
	Remaining float64   `json:"remaining"`
	ResetAt   time.Time `json:"reset_at"`
}

type Weekly struct {
	UsedPercent      float64   `json:"used_percent"`
	RemainingPercent float64   `json:"remaining_percent"`
	ResetAt          time.Time `json:"reset_at"`
	OnDemand         *float64  `json:"on_demand,omitempty"`
	Prepaid          *float64  `json:"prepaid,omitempty"`
}

type Counters struct {
	Requests     int64 `json:"requests"`
	Failures     int64 `json:"failures"`
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}

type Delta Counters

type Snapshot struct {
	AccountID string    `json:"account_id"`
	Monthly   *Monthly  `json:"monthly"`
	Weekly    *Weekly   `json:"weekly"`
	Local     Counters  `json:"local"`
	FetchedAt time.Time `json:"fetched_at"`
	Stale     bool      `json:"stale"`
	Unknown   bool      `json:"unknown"`
	Error     string    `json:"error,omitempty"`
}

type RefreshStatus struct {
	AccountID   string
	LastSuccess time.Time
	LastAttempt time.Time
	LastError   string
	Refreshing  bool
	Stale       bool
}

type HTTPError struct {
	Status     int
	RetryAfter string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("xai billing returned HTTP %d", e.Status) }
