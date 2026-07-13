package models

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrCredential = errors.New("xai model catalog credential rejected")
	ErrSchema     = errors.New("unrecognized xai model catalog schema")
	ErrStaleState = errors.New("model catalog stale state was not persisted")
)

type Model struct {
	ID                    string   `json:"id"`
	DisplayName           string   `json:"display_name,omitempty"`
	ContextWindow         int64    `json:"context_window,omitempty"`
	MaxOutputTokens       int64    `json:"max_output_tokens,omitempty"`
	ReasoningEfforts      []string `json:"reasoning_efforts,omitempty"`
	SupportsBackendSearch *bool    `json:"supports_backend_search,omitempty"`
}

type Capability struct {
	Model
	Supported    bool      `json:"supported"`
	DiscoveredAt time.Time `json:"discovered_at"`
	Stale        bool      `json:"stale"`
}

type PublicModel struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	OwnedBy string `json:"owned_by"`
	AliasOf string `json:"alias_of,omitempty"`
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
	Status int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("xai model catalog returned HTTP %d", e.Status)
}
