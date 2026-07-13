package web

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound lets service implementations distinguish a missing management
// resource from an operational failure without exposing storage details.
var ErrNotFound = errors.New("web management resource not found")

// Services are UI-facing projections over the management layer. Implementations
// must not place OAuth credentials, identity subjects, or raw billing payloads
// in any returned value.
type Services struct {
	Accounts  AccountService
	OAuth     OAuthService
	Usage     UsageService
	Models    ModelService
	APIKeys   APIKeyService
	Readiness ReadinessService
}

type ReadinessService interface {
	Ready(context.Context) (bool, error)
}

type AccountService interface {
	List(context.Context) ([]AccountSummary, error)
	Get(context.Context, string) (AccountDetail, error)
	Update(context.Context, string, AccountUpdate) error
	Delete(context.Context, string) error
	Refresh(context.Context, string) error
}

type AccountUpdate struct {
	Label   *string
	Enabled *bool
}

type AccountSummary struct {
	ID             string
	Label          string
	Enabled        bool
	Status         string
	ExpiresAt      *time.Time
	CooldownUntil  *time.Time
	ModelCount     int
	UsageFetchedAt *time.Time
	UsageStale     bool
	SanitizedError string
}

type AccountDetail struct {
	AccountSummary
	LastRefreshAt *time.Time
	Models        []AccountModel
	Cooldowns     []AccountCooldown
}

type AccountModel struct {
	Name                  string
	DisplayName           string
	Supported             bool
	SupportsBackendSearch *bool
	ContextWindow         int64
	MaxOutputTokens       int64
	ReasoningEfforts      []string
	DiscoveredAt          time.Time
	Stale                 bool
}

type AccountCooldown struct {
	Model          string
	Until          *time.Time
	BackoffLevel   int
	LastErrorClass string
	LastErrorAt    *time.Time
}

// OAuthService owns persisted device-flow state. Start must arrange exactly one
// polling/completion operation for a state, and Get must resume or observe that
// same operation so browser refreshes and concurrent tabs cannot duplicate an
// account record.
type OAuthService interface {
	Start(context.Context) (OAuthFlow, error)
	Get(context.Context, string) (OAuthFlow, error)
	Cancel(context.Context, string) error
}

type OAuthFlow struct {
	State            string
	Status           string
	UserCode         string
	VerificationURL  string
	ExpiresAt        time.Time
	PollAfter        time.Duration
	AccountID        string
	SanitizedMessage string
}

type UsageService interface {
	List(context.Context) ([]AccountUsage, error)
	Refresh(context.Context, string) error
}

type AccountUsage struct {
	AccountID       string
	AccountLabel    string
	Monthly         UsagePeriod
	Weekly          UsagePeriod
	Local           LocalUsage
	FetchedAt       *time.Time
	Stale           bool
	SanitizedStatus string
}

type UsagePeriod struct {
	Used    float64
	Limit   *float64
	Percent *float64
	Unit    string
}

type LocalUsage struct {
	Requests     uint64
	InputTokens  uint64
	OutputTokens uint64
}

type ModelService interface {
	List(context.Context) ([]ModelSupport, error)
	Refresh(context.Context, string) error
}

type ModelSupport struct {
	AccountID             string
	AccountLabel          string
	Name                  string
	DisplayName           string
	Supported             bool
	SupportsBackendSearch *bool
	Allowlisted           bool
	ContextWindow         int64
	MaxOutputTokens       int64
	DiscoveredAt          time.Time
	Stale                 bool
}

type APIKeyService interface {
	List(context.Context) ([]APIKey, error)
	Create(context.Context, string) (CreatedAPIKey, error)
	Revoke(context.Context, string) error
}

type APIKey struct {
	ID         string
	Prefix     string
	Label      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// CreatedAPIKey.Plaintext is a one-response value. List must never return it.
type CreatedAPIKey struct {
	Key       APIKey
	Plaintext string
}
