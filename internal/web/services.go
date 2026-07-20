package web

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound lets service implementations distinguish a missing management
// resource from an operational failure without exposing storage details.
var ErrNotFound = errors.New("web management resource not found")

// ErrActionUnavailable reports a provider capability mismatch without exposing
// runtime registry details to the Web surface.
var ErrActionUnavailable = errors.New("web management action unavailable")

// Provider is the allowlisted provider identity rendered by the Web UI.
type Provider string

const (
	ProviderXAI   Provider = "xai"
	ProviderDevin Provider = "devin"
)

func (p Provider) Valid() bool { return p == ProviderXAI || p == ProviderDevin }

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
	Provider         Provider
	ID               string
	Label            string
	Enabled          bool
	Status           string
	StatusLabel      string
	NeedsRelogin     bool
	CanRelogin       bool
	CanRefresh       bool
	CanRefreshModels bool
	CanRefreshUsage  bool
	ExpiresAt        *time.Time
	CooldownUntil    *time.Time
	ModelCount       int
	UsageFetchedAt   *time.Time
	UsageStale       bool
	SanitizedError   string
}

type AccountDetail struct {
	AccountSummary
	LastRefreshAt *time.Time
	Models        []AccountModel
	Cooldowns     []AccountCooldown
}

type AccountModel struct {
	Provider              Provider
	Name                  string
	UpstreamName          string
	OwnedBy               string
	DisplayName           string
	Supported             bool
	CapabilityKnown       bool
	DiscoveryAvailable    bool
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

// OAuthService owns safe management handles for persisted provider login
// sessions. Session IDs are distinct from provider OAuth state; callers must
// bind every lookup and cancellation to the selected provider.
type OAuthService interface {
	Start(context.Context, Provider) (OAuthFlow, error)
	Get(context.Context, Provider, string) (OAuthFlow, error)
	Cancel(context.Context, Provider, string) error
}

type OAuthFlow struct {
	Provider  Provider
	SessionID string
	// State is a provider-qualified safe management reference retained for the
	// frozen server-rendered template actions. It is never provider OAuth state.
	State            string
	Status           string
	UserCode         string
	AuthorizationURL string
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
	Provider        Provider
	AccountID       string
	AccountLabel    string
	QuotaAvailable  bool
	CanRefresh      bool
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
	Provider              Provider
	OwnedBy               string
	AccountID             string
	AccountLabel          string
	Name                  string
	UpstreamName          string
	DisplayName           string
	Supported             bool
	CapabilityKnown       bool
	DiscoveryAvailable    bool
	SupportsBackendSearch *bool
	Allowlisted           bool
	CanRefresh            bool
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
