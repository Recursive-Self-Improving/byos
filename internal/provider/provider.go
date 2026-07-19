// Package provider defines provider-neutral identity and runtime contracts.
package provider

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"time"
)

// Kind is a stable provider identifier persisted by BYOS.
type Kind string

const (
	XAI   Kind = "xai"
	Devin Kind = "devin"
)

var ErrInvalidKind = errors.New("invalid provider kind")

func ParseKind(value string) (Kind, error) {
	kind := Kind(value)
	if !kind.Valid() {
		return "", fmt.Errorf("%w: %q", ErrInvalidKind, value)
	}
	return kind, nil
}

func (k Kind) Valid() bool { return k == XAI || k == Devin }

func (k Kind) String() string { return string(k) }

func (k Kind) MarshalText() ([]byte, error) {
	if !k.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrInvalidKind, k)
	}
	return []byte(k), nil
}

func (k *Kind) UnmarshalText(text []byte) error {
	if k == nil {
		return errors.New("provider.Kind: UnmarshalText on nil pointer")
	}
	parsed, err := ParseKind(string(text))
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}

func (k Kind) Value() (driver.Value, error) {
	if !k.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrInvalidKind, k)
	}
	return string(k), nil
}

func (k *Kind) Scan(src any) error {
	if k == nil {
		return errors.New("provider.Kind: Scan on nil pointer")
	}
	var value string
	switch typed := src.(type) {
	case string:
		value = typed
	case []byte:
		value = string(typed)
	default:
		return fmt.Errorf("provider.Kind: cannot scan %T", src)
	}
	parsed, err := ParseKind(value)
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}

// ResolvedModel is immutable static model identity. It deliberately contains no
// runtime policy, client, credentials, or capability implementation.
type ResolvedModel struct {
	PublicName   string
	UpstreamName string
	Provider     Kind
	OwnedBy      string
	PolicyKey    string
}

// Event is one provider-neutral generation stream event. Data remains owned by
// the event and must stay valid and unchanged after later Stream.Next calls.
type Event struct {
	Event string
	Data  []byte
	Usage Usage
}

// Usage is token usage reported by a generation response.
type Usage struct {
	InputTokens     int64
	OutputTokens    int64
	TotalTokens     int64
	CacheReadTokens int64
}

// Stream exposes generation events. A successful Next commits a stream at the
// executor boundary; errors before that point remain eligible for failover.
type Stream interface {
	Next(context.Context) (Event, error)
	Close() error
}

// GenerationRequest remains canonical provider-neutral data. CanonicalBody
// already contains Model.UpstreamName; clients must not resolve or overwrite it.
// The selected GenerationClient alone converts it to provider wire format.
type GenerationRequest struct {
	Model         ResolvedModel
	CanonicalBody []byte
	Credential    Credential
}

// RequestPolicy applies provider-owned canonical request policy before the
// executor overwrites the public model with ResolvedModel.UpstreamName.
type RequestPolicy interface {
	Prepare(context.Context, ResolvedModel, []byte) ([]byte, error)
}

// GenerationClient is the sole provider-wire serialization boundary.
type GenerationClient interface {
	Execute(context.Context, GenerationRequest) ([]Event, error)
	Stream(context.Context, GenerationRequest) (Stream, error)
}

// Credential is opaque provider credential material returned for one account.
// Shared callers may carry it but must not interpret its value.
type Credential struct {
	Value string
}

// CredentialManager obtains usable credentials and performs provider-specific
// authentication recovery or relogin state changes. ErrorClassification is the
// sole authority for routing decisions; AuthenticationFailed only performs the
// requested credential lifecycle operation and returns no competing disposition.
type CredentialManager interface {
	Credential(context.Context, string) (Credential, error)
	AuthenticationFailed(context.Context, string, *UpstreamError) error
}

// DiscoveredModel is a provider discovery result. Discovery is an optional
// health overlay and does not establish static model ownership.
type DiscoveredModel struct {
	UpstreamName          string
	DisplayName           string
	SupportsBackendSearch *bool
	ContextWindow         int64
	MaxOutputTokens       int64
	ReasoningEfforts      []string
}

type ModelDiscoverer interface {
	Discover(context.Context, Credential) ([]DiscoveredModel, error)
}

// UsageSnapshot is optional provider account/quota usage. Per-response token
// usage is reported through Event.Usage instead.
type UsageSnapshot struct {
	FetchedAt time.Time
	Raw       []byte
}

type UsageFetcher interface {
	FetchUsage(context.Context, Credential) (UsageSnapshot, error)
}

type ErrorClass string

const (
	ClassValidation         ErrorClass = "validation"
	ClassUnauthorized       ErrorClass = "unauthorized"
	ClassInvalidGrant       ErrorClass = "invalid_grant"
	ClassPermission         ErrorClass = "permission"
	ClassFreeUsageExhausted ErrorClass = "free_usage_exhausted"
	ClassRateLimit          ErrorClass = "rate_limit"
	ClassTransient          ErrorClass = "transient"
	ClassConnection         ErrorClass = "connection"
	ClassCancelled          ErrorClass = "cancelled"
	ClassUpstream           ErrorClass = "upstream"
)

type CooldownScope string

const (
	CooldownNone    CooldownScope = ""
	CooldownModel   CooldownScope = "model"
	CooldownAccount CooldownScope = "account"
)

// ErrorClassification contains sanitized routing and public error metadata.
type ErrorClassification struct {
	Class              ErrorClass
	RetryNext          bool
	RefreshSame        bool
	DisableAccount     bool
	ReloginRequired    bool
	ExplicitRetryAfter bool
	CooldownScope      CooldownScope
	Cooldown           time.Duration
	RetryAfter         time.Time
	PublicStatus       int
	PublicCode         string
	PublicMessage      string
}

// UpstreamError contains no upstream body or credential-bearing headers.
type UpstreamError struct {
	Provider       Kind
	Status         int
	Classification ErrorClassification
}

func (e *UpstreamError) Error() string {
	if e == nil {
		return "provider upstream error"
	}
	return fmt.Sprintf("%s upstream returned HTTP %d", e.Provider, e.Status)
}

// Capabilities are runtime implementations only. Discoverer and UsageFetcher
// are optional and remain nil when unsupported.
type Capabilities struct {
	Policy          RequestPolicy
	Generation      GenerationClient
	Credentials     CredentialManager
	ModelDiscoverer ModelDiscoverer
	UsageFetcher    UsageFetcher
}

// ModelCatalog resolves immutable static model ownership.
type ModelCatalog interface {
	Resolve(string) (ResolvedModel, error)
}

// CapabilityRegistry resolves runtime behavior independently of model catalog
// construction and ownership.
type CapabilityRegistry interface {
	Capabilities(Kind, string) (Capabilities, bool)
}
