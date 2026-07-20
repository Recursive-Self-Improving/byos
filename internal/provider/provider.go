// Package provider defines provider-neutral identity and runtime contracts.
package provider

import (
	"context"
	"crypto/rand"
	"database/sql/driver"
	"encoding/base64"
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

// SessionID is a random opaque public handle for one authorization session. It
// is distinct from the raw OAuth state, which remains internal to the
// callback/PKCE protocol and is never exposed to admin, CLI, or Web callers.
// SessionID is persisted plaintext and indexed so status/cancel lookups by
// provider+SessionID never touch raw state. It is provider+flow-bound: a
// SessionID is only meaningful alongside its provider kind and flow type.
type SessionID string

const sessionIDBytes = 24

// NewSessionID generates a cryptographically random SessionID. The randomness
// is independent of the OAuth state and PKCE verifier so leaking a SessionID
// cannot recover raw state or replay a callback.
func NewSessionID() (SessionID, error) {
	var buf [sessionIDBytes]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("session id randomness: %w", err)
	}
	return SessionID(base64.RawURLEncoding.EncodeToString(buf[:])), nil
}

// String returns the SessionID as a string. It is safe to expose to callers.
func (s SessionID) String() string { return string(s) }

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

// CanonicalRequest is the provider-neutral structured generation request.
// Routing parses it once and owns model resolution; the selected client alone
// serializes it to provider wire bytes.
type CanonicalRequest map[string]any

type GenerationRequest struct {
	Model      ResolvedModel
	Canonical  CanonicalRequest
	Credential Credential
}

// RequestPolicy mutates provider-owned canonical request policy before the
// executor overwrites the public model with ResolvedModel.UpstreamName.
type RequestPolicy interface {
	Prepare(context.Context, ResolvedModel, CanonicalRequest) error
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

// CredentialUsability projects whether an account can yield a credential when
// selected, without returning credential material or performing a refresh.
// Routing may use this optional pre-scheduler check to exclude unusable
// accounts.
type CredentialUsability interface {
	CredentialUsable(context.Context, string) (bool, error)
}

// CredentialUsabilityRegistry resolves provider-bound CredentialUsability
// projections for maintenance workers that must observe credential usability
// without performing refresh or acquiring credential material. It is distinct
// from CapabilityRegistry so providers whose runtime registration is
// lifecycle-only (e.g. Devin until full generation composition) still project
// usability to the refresh worker without registering placeholder generation
// capabilities or violating CapabilityRegistry's all-or-none generation trio.
type CredentialUsabilityRegistry interface {
	CredentialUsability(Kind) (CredentialUsability, bool)
}

// CredentialRefresher exposes explicit provider-bound refresh operations without
// returning credential material or expiry metadata to shared callers.
type CredentialRefresher interface {
	NeedsRefresh(context.Context, string, time.Time) (bool, error)
	Refresh(context.Context, string) error
}

// CredentialManager obtains usable credentials and performs provider-specific
// authentication recovery or relogin state changes. ErrorClassification is the
// sole authority for routing decisions; AuthenticationFailed only performs the
// requested credential lifecycle operation and returns no competing disposition.
type CredentialManager interface {
	Credential(context.Context, string) (Credential, error)
	AuthenticationFailed(context.Context, string, *UpstreamError) error
}

var ErrProviderMismatch = errors.New("provider mismatch")

// ErrOAuthConflict is the stable conflict sentinel returned by lifecycle
// operations when an authorization session is known but is no longer
// cancellable because it has reached a terminal state (consumed, completed,
// failed, expired, or cancelled). It deliberately does not wrap sql.ErrNoRows
// so callers can distinguish a known-but-terminal session (409 Conflict) from
// a genuinely unknown or wrong-provider session (404 Not Found). Its message
// is sanitized and safe to surface.
var ErrOAuthConflict = errors.New("authorization is no longer cancellable")

// AuthorizationStatus is the normalized state of a provider authorization
// session. Providers may support only the states applicable to their flow.
type AuthorizationStatus string

const (
	AuthorizationPending    AuthorizationStatus = "pending"
	AuthorizationAuthorized AuthorizationStatus = "authorized"
	AuthorizationConsumed   AuthorizationStatus = "consumed"
	AuthorizationCompleted  AuthorizationStatus = "completed"
	AuthorizationFailed     AuthorizationStatus = "failed"
	AuthorizationExpired    AuthorizationStatus = "expired"
	AuthorizationCancelled  AuthorizationStatus = "cancelled"
)

// AuthorizationRef binds every lifecycle operation to a provider before an
// implementation reads persisted state or performs network I/O. State is the
// raw OAuth state used internally for callback/PKCE completion; SessionID is
// the public opaque handle for status/cancel lookups. At least one of State
// or SessionID must be set; callback completion uses State, while admin/CLI
// status and cancel use SessionID.
type AuthorizationRef struct {
	Provider  Kind
	State     string
	SessionID SessionID
}

// Authorization contains only values safe to return to a caller starting an
// authorization flow. Provider codes, tokens, PKCE verifiers, and verified
// identity claims must remain behind the lifecycle implementation. SessionID
// is the public handle callers use to poll or cancel the flow; Ref.State is
// the raw OAuth state retained only for callback completion.
type Authorization struct {
	Ref                     AuthorizationRef
	SessionID               SessionID
	UserCode                string
	VerificationURL         string
	VerificationURLComplete string
	ExpiresAt               time.Time
	PollInterval            time.Duration
}

// AuthorizationSession is the safe, normalized projection of a persisted
// authorization session. SanitizedMessage must never contain an upstream body,
// credential, identity claim, or storage detail.
type AuthorizationSession struct {
	Authorization
	Status           AuthorizationStatus
	AccountID        string
	SanitizedMessage string
}

// AuthorizationCompletion carries provider-specific callback input without
// exposing it through persisted authorization state or public results.
type AuthorizationCompletion struct {
	Code string
}

// AccountResult identifies the account produced by successful authorization.
// Account credentials and verified identity claims deliberately remain absent.
type AccountResult struct {
	Provider  Kind
	AccountID string
}

// AccountLifecycle is an optional provider-bound authorization capability.
// Implementations own protocol-specific state, secrets, and persistence.
type AccountLifecycle interface {
	Start(context.Context) (Authorization, error)
	Status(context.Context, AuthorizationRef) (AuthorizationSession, error)
	Complete(context.Context, AuthorizationRef, AuthorizationCompletion) (AccountResult, error)
	Cancel(context.Context, AuthorizationRef) error
	Resume(context.Context) ([]AuthorizationSession, error)
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
// usage is reported through Event.Usage instead. Monthly and Weekly are
// normalized provider-neutral windows; Raw is the bounded provider response
// retained for diagnostics and FetchedAt is the provider observation time.
type UsageSnapshot struct {
	Monthly   *MonthlyUsage
	Weekly    *WeeklyUsage
	FetchedAt time.Time
	Raw       []byte
}

type MonthlyUsage struct {
	Limit     float64
	Used      float64
	Remaining float64
	ResetAt   time.Time
}

type WeeklyUsage struct {
	UsedPercent      float64
	RemainingPercent float64
	ResetAt          time.Time
	OnDemand         *float64
	Prepaid          *float64
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

// Capabilities are runtime implementations only. CredentialRefresher,
// Lifecycle, ModelDiscoverer, and UsageFetcher are optional and remain nil when
// unsupported.
type Capabilities struct {
	Policy              RequestPolicy
	Generation          GenerationClient
	Credentials         CredentialManager
	CredentialRefresher CredentialRefresher
	Lifecycle           AccountLifecycle
	ModelDiscoverer     ModelDiscoverer
	UsageFetcher        UsageFetcher
}

// ModelCatalog resolves immutable static model ownership.
type ModelCatalog interface {
	Resolve(string) (ResolvedModel, error)
}

// CapabilityRegistry resolves generation-facing runtime behavior independently
// of model catalog construction and ownership.
type CapabilityRegistry interface {
	Capabilities(Kind, string) (Capabilities, bool)
}

// LifecycleRegistry resolves provider-bound account lifecycle behavior without
// requiring generation-only callers to implement or depend on that lookup.
type LifecycleRegistry interface {
	Lifecycle(Kind, string) (AccountLifecycle, bool)
}

// CredentialRefreshRegistry resolves explicit provider-bound credential
// refresh behavior without exposing credential material to shared callers.
type CredentialRefreshRegistry interface {
	CredentialRefresher(Kind, string) (CredentialRefresher, bool)
}
