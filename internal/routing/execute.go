package routing

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"byos/internal/provider"
	"byos/internal/store"
)

type accountSource interface {
	List(context.Context) ([]store.Account, error)
	Get(context.Context, string) (store.Account, error)
}
type modelCapabilitySource interface {
	List(context.Context, string) ([]store.ModelCapability, error)
}
type cooldownSource interface {
	Get(context.Context, string, string, time.Time) (store.Cooldown, error)
}

type LocalUsageDelta struct{ Requests, Failures, InputTokens, OutputTokens int64 }
type UsageRecorder interface {
	Record(context.Context, string, LocalUsageDelta) error
}

type Executor struct {
	scheduler    *Scheduler
	catalog      provider.ModelCatalog
	registry     provider.CapabilityRegistry
	cooldowns    *CooldownManager
	accounts     accountSource
	capabilities modelCapabilitySource
	states       cooldownSource
	usage        UsageRecorder
	now          func() time.Time
}

func NewExecutor(scheduler *Scheduler, catalog provider.ModelCatalog, registry provider.CapabilityRegistry, cooldowns *CooldownManager, accounts *store.AccountRepository, capabilities *store.ModelCapabilityRepository, states *store.CooldownRepository) *Executor {
	return newExecutor(scheduler, catalog, registry, cooldowns, accounts, capabilities, states)
}

func newExecutor(scheduler *Scheduler, catalog provider.ModelCatalog, registry provider.CapabilityRegistry, cooldowns *CooldownManager, accounts accountSource, capabilities modelCapabilitySource, states cooldownSource) *Executor {
	if scheduler == nil {
		scheduler = NewScheduler()
	}
	return &Executor{scheduler: scheduler, catalog: catalog, registry: registry, cooldowns: cooldowns, accounts: accounts, capabilities: capabilities, states: states, now: func() time.Time { return time.Now().UTC() }}
}
func (e *Executor) SetUsageRecorder(recorder UsageRecorder) { e.usage = recorder }

func (e *Executor) record(ctx context.Context, accountID string, delta LocalUsageDelta) {
	if e.usage == nil {
		return
	}
	recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = e.usage.Record(recordCtx, accountID, delta)
}

func terminalUsage(event provider.Event) (LocalUsageDelta, bool) {
	if event.Usage != (provider.Usage{}) {
		return LocalUsageDelta{Requests: 1, InputTokens: event.Usage.InputTokens, OutputTokens: event.Usage.OutputTokens}, true
	}
	var raw struct {
		Type     string `json:"type"`
		Response struct {
			Usage struct {
				InputTokens  int64 `json:"input_tokens"`
				OutputTokens int64 `json:"output_tokens"`
			} `json:"usage"`
		} `json:"response"`
	}
	if json.Unmarshal(event.Data, &raw) != nil || (raw.Type != "response.completed" && raw.Type != "response.incomplete") {
		return LocalUsageDelta{}, false
	}
	return LocalUsageDelta{Requests: 1, InputTokens: raw.Response.Usage.InputTokens, OutputTokens: raw.Response.Usage.OutputTokens}, true
}
func completedUsage(events []provider.Event) LocalUsageDelta {
	for index := len(events) - 1; index >= 0; index-- {
		if delta, ok := terminalUsage(events[index]); ok {
			return delta
		}
	}
	return LocalUsageDelta{Requests: 1}
}

type Request struct {
	Model              string
	Body               []byte
	PreferredAccountID string
}
type Result struct {
	Model, AccountID string
	Events           []provider.Event
}
type ExecutionError struct{ Classified provider.ErrorClassification }

func (e *ExecutionError) Error() string {
	if e.Classified.PublicMessage != "" {
		return e.Classified.PublicMessage
	}
	return "request execution failed"
}

type executionPlan struct {
	model        provider.ResolvedModel
	capabilities provider.Capabilities
	canonical    provider.CanonicalRequest
}

func (e *Executor) Execute(ctx context.Context, request Request) (Result, error) {
	plan, err := e.prepare(ctx, request)
	if err != nil {
		return Result{}, err
	}
	ordered, err := e.candidates(ctx, plan.model, plan.capabilities.Credentials, request.PreferredAccountID)
	if err != nil {
		if errors.Is(err, ErrNoAvailableAccounts) {
			return Result{}, ErrModelUnavailable
		}
		return Result{}, err
	}
	var last error
	for _, candidate := range ordered {
		account, err := e.accounts.Get(ctx, candidate.ID)
		if err != nil {
			return Result{}, err
		}
		if account.Provider != plan.model.Provider {
			continue
		}
		credential, err := plan.capabilities.Credentials.Credential(ctx, account.ID)
		if err != nil {
			classified := classifyExecutionError(err)
			e.record(ctx, account.ID, LocalUsageDelta{Requests: 1, Failures: 1})
			classified, applyErr := e.applyFailure(ctx, account.ID, plan.model.UpstreamName, classified)
			if applyErr != nil {
				return Result{}, applyErr
			}
			last = &ExecutionError{Classified: classified}
			if classified.RetryNext {
				continue
			}
			return Result{}, last
		}
		events, err := plan.capabilities.Generation.Execute(ctx, provider.GenerationRequest{Model: plan.model, Canonical: plan.canonical, Credential: credential})
		if err == nil {
			if err := e.cooldowns.Success(ctx, account.ID, plan.model.UpstreamName); err != nil {
				return Result{}, err
			}
			e.record(ctx, account.ID, completedUsage(events))
			return Result{Model: plan.model.UpstreamName, AccountID: account.ID, Events: events}, nil
		}
		classified := classifyExecutionError(err)
		if classified.RefreshSame {
			credential, recoveryClassification, retrySame := recoverAuthentication(ctx, plan.capabilities.Credentials, account.ID, err, classified)
			classified = recoveryClassification
			if retrySame {
				events, err = plan.capabilities.Generation.Execute(ctx, provider.GenerationRequest{Model: plan.model, Canonical: plan.canonical, Credential: credential})
				if err == nil {
					if err := e.cooldowns.Success(ctx, account.ID, plan.model.UpstreamName); err != nil {
						return Result{}, err
					}
					e.record(ctx, account.ID, completedUsage(events))
					return Result{Model: plan.model.UpstreamName, AccountID: account.ID, Events: events}, nil
				}
				classified = classifyExecutionError(err)
			}
		}
		e.record(ctx, account.ID, LocalUsageDelta{Requests: 1, Failures: 1})
		classified, applyErr := e.applyFailure(ctx, account.ID, plan.model.UpstreamName, classified)
		if applyErr != nil {
			return Result{}, applyErr
		}
		last = &ExecutionError{Classified: classified}
		if !classified.RetryNext {
			return Result{}, last
		}
	}
	if last != nil {
		return Result{}, last
	}
	return Result{}, ErrNoAvailableAccounts
}

// recoverAuthentication performs exactly one provider-owned recovery. A typed,
// sanitized recovery error replaces the original 401 classification. Generic
// recovery failures preserve the original 401 disposition, and no failure path
// returns a credential that could resend the rejected token.
func recoverAuthentication(ctx context.Context, credentials provider.CredentialManager, accountID string, cause error, original provider.ErrorClassification) (provider.Credential, provider.ErrorClassification, bool) {
	var upstream *provider.UpstreamError
	if !errors.As(cause, &upstream) {
		return provider.Credential{}, original, false
	}
	if err := credentials.AuthenticationFailed(ctx, accountID, upstream); err != nil {
		if classified, ok := typedErrorClassification(err); ok {
			return provider.Credential{}, classified, false
		}
		return provider.Credential{}, original, false
	}
	credential, err := credentials.Credential(ctx, accountID)
	if err != nil {
		if classified, ok := typedErrorClassification(err); ok {
			return provider.Credential{}, classified, false
		}
		return provider.Credential{}, original, false
	}
	return credential, original, true
}

func typedErrorClassification(err error) (provider.ErrorClassification, bool) {
	var upstream *provider.UpstreamError
	if !errors.As(err, &upstream) {
		return provider.ErrorClassification{}, false
	}
	return upstream.Classification, true
}

func (e *Executor) prepare(ctx context.Context, request Request) (executionPlan, error) {
	if e.catalog == nil {
		return executionPlan{}, errors.New("model catalog is required")
	}
	resolved, err := e.catalog.Resolve(request.Model)
	if err != nil {
		if errors.Is(err, provider.ErrUnknownModel) {
			return executionPlan{}, ErrModelUnavailable
		}
		return executionPlan{}, err
	}
	if !resolved.Provider.Valid() || resolved.UpstreamName == "" || resolved.PolicyKey == "" {
		return executionPlan{}, errors.New("resolved model is incomplete")
	}
	if e.registry == nil {
		return executionPlan{}, ErrModelUnavailable
	}
	capabilities, ok := e.registry.Capabilities(resolved.Provider, resolved.PolicyKey)
	if !ok || capabilities.Policy == nil || capabilities.Generation == nil || capabilities.Credentials == nil {
		return executionPlan{}, ErrModelUnavailable
	}
	canonical, err := decodeCanonicalRequest(request.Body)
	if err != nil {
		return executionPlan{}, err
	}
	if err := capabilities.Policy.Prepare(ctx, resolved, canonical); err != nil {
		return executionPlan{}, err
	}
	canonical["model"] = resolved.UpstreamName
	return executionPlan{model: resolved, capabilities: capabilities, canonical: canonical}, nil
}

func decodeCanonicalRequest(body []byte) (provider.CanonicalRequest, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var canonical provider.CanonicalRequest
	if err := decoder.Decode(&canonical); err != nil {
		return nil, err
	}
	if canonical == nil {
		return nil, errors.New("canonical request must be a JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("canonical request must contain one JSON value")
		}
		return nil, err
	}
	return canonical, nil
}

func (e *Executor) candidates(ctx context.Context, resolved provider.ResolvedModel, credentials provider.CredentialManager, preferred string) ([]Candidate, error) {
	accounts, err := e.accounts.List(ctx)
	if err != nil {
		return nil, err
	}
	now := e.now()
	candidates := make([]Candidate, 0, len(accounts))
	usability, checkUsability := credentials.(provider.CredentialUsability)
	for _, account := range accounts {
		if account.Provider != resolved.Provider {
			continue
		}
		valid := account.Status == "ready"
		if valid && checkUsability {
			valid, err = usability.CredentialUsable(ctx, account.ID)
			if err != nil {
				return nil, err
			}
		}
		candidate := Candidate{ID: account.ID, Provider: account.Provider, Enabled: account.Enabled, Valid: valid, Capabilities: make(map[string]bool), CooldownUntil: make(map[string]time.Time)}
		capabilities, err := e.capabilities.List(ctx, account.ID)
		if err != nil {
			return nil, err
		}
		candidate.CapabilitiesKnown = len(capabilities) > 0
		for _, capability := range capabilities {
			if capability.Supported && (capability.SupportsBackendSearch == nil || *capability.SupportsBackendSearch) {
				candidate.Capabilities[capability.Model] = true
			}
		}
		for _, scope := range []string{resolved.UpstreamName, "*"} {
			state, err := e.states.Get(ctx, account.ID, scope, now)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return nil, err
			}
			if err == nil && state.Until != nil {
				candidate.CooldownUntil[scope] = *state.Until
			}
		}
		candidates = append(candidates, candidate)
	}
	ordered, err := e.scheduler.OrderForProvider(resolved.Provider, resolved.UpstreamName, candidates, preferred, now)
	if errors.Is(err, ErrNoAvailableAccounts) {
		if classified, ok := allCoolingClassification(candidates, resolved.Provider, resolved.UpstreamName, now); ok {
			return nil, &ExecutionError{Classified: classified}
		}
	}
	return ordered, err
}

func allCoolingClassification(candidates []Candidate, kind provider.Kind, model string, now time.Time) (provider.ErrorClassification, bool) {
	known, unknown := make([]Candidate, 0, len(candidates)), make([]Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Provider != kind || !candidate.Enabled || !candidate.Valid {
			continue
		}
		if candidate.CapabilitiesKnown {
			if candidate.Capabilities[model] {
				known = append(known, candidate)
			}
		} else {
			unknown = append(unknown, candidate)
		}
	}
	eligible := known
	if len(eligible) == 0 {
		eligible = unknown
	}
	if len(eligible) == 0 {
		return provider.ErrorClassification{}, false
	}
	var earliest time.Time
	for _, candidate := range eligible {
		availableAt := candidate.CooldownUntil[model]
		if global := candidate.CooldownUntil["*"]; global.After(availableAt) {
			availableAt = global
		}
		if !availableAt.After(now) {
			return provider.ErrorClassification{}, false
		}
		if earliest.IsZero() || availableAt.Before(earliest) {
			earliest = availableAt
		}
	}
	return provider.ErrorClassification{Class: provider.ClassRateLimit, ExplicitRetryAfter: true, CooldownScope: provider.CooldownModel, Cooldown: earliest.Sub(now), RetryAfter: earliest, PublicStatus: http.StatusTooManyRequests, PublicCode: "rate_limit_exceeded", PublicMessage: "all available accounts are rate limited"}, true
}

func (e *Executor) applyFailure(ctx context.Context, accountID, model string, classified provider.ErrorClassification) (provider.ErrorClassification, error) {
	if err := e.cooldowns.Apply(ctx, accountID, model, classified); err != nil {
		return classified, err
	}
	scope := model
	if classified.CooldownScope == provider.CooldownAccount {
		scope = "*"
	}
	now := e.now()
	state, err := e.states.Get(ctx, accountID, scope, now)
	if errors.Is(err, sql.ErrNoRows) {
		return classified, nil
	}
	if err != nil {
		return classified, err
	}
	if state.Until != nil && state.Until.After(now) {
		classified.RetryAfter = *state.Until
		classified.Cooldown = state.Until.Sub(now)
	}
	return classified, nil
}

func classifyExecutionError(err error) provider.ErrorClassification {
	var upstream *provider.UpstreamError
	if errors.As(err, &upstream) {
		return upstream.Classification
	}
	base := provider.ErrorClassification{Class: provider.ClassUpstream, PublicStatus: http.StatusBadGateway, PublicCode: "provider_error", PublicMessage: "upstream provider error"}
	if errors.Is(err, context.Canceled) {
		base.Class = provider.ClassCancelled
		base.PublicStatus = 499
		base.PublicCode = "request_cancelled"
		base.PublicMessage = "request cancelled"
		return base
	}
	var networkErr net.Error
	if errors.As(err, &networkErr) {
		base.Class = provider.ClassConnection
		base.RetryNext = true
		base.PublicStatus = http.StatusServiceUnavailable
		base.PublicCode = "provider_unavailable"
	}
	return base
}
