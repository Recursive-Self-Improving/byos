package routing

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	oauthxai "byoo/internal/oauth/xai"
	"byoo/internal/search"
	"byoo/internal/store"
	"byoo/internal/xai"
)

// ModelResolver resolves public model names and aliases to an upstream model.
type ModelResolver interface {
	Resolve(string) (string, error)
}

// ResolverFunc adapts a function to ModelResolver.
type ResolverFunc func(string) (string, error)

func (f ResolverFunc) Resolve(model string) (string, error) { return f(model) }

type executionClient interface {
	Execute(context.Context, string, string, []byte) ([]xai.Event, error)
	Stream(context.Context, string, string, []byte) (*xai.Stream, error)
}

type credentialRefresher interface {
	Refresh(context.Context, string) (store.Account, error)
}
type LocalUsageDelta struct{ Requests, Failures, InputTokens, OutputTokens int64 }
type UsageRecorder interface {
	Record(context.Context, string, LocalUsageDelta) error
}

// Executor coordinates account selection, credential refresh, cooldowns, and xAI execution.
type Executor struct {
	scheduler    *Scheduler
	client       executionClient
	refresher    credentialRefresher
	cooldowns    *CooldownManager
	accounts     *store.AccountRepository
	capabilities *store.ModelCapabilityRepository
	states       *store.CooldownRepository
	resolver     ModelResolver
	usage        UsageRecorder
	now          func() time.Time
}

func NewExecutor(
	scheduler *Scheduler,
	client *xai.Client,
	refresher *oauthxai.RefreshService,
	cooldowns *CooldownManager,
	accounts *store.AccountRepository,
	capabilities *store.ModelCapabilityRepository,
	states *store.CooldownRepository,
	resolver ModelResolver,
) *Executor {
	return newExecutor(scheduler, client, refresher, cooldowns, accounts, capabilities, states, resolver)
}

func newExecutor(
	scheduler *Scheduler,
	client executionClient,
	refresher credentialRefresher,
	cooldowns *CooldownManager,
	accounts *store.AccountRepository,
	capabilities *store.ModelCapabilityRepository,
	states *store.CooldownRepository,
	resolver ModelResolver,
) *Executor {
	if scheduler == nil {
		scheduler = NewScheduler()
	}
	return &Executor{
		scheduler: scheduler, client: client, refresher: refresher, cooldowns: cooldowns,
		accounts: accounts, capabilities: capabilities, states: states, resolver: resolver,
		now: func() time.Time { return time.Now().UTC() },
	}
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

func terminalUsage(event xai.Event) (LocalUsageDelta, bool) {
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
func completedUsage(events []xai.Event) LocalUsageDelta {
	for index := len(events) - 1; index >= 0; index-- {
		if delta, ok := terminalUsage(events[index]); ok {
			return delta
		}
	}
	return LocalUsageDelta{Requests: 1}
}

// Request is a canonical xAI Responses request plus optional response affinity.
type Request struct {
	Model              string
	Body               []byte
	PreferredAccountID string
}

// Result is a completed non-stream execution.
type Result struct {
	Model, AccountID string
	Events           []xai.Event
}

// ExecutionError preserves the sanitized routing classification without exposing upstream response bodies.
type ExecutionError struct {
	Classified ClassifiedError
}

func (e *ExecutionError) Error() string {
	if e.Classified.PublicMessage != "" {
		return e.Classified.PublicMessage
	}
	return "request execution failed"
}

func (e *Executor) Execute(ctx context.Context, request Request) (Result, error) {
	model, body, err := e.prepare(request)
	if err != nil {
		return Result{}, err
	}
	ordered, err := e.candidates(ctx, model, request.PreferredAccountID)
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
		account, classified, err := e.readyAccount(ctx, account)
		if err != nil {
			e.record(ctx, candidate.ID, LocalUsageDelta{Requests: 1, Failures: 1})
			classified, applyErr := e.applyFailure(ctx, candidate.ID, model, classified)
			if applyErr != nil {
				return Result{}, applyErr
			}
			last = &ExecutionError{Classified: classified}
			if classified.RetryNext {
				continue
			}
			return Result{}, last
		}
		events, err := e.client.Execute(ctx, account.Credentials.AccessToken, model, body)
		if err == nil {
			if err := e.cooldowns.Success(ctx, account.ID, model); err != nil {
				return Result{}, err
			}
			e.record(ctx, account.ID, completedUsage(events))
			return Result{Model: model, AccountID: account.ID, Events: events}, nil
		}
		classified = classifyExecutionError(err, e.now())
		if classified.RefreshSame {
			refreshed, refreshClass, refreshErr := e.refresh(ctx, account.ID)
			if refreshErr == nil {
				events, err = e.client.Execute(ctx, refreshed.Credentials.AccessToken, model, body)
				if err == nil {
					if err := e.cooldowns.Success(ctx, account.ID, model); err != nil {
						return Result{}, err
					}
					e.record(ctx, account.ID, completedUsage(events))
					return Result{Model: model, AccountID: account.ID, Events: events}, nil
				}
				classified = classifyExecutionError(err, e.now())
			} else {
				err, classified = refreshErr, refreshClass
			}
		}
		e.record(ctx, account.ID, LocalUsageDelta{Requests: 1, Failures: 1})
		classified, applyErr := e.applyFailure(ctx, account.ID, model, classified)
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

func (e *Executor) prepare(request Request) (string, []byte, error) {
	if e.resolver == nil {
		return "", nil, errors.New("model resolver is required")
	}
	model, err := e.resolver.Resolve(request.Model)
	if err != nil {
		return "", nil, err
	}
	if model == "" {
		return "", nil, errors.New("resolved model is empty")
	}
	if err := search.Validate(request.Body); err != nil {
		return "", nil, fmt.Errorf("x_search invariant: %w", err)
	}
	body := request.Body
	var canonical map[string]any
	if err := json.Unmarshal(body, &canonical); err != nil {
		return "", nil, err
	}
	canonical["model"] = model
	body, err = json.Marshal(canonical)
	if err != nil {
		return "", nil, fmt.Errorf("encode canonical request: %w", err)
	}
	return model, body, nil
}

func (e *Executor) candidates(ctx context.Context, model, preferred string) ([]Candidate, error) {
	accounts, err := e.accounts.List(ctx)
	if err != nil {
		return nil, err
	}
	now := e.now()
	candidates := make([]Candidate, 0, len(accounts))
	for _, account := range accounts {
		candidate := Candidate{ID: account.ID, Enabled: account.Enabled, Valid: account.Status == "ready" && oauthxai.CredentialsUsable(account, now), Capabilities: make(map[string]bool), CooldownUntil: make(map[string]time.Time)}
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
		for _, scope := range []string{model, "*"} {
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
	ordered, err := e.scheduler.Order(model, candidates, preferred, now)
	if errors.Is(err, ErrNoAvailableAccounts) {
		if classified, ok := allCoolingClassification(candidates, model, now); ok {
			return nil, &ExecutionError{Classified: classified}
		}
	}
	return ordered, err
}

func allCoolingClassification(candidates []Candidate, model string, now time.Time) (ClassifiedError, bool) {
	known := make([]Candidate, 0, len(candidates))
	unknown := make([]Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if !candidate.Enabled || !candidate.Valid {
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
		return ClassifiedError{}, false
	}
	var earliest time.Time
	for _, candidate := range eligible {
		availableAt := candidate.CooldownUntil[model]
		if global := candidate.CooldownUntil["*"]; global.After(availableAt) {
			availableAt = global
		}
		if !availableAt.After(now) {
			return ClassifiedError{}, false
		}
		if earliest.IsZero() || availableAt.Before(earliest) {
			earliest = availableAt
		}
	}
	return ClassifiedError{
		Class: ClassRateLimit, ExplicitRetryAfter: true, Cooldown: earliest.Sub(now), RetryAfter: earliest,
		PublicStatus: http.StatusTooManyRequests, PublicCode: "rate_limit_exceeded", PublicMessage: "all available accounts are rate limited",
	}, true
}

func (e *Executor) readyAccount(ctx context.Context, account store.Account) (store.Account, ClassifiedError, error) {
	if !oauthxai.NeedsRefresh(account, e.now()) {
		return account, ClassifiedError{}, nil
	}
	refreshed, classified, err := e.refresh(ctx, account.ID)
	return refreshed, classified, err
}

func (e *Executor) refresh(ctx context.Context, accountID string) (store.Account, ClassifiedError, error) {
	account, err := e.refresher.Refresh(ctx, accountID)
	if err == nil {
		return account, ClassifiedError{}, nil
	}
	var oauthErr *oauthxai.OAuthError
	if errors.As(err, &oauthErr) && oauthErr.Code == "invalid_grant" {
		classified := InvalidGrant(oauthErr.Description)
		return store.Account{}, classified, err
	}
	classified := Classify(0, nil, nil, err, nil, e.now())
	return store.Account{}, classified, err
}

func (e *Executor) applyFailure(ctx context.Context, accountID, model string, classified ClassifiedError) (ClassifiedError, error) {
	if err := e.cooldowns.Apply(ctx, accountID, model, classified); err != nil {
		return classified, err
	}
	scope := model
	if classified.AccountWide {
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

func classifyExecutionError(err error, now time.Time) ClassifiedError {
	var upstream *xai.UpstreamError
	if errors.As(err, &upstream) {
		return Classify(upstream.Status, upstream.Headers, []byte(upstream.Body), nil, nil, now)
	}
	var networkErr net.Error
	if !errors.Is(err, context.Canceled) && errors.As(err, &networkErr) {
		err = &ConnectionSetupError{Err: err}
	}
	return Classify(0, nil, nil, err, nil, now)
}
