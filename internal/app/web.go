package app

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"

	"supergrok-api/internal/accounts"
	"supergrok-api/internal/models"
	oauthxai "supergrok-api/internal/oauth/xai"
	"supergrok-api/internal/store"
	"supergrok-api/internal/usage"
	"supergrok-api/internal/web"
)

type webAccountManager interface {
	List(context.Context) ([]store.Account, error)
	Get(context.Context, string) (store.Account, error)
	Update(context.Context, string, string, bool) error
	Delete(context.Context, string) error
	Refresh(context.Context, string) (store.Account, error)
}

type webCapabilityService interface {
	Capabilities(context.Context, string) ([]models.Capability, error)
	Resolve(string) (string, bool)
}

type webUsageReader interface {
	Latest(context.Context, string) (usage.Snapshot, error)
}

type webCooldownReader interface {
	Get(context.Context, string, string, time.Time) (store.Cooldown, error)
}

type webAccountAdapter struct {
	accounts  webAccountManager
	models    webCapabilityService
	usage     webUsageReader
	cooldowns webCooldownReader
	now       func() time.Time
}

func (a *webAccountAdapter) List(ctx context.Context) ([]web.AccountSummary, error) {
	values, err := a.accounts.List(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]web.AccountSummary, 0, len(values))
	for _, value := range values {
		detail, err := a.project(ctx, value)
		if err != nil {
			return nil, err
		}
		result = append(result, detail.AccountSummary)
	}
	return result, nil
}

func (a *webAccountAdapter) Get(ctx context.Context, id string) (web.AccountDetail, error) {
	value, err := a.accounts.Get(ctx, id)
	if err != nil {
		return web.AccountDetail{}, err
	}
	return a.project(ctx, value)
}

func (a *webAccountAdapter) Update(ctx context.Context, id string, update web.AccountUpdate) error {
	value, err := a.accounts.Get(ctx, id)
	if err != nil {
		return err
	}
	if update.Label != nil {
		value.Label = *update.Label
	}
	if update.Enabled != nil {
		value.Enabled = *update.Enabled
	}
	return a.accounts.Update(ctx, id, value.Label, value.Enabled)
}

func (a *webAccountAdapter) Delete(ctx context.Context, id string) error {
	return a.accounts.Delete(ctx, id)
}

func (a *webAccountAdapter) Refresh(ctx context.Context, id string) error {
	_, err := a.accounts.Refresh(ctx, id)
	return err
}

func (a *webAccountAdapter) project(ctx context.Context, account store.Account) (web.AccountDetail, error) {
	capabilities, err := a.models.Capabilities(ctx, account.ID)
	if err != nil {
		return web.AccountDetail{}, err
	}
	modelViews := make([]web.AccountModel, 0, len(capabilities))
	modelNames := make([]string, 0, len(capabilities)+1)
	modelNames = append(modelNames, "*")
	for _, capability := range capabilities {
		modelViews = append(modelViews, web.AccountModel{
			Name:                  capability.ID,
			DisplayName:           capability.DisplayName,
			Supported:             capability.Supported,
			SupportsBackendSearch: capability.SupportsBackendSearch,
			ContextWindow:         capability.ContextWindow,
			MaxOutputTokens:       capability.MaxOutputTokens,
			ReasoningEfforts:      append([]string(nil), capability.ReasoningEfforts...),
			DiscoveredAt:          capability.DiscoveredAt,
			Stale:                 capability.Stale,
		})
		modelNames = append(modelNames, capability.ID)
	}

	now := a.now()
	cooldownViews := make([]web.AccountCooldown, 0, len(modelNames))
	var latestCooldown *time.Time
	for _, model := range modelNames {
		value, err := a.cooldowns.Get(ctx, account.ID, model, now)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return web.AccountDetail{}, err
		}
		cooldownViews = append(cooldownViews, web.AccountCooldown{
			Model:          value.Model,
			Until:          value.Until,
			BackoffLevel:   value.BackoffLevel,
			LastErrorClass: safeErrorClass(value.LastErrorClass),
			LastErrorAt:    value.LastErrorAt,
		})
		if value.Until != nil && (latestCooldown == nil || value.Until.After(*latestCooldown)) {
			copy := *value.Until
			latestCooldown = &copy
		}
	}

	snapshot, err := a.usage.Latest(ctx, account.ID)
	if errors.Is(err, sql.ErrNoRows) {
		snapshot = usage.Snapshot{AccountID: account.ID, Unknown: true}
	} else if err != nil {
		return web.AccountDetail{}, err
	}
	var fetchedAt *time.Time
	if !snapshot.FetchedAt.IsZero() {
		copy := snapshot.FetchedAt
		fetchedAt = &copy
	}
	summary := web.AccountSummary{
		ID:             account.ID,
		Label:          account.Label,
		Enabled:        account.Enabled,
		Status:         account.Status,
		ExpiresAt:      account.ExpiresAt,
		CooldownUntil:  latestCooldown,
		ModelCount:     len(modelViews),
		UsageFetchedAt: fetchedAt,
		UsageStale:     snapshot.Stale || snapshot.Unknown,
	}
	if account.LastError != "" {
		summary.SanitizedError = "Account refresh failed."
	}
	return web.AccountDetail{AccountSummary: summary, LastRefreshAt: account.LastRefreshAt, Models: modelViews, Cooldowns: cooldownViews}, nil
}

func safeErrorClass(value string) string {
	switch value {
	case "validation", "unauthorized", "invalid_grant", "permission", "free_usage_exhausted", "rate_limit", "transient", "connection", "cancelled", "upstream":
		return value
	case "":
		return ""
	default:
		return "upstream"
	}
}

type webUsageAdapter struct {
	accounts  webAccountManager
	usage     webUsageReader
	refresher interface {
		Refresh(context.Context, string) error
	}
}

func (a *webUsageAdapter) List(ctx context.Context) ([]web.AccountUsage, error) {
	accountValues, err := a.accounts.List(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]web.AccountUsage, 0, len(accountValues))
	for _, account := range accountValues {
		snapshot, err := a.usage.Latest(ctx, account.ID)
		if errors.Is(err, sql.ErrNoRows) {
			snapshot = usage.Snapshot{AccountID: account.ID, Unknown: true}
		} else if err != nil {
			return nil, err
		}
		result = append(result, projectWebUsage(account, snapshot))
	}
	return result, nil
}

func (a *webUsageAdapter) Refresh(ctx context.Context, id string) error {
	return a.refresher.Refresh(ctx, id)
}

func projectWebUsage(account store.Account, snapshot usage.Snapshot) web.AccountUsage {
	result := web.AccountUsage{
		AccountID:    account.ID,
		AccountLabel: account.Label,
		Local: web.LocalUsage{
			Requests:     nonnegativeCounter(snapshot.Local.Requests),
			InputTokens:  nonnegativeCounter(snapshot.Local.InputTokens),
			OutputTokens: nonnegativeCounter(snapshot.Local.OutputTokens),
		},
		Stale: snapshot.Stale || snapshot.Unknown,
	}
	if snapshot.Monthly != nil {
		limit := snapshot.Monthly.Limit
		result.Monthly = web.UsagePeriod{Used: snapshot.Monthly.Used, Limit: &limit, Unit: "credits"}
		if limit > 0 {
			percent := snapshot.Monthly.Used / limit * 100
			result.Monthly.Percent = &percent
		}
	}
	if snapshot.Weekly != nil {
		limit := 100.0
		percent := snapshot.Weekly.UsedPercent
		result.Weekly = web.UsagePeriod{Used: percent, Limit: &limit, Percent: &percent, Unit: "percent"}
	}
	if !snapshot.FetchedAt.IsZero() {
		fetchedAt := snapshot.FetchedAt
		result.FetchedAt = &fetchedAt
	}
	switch {
	case snapshot.Unknown:
		result.SanitizedStatus = "Usage data is not available yet."
	case snapshot.Error != "" || snapshot.Stale:
		result.SanitizedStatus = "Usage data may be stale."
	}
	return result
}

func nonnegativeCounter(value int64) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value)
}

type webModelAdapter struct {
	accounts  webAccountManager
	models    webCapabilityService
	refresher interface {
		Refresh(context.Context, string) error
	}
}

func (a *webModelAdapter) List(ctx context.Context) ([]web.ModelSupport, error) {
	accountValues, err := a.accounts.List(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]web.ModelSupport, 0)
	for _, account := range accountValues {
		capabilities, err := a.models.Capabilities(ctx, account.ID)
		if err != nil {
			return nil, err
		}
		for _, capability := range capabilities {
			resolved, allowlisted := a.models.Resolve(capability.ID)
			result = append(result, web.ModelSupport{
				AccountID:             account.ID,
				AccountLabel:          account.Label,
				Name:                  capability.ID,
				DisplayName:           capability.DisplayName,
				Supported:             capability.Supported,
				SupportsBackendSearch: capability.SupportsBackendSearch,
				Allowlisted:           allowlisted && resolved == capability.ID,
				ContextWindow:         capability.ContextWindow,
				MaxOutputTokens:       capability.MaxOutputTokens,
				DiscoveredAt:          capability.DiscoveredAt,
				Stale:                 capability.Stale,
			})
		}
	}
	return result, nil
}

func (a *webModelAdapter) Refresh(ctx context.Context, id string) error {
	return a.refresher.Refresh(ctx, id)
}

type webAPIKeyAdapter struct {
	service interface {
		List(context.Context) ([]store.APIKey, error)
		Create(context.Context, string) (accounts.CreatedAPIKey, error)
		Revoke(context.Context, string) error
	}
}

func (a *webAPIKeyAdapter) List(ctx context.Context) ([]web.APIKey, error) {
	values, err := a.service.List(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]web.APIKey, 0, len(values))
	for _, value := range values {
		result = append(result, projectWebAPIKey(value))
	}
	return result, nil
}

func (a *webAPIKeyAdapter) Create(ctx context.Context, label string) (web.CreatedAPIKey, error) {
	created, err := a.service.Create(ctx, label)
	if err != nil {
		return web.CreatedAPIKey{}, err
	}
	return web.CreatedAPIKey{Key: projectWebAPIKey(created.Key), Plaintext: created.Plaintext}, nil
}

func (a *webAPIKeyAdapter) Revoke(ctx context.Context, id string) error {
	return a.service.Revoke(ctx, id)
}

func projectWebAPIKey(value store.APIKey) web.APIKey {
	return web.APIKey{ID: value.ID, Prefix: value.Prefix, Label: value.Label, CreatedAt: value.CreatedAt, LastUsedAt: value.LastUsedAt, RevokedAt: value.RevokedAt}
}

type webOAuthAccountManager interface {
	StartLogin(context.Context) (oauthxai.DeviceAuthorization, error)
	CompleteLogin(context.Context, string) (store.Account, error)
}

type webOAuthLifecycle interface {
	Session(context.Context, string) (store.OAuthSession, error)
	Resumable(context.Context) ([]store.OAuthSession, error)
	Cancel(context.Context, string) error
	Stop(string)
}

type activeOAuthCompletion struct {
	cancel context.CancelFunc
	done   chan struct{}
}

type webOAuthAdapter struct {
	ctx      context.Context
	accounts webOAuthAccountManager
	oauth    webOAuthLifecycle
	now      func() time.Time

	mu     sync.Mutex
	active map[string]*activeOAuthCompletion
	closed bool
}

func newWebOAuthAdapter(ctx context.Context, accountService webOAuthAccountManager, oauthService webOAuthLifecycle) *webOAuthAdapter {
	return &webOAuthAdapter{ctx: ctx, accounts: accountService, oauth: oauthService, now: func() time.Time { return time.Now().UTC() }, active: make(map[string]*activeOAuthCompletion)}
}

func (a *webOAuthAdapter) Start(ctx context.Context) (web.OAuthFlow, error) {
	value, err := a.accounts.StartLogin(ctx)
	if err != nil {
		return web.OAuthFlow{}, err
	}
	a.resume(value.State)
	return web.OAuthFlow{State: value.State, Status: "pending", UserCode: value.UserCode, VerificationURL: verificationURL(value.VerificationURIComplete, value.VerificationURI), ExpiresAt: value.ExpiresAt, PollAfter: value.PollInterval}, nil
}

func (a *webOAuthAdapter) Get(ctx context.Context, state string) (web.OAuthFlow, error) {
	value, err := a.oauth.Session(ctx, state)
	if err != nil {
		return web.OAuthFlow{}, err
	}
	if value.Status == "authorized" || (value.Status == "pending" && a.now().Before(value.ExpiresAt)) {
		a.resume(state)
	}
	return projectWebOAuthFlow(value, a.now()), nil
}
func (a *webOAuthAdapter) Status(ctx context.Context, state string) (store.OAuthSession, error) {
	if _, err := a.Get(ctx, state); err != nil {
		return store.OAuthSession{}, err
	}
	return a.oauth.Session(ctx, state)
}

func (a *webOAuthAdapter) Cancel(ctx context.Context, state string) error {
	a.mu.Lock()
	active := a.active[state]
	a.mu.Unlock()
	if active != nil {
		active.cancel()
	}
	return a.oauth.Cancel(ctx, state)
}

func (a *webOAuthAdapter) Run(ctx context.Context) error {
	values, err := a.oauth.Resumable(ctx)
	if err == nil {
		for _, value := range values {
			a.resume(value.State)
		}
	} else if ctx.Err() == nil {
		return err
	}
	if ctx.Err() == nil {
		<-ctx.Done()
	}

	a.mu.Lock()
	a.closed = true
	active := make(map[string]*activeOAuthCompletion, len(a.active))
	for state, completion := range a.active {
		active[state] = completion
	}
	a.mu.Unlock()
	for state, completion := range active {
		completion.cancel()
		a.oauth.Stop(state)
	}
	for _, completion := range active {
		<-completion.done
	}
	return ctx.Err()
}

func (a *webOAuthAdapter) resume(state string) {
	a.mu.Lock()
	if a.closed || a.active[state] != nil {
		a.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(a.ctx)
	completion := &activeOAuthCompletion{cancel: cancel, done: make(chan struct{})}
	a.active[state] = completion
	a.mu.Unlock()

	go func() {
		defer func() {
			cancel()
			a.mu.Lock()
			delete(a.active, state)
			close(completion.done)
			a.mu.Unlock()
		}()
		_, _ = a.accounts.CompleteLogin(ctx, state)
	}()
}

func projectWebOAuthFlow(value store.OAuthSession, now time.Time) web.OAuthFlow {
	status := value.Status
	message := ""
	switch status {
	case "authorized":
		status = "pending"
		message = "Authorization received. Finishing account setup."
	case "pending":
		if !now.Before(value.ExpiresAt) {
			status = "expired"
			message = "The device code expired. Start a new connection."
		}
	case "completed":
	case "cancelled":
		message = "Device authorization was cancelled."
	case "expired":
		message = "The device code expired. Start a new connection."
	default:
		status = "failed"
		message = "Device authorization failed. Start a new connection."
	}
	return web.OAuthFlow{
		State:            value.State,
		Status:           status,
		UserCode:         value.UserCode,
		VerificationURL:  verificationURL(value.VerificationURIComplete, value.VerificationURI),
		ExpiresAt:        value.ExpiresAt,
		PollAfter:        value.PollInterval,
		AccountID:        value.AccountID,
		SanitizedMessage: message,
	}
}

func verificationURL(complete, fallback string) string {
	if complete != "" {
		return complete
	}
	return fallback
}
