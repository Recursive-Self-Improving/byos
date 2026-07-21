package app

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"time"

	"byos/internal/accounts"
	"byos/internal/models"
	oauthdevin "byos/internal/oauth/devin"
	"byos/internal/provider"
	"byos/internal/store"
	"byos/internal/usage"
	"byos/internal/web"
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

type webStaticModelCatalog interface {
	Models() []provider.ResolvedModel
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
	static    webStaticModelCatalog
	registry  provider.CapabilityRegistry
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
	account, err := a.accounts.Get(ctx, id)
	if err != nil {
		return err
	}
	capabilities := webRuntimeCapabilities(a.registry, account)
	if capabilities.CredentialRefresher == nil || account.Status == "relogin_required" {
		return web.ErrActionUnavailable
	}
	_, err = a.accounts.Refresh(ctx, id)
	return err
}

func (a *webAccountAdapter) project(ctx context.Context, account store.Account) (web.AccountDetail, error) {
	selected, ok := webProvider(account.Provider)
	if !ok {
		return web.AccountDetail{}, web.ErrActionUnavailable
	}
	capabilities := webRuntimeCapabilities(a.registry, account)
	modelViews, err := projectWebAccountModels(ctx, account, a.models, a.static, a.registry)
	if err != nil {
		return web.AccountDetail{}, err
	}
	modelNames := make([]string, 0, len(modelViews)+1)
	modelNames = append(modelNames, "*")
	for _, model := range modelViews {
		modelNames = append(modelNames, model.UpstreamName)
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
	quotaAvailable := capabilities.UsageFetcher != nil
	var fetchedAt *time.Time
	if quotaAvailable && !snapshot.FetchedAt.IsZero() {
		copy := snapshot.FetchedAt
		fetchedAt = &copy
	}
	needsRelogin := account.Status == "relogin_required"
	summary := web.AccountSummary{
		Provider:         selected,
		ID:               account.ID,
		Label:            account.Label,
		Enabled:          account.Enabled,
		Status:           account.Status,
		StatusLabel:      webAccountStatusLabel(account.Status),
		NeedsRelogin:     needsRelogin,
		CanRelogin:       capabilities.Lifecycle != nil,
		CanRefresh:       capabilities.CredentialRefresher != nil && !needsRelogin,
		CanRefreshModels: capabilities.ModelDiscoverer != nil,
		CanRefreshUsage:  quotaAvailable,
		ExpiresAt:        account.ExpiresAt,
		CooldownUntil:    latestCooldown,
		ModelCount:       len(modelViews),
		UsageFetchedAt:   fetchedAt,
		UsageStale:       quotaAvailable && (snapshot.Stale || snapshot.Unknown),
	}
	if account.LastError != "" {
		summary.SanitizedError = "Account refresh failed."
	}
	return web.AccountDetail{AccountSummary: summary, LastRefreshAt: account.LastRefreshAt, Models: modelViews, Cooldowns: cooldownViews}, nil
}

func webRuntimeCapabilities(registry provider.CapabilityRegistry, account store.Account) provider.Capabilities {
	if registry == nil {
		return provider.Capabilities{}
	}
	capabilities, _ := registry.Capabilities(account.Provider, string(account.Provider))
	return capabilities
}

func webProvider(kind provider.Kind) (web.Provider, bool) {
	switch kind {
	case provider.XAI:
		return web.ProviderXAI, true
	case provider.Devin:
		return web.ProviderDevin, true
	default:
		return "", false
	}
}

func webAccountStatusLabel(status string) string {
	switch status {
	case "ready":
		return "Ready"
	case "relogin_required":
		return "Reconnect required"
	case "":
		return "Unknown"
	default:
		return status
	}
}

func projectWebAccountModels(ctx context.Context, account store.Account, dynamic webCapabilityService, static webStaticModelCatalog, registry provider.CapabilityRegistry) ([]web.AccountModel, error) {
	selected, ok := webProvider(account.Provider)
	if !ok {
		return nil, web.ErrActionUnavailable
	}
	capabilities := webRuntimeCapabilities(registry, account)
	discoveryAvailable := capabilities.ModelDiscoverer != nil
	discovered := make(map[string]models.Capability)
	if discoveryAvailable && dynamic != nil {
		values, err := dynamic.Capabilities(ctx, account.ID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		for _, value := range values {
			discovered[value.ID] = value
		}
	}
	if static == nil {
		return nil, nil
	}
	resolved := static.Models()
	result := make([]web.AccountModel, 0, len(resolved))
	for _, model := range resolved {
		if model.Provider != account.Provider {
			continue
		}
		observed, known := discovered[model.UpstreamName]
		view := web.AccountModel{
			Provider:           selected,
			Name:               model.PublicName,
			UpstreamName:       model.UpstreamName,
			OwnedBy:            model.OwnedBy,
			Supported:          !discoveryAvailable,
			CapabilityKnown:    known,
			DiscoveryAvailable: discoveryAvailable,
		}
		if known {
			view.DisplayName = observed.DisplayName
			view.Supported = observed.Supported
			view.SupportsBackendSearch = observed.SupportsBackendSearch
			view.ContextWindow = observed.ContextWindow
			view.MaxOutputTokens = observed.MaxOutputTokens
			view.ReasoningEfforts = append([]string(nil), observed.ReasoningEfforts...)
			view.DiscoveredAt = observed.DiscoveredAt
			view.Stale = observed.Stale
		}
		result = append(result, view)
	}
	return result, nil
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
	registry  provider.CapabilityRegistry
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
		quotaAvailable := webRuntimeCapabilities(a.registry, account).UsageFetcher != nil
		result = append(result, projectWebUsage(account, snapshot, quotaAvailable))
	}
	return result, nil
}

func (a *webUsageAdapter) Refresh(ctx context.Context, id string) error {
	account, err := a.accounts.Get(ctx, id)
	if err != nil {
		return err
	}
	if webRuntimeCapabilities(a.registry, account).UsageFetcher == nil {
		return web.ErrActionUnavailable
	}
	return a.refresher.Refresh(ctx, id)
}

func projectWebUsage(account store.Account, snapshot usage.Snapshot, quotaAvailable bool) web.AccountUsage {
	selected, _ := webProvider(account.Provider)
	result := web.AccountUsage{
		Provider:       selected,
		AccountID:      account.ID,
		AccountLabel:   account.Label,
		QuotaAvailable: quotaAvailable,
		CanRefresh:     quotaAvailable,
		Local: web.LocalUsage{
			Requests:        nonnegativeCounter(snapshot.Local.Requests),
			InputTokens:     nonnegativeCounter(snapshot.Local.InputTokens),
			OutputTokens:    nonnegativeCounter(snapshot.Local.OutputTokens),
			CacheReadTokens: nonnegativeCounter(snapshot.Local.CacheReadTokens),
		},
	}
	if !quotaAvailable {
		result.SanitizedStatus = "Upstream quota is unavailable for this provider."
		return result
	}
	result.Stale = snapshot.Stale || snapshot.Unknown
	if snapshot.Monthly != nil {
		limit := snapshot.Monthly.Limit
		result.Monthly = web.UsagePeriod{Available: true, Used: snapshot.Monthly.Used, Limit: &limit, Unit: "credits"}
		if limit > 0 {
			percent := snapshot.Monthly.Used / limit * 100
			result.Monthly.Percent = &percent
		}
		if !snapshot.Monthly.ResetAt.IsZero() {
			resetAt := snapshot.Monthly.ResetAt
			result.Monthly.ResetAt = &resetAt
		}
	}
	if snapshot.Weekly != nil {
		limit := 100.0
		percent := snapshot.Weekly.UsedPercent
		result.Weekly = web.UsagePeriod{Available: true, Used: percent, Limit: &limit, Percent: &percent, Unit: "percent"}
		if !snapshot.Weekly.ResetAt.IsZero() {
			resetAt := snapshot.Weekly.ResetAt
			result.Weekly.ResetAt = &resetAt
		}
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
	static    webStaticModelCatalog
	registry  provider.CapabilityRegistry
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
		modelsForAccount, err := projectWebAccountModels(ctx, account, a.models, a.static, a.registry)
		if err != nil {
			return nil, err
		}
		for _, model := range modelsForAccount {
			resolved, allowlisted := a.models.Resolve(model.Name)
			result = append(result, web.ModelSupport{
				Provider:              model.Provider,
				OwnedBy:               model.OwnedBy,
				AccountID:             account.ID,
				AccountLabel:          account.Label,
				Name:                  model.Name,
				UpstreamName:          model.UpstreamName,
				DisplayName:           model.DisplayName,
				Supported:             model.Supported,
				CapabilityKnown:       model.CapabilityKnown,
				DiscoveryAvailable:    model.DiscoveryAvailable,
				SupportsBackendSearch: model.SupportsBackendSearch,
				Allowlisted:           allowlisted && resolved == model.UpstreamName,
				CanRefresh:            model.DiscoveryAvailable,
				ContextWindow:         model.ContextWindow,
				MaxOutputTokens:       model.MaxOutputTokens,
				DiscoveredAt:          model.DiscoveredAt,
				Stale:                 model.Stale,
			})
		}
	}
	return result, nil
}

func (a *webModelAdapter) Refresh(ctx context.Context, id string) error {
	account, err := a.accounts.Get(ctx, id)
	if err != nil {
		return err
	}
	if webRuntimeCapabilities(a.registry, account).ModelDiscoverer == nil {
		return web.ErrActionUnavailable
	}
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
	StartLogin(context.Context, provider.Kind) (provider.Authorization, error)
	LoginStatus(context.Context, provider.Kind, provider.SessionID) (provider.AuthorizationSession, error)
	CompleteLogin(context.Context, provider.Kind, provider.AuthorizationRef, provider.AuthorizationCompletion) (store.Account, error)
	CancelLogin(context.Context, provider.Kind, provider.SessionID) error
	ResumeLogins(context.Context, provider.Kind) ([]provider.AuthorizationSession, error)
}

type activeOAuthCompletion struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// cachedAuthorizationURL retains only the safe, necessary authorization URL a
// browser may re-request, paired with the session ExpiresAt so the cache can be
// evicted independently of any browser poll. Raw OAuth state is never stored
// outside the URL itself; the cache is in-memory only and never persisted or
// logged.
type cachedAuthorizationURL struct {
	url       string
	expiresAt time.Time
}

type webOAuthAdapter struct {
	ctx              context.Context
	accounts         webOAuthAccountManager
	devinCallbackURL string
	now              func() time.Time

	mu                sync.Mutex
	active            map[string]*activeOAuthCompletion
	authorizationURLs map[string]cachedAuthorizationURL
	closed            bool
	// sweepInterval bounds the independent expiry/completion sweeper. Zero
	// defaults to oauthURLSweepInterval in Run.
	sweepInterval time.Duration
}

const oauthURLSweepInterval = time.Minute

func newWebOAuthAdapter(ctx context.Context, accountService webOAuthAccountManager) *webOAuthAdapter {
	return &webOAuthAdapter{
		ctx: ctx, accounts: accountService,
		now:               func() time.Time { return time.Now().UTC() },
		active:            make(map[string]*activeOAuthCompletion),
		authorizationURLs: make(map[string]cachedAuthorizationURL),
		sweepInterval:     oauthURLSweepInterval,
	}
}

func (a *webOAuthAdapter) Start(ctx context.Context, selected web.Provider) (web.OAuthFlow, error) {
	kind, ok := webProviderKind(selected)
	if !ok {
		return web.OAuthFlow{}, web.ErrActionUnavailable
	}
	value, err := a.accounts.StartLogin(ctx, kind)
	if err != nil {
		return web.OAuthFlow{}, err
	}
	sessionID := value.SessionID.String()
	if sessionID == "" || value.Ref.Provider != kind || value.Ref.SessionID != value.SessionID {
		return web.OAuthFlow{}, web.ErrActionUnavailable
	}
	flow := projectWebOAuthFlow(selected, provider.AuthorizationSession{Authorization: value, Status: provider.AuthorizationPending}, a.now())
	if flow.AuthorizationURL != "" && !webOAuthFlowTerminal(flow.Status) {
		a.rememberAuthorizationURL(kind, sessionID, flow.AuthorizationURL, value.ExpiresAt)
	}
	if kind == provider.XAI {
		a.resume(kind, sessionID)
	}
	return flow, nil
}

func (a *webOAuthAdapter) Get(ctx context.Context, selected web.Provider, sessionID string) (web.OAuthFlow, error) {
	kind, ok := webProviderKind(selected)
	if !ok {
		return web.OAuthFlow{}, web.ErrNotFound
	}
	value, err := a.accounts.LoginStatus(ctx, kind, provider.SessionID(sessionID))
	if err != nil {
		return web.OAuthFlow{}, err
	}
	now := a.now()
	if kind == provider.XAI && (value.Status == provider.AuthorizationAuthorized || (value.Status == provider.AuthorizationPending && now.Before(value.ExpiresAt))) {
		a.resume(kind, sessionID)
	}
	flow := projectWebOAuthFlow(selected, value, now)
	if webOAuthFlowTerminal(flow.Status) {
		a.forgetAuthorizationURL(kind, sessionID)
	} else if flow.AuthorizationURL == "" {
		flow.AuthorizationURL = a.authorizationURL(kind, sessionID)
	}
	return flow, nil
}

func (a *webOAuthAdapter) Cancel(ctx context.Context, selected web.Provider, sessionID string) error {
	kind, ok := webProviderKind(selected)
	if !ok {
		return web.ErrNotFound
	}
	key := oauthCompletionKey(kind, sessionID)
	a.mu.Lock()
	active := a.active[key]
	delete(a.authorizationURLs, key)
	a.mu.Unlock()
	if active != nil {
		active.cancel()
	}
	return a.accounts.CancelLogin(ctx, kind, provider.SessionID(sessionID))
}

// CompleteDevinCallback consumes a browser-copied loopback callback without
// persisting or logging its raw URL. SessionID binds the callback state to the
// exact management flow displayed to the authenticated administrator.
func (a *webOAuthAdapter) CompleteDevinCallback(ctx context.Context, sessionID, callbackURL string) (string, error) {
	if a == nil || a.accounts == nil || strings.TrimSpace(sessionID) == "" {
		return "", web.ErrNotFound
	}
	state, code, err := oauthdevin.ParseCallbackURL(callbackURL, a.devinCallbackURL)
	if err != nil {
		return "", err
	}
	account, err := a.accounts.CompleteLogin(ctx, provider.Devin, provider.AuthorizationRef{
		Provider: provider.Devin, State: state, SessionID: provider.SessionID(sessionID),
	}, provider.AuthorizationCompletion{Code: code})
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(account.ID) == "" {
		return "", errors.New("Devin authorization completed without an account")
	}
	a.forgetAuthorizationURL(provider.Devin, sessionID)
	return account.ID, nil
}

func (a *webOAuthAdapter) Run(ctx context.Context) error {
	defer a.shutdown()
	values, err := a.accounts.ResumeLogins(ctx, provider.XAI)
	if err != nil && ctx.Err() == nil {
		return err
	}
	for _, value := range values {
		a.resume(provider.XAI, value.SessionID.String())
	}
	if _, err := a.accounts.ResumeLogins(ctx, provider.Devin); err != nil && ctx.Err() == nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	interval := a.sweepInterval
	if interval <= 0 {
		interval = oauthURLSweepInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			a.sweep(ctx)
		}
	}
}

func (a *webOAuthAdapter) shutdown() {
	a.mu.Lock()
	a.closed = true
	active := make([]*activeOAuthCompletion, 0, len(a.active))
	for _, completion := range a.active {
		active = append(active, completion)
	}
	a.active = nil
	a.authorizationURLs = nil
	a.mu.Unlock()
	for _, completion := range active {
		completion.cancel()
	}
	for _, completion := range active {
		<-completion.done
	}
}

func (a *webOAuthAdapter) Resume(sessionID string) {
	a.resume(provider.XAI, sessionID)
}

func (a *webOAuthAdapter) EnsureCompletion(sessionID string) {
	a.resume(provider.XAI, sessionID)
}

func (a *webOAuthAdapter) resume(kind provider.Kind, sessionID string) {
	if kind != provider.XAI || sessionID == "" {
		return
	}
	key := oauthCompletionKey(kind, sessionID)
	a.mu.Lock()
	if a.closed || a.active[key] != nil {
		a.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(a.ctx)
	completion := &activeOAuthCompletion{cancel: cancel, done: make(chan struct{})}
	a.active[key] = completion
	a.mu.Unlock()

	go func() {
		defer func() {
			cancel()
			a.mu.Lock()
			delete(a.active, key)
			delete(a.authorizationURLs, key)
			close(completion.done)
			a.mu.Unlock()
		}()
		ref := provider.AuthorizationRef{Provider: kind, SessionID: provider.SessionID(sessionID)}
		_, _ = a.accounts.CompleteLogin(ctx, kind, ref, provider.AuthorizationCompletion{})
	}()
}

func oauthCompletionKey(kind provider.Kind, sessionID string) string {
	return string(kind) + "\x00" + sessionID
}

func (a *webOAuthAdapter) rememberAuthorizationURL(kind provider.Kind, sessionID, value string, expiresAt time.Time) {
	a.mu.Lock()
	if !a.closed {
		if a.authorizationURLs == nil {
			a.authorizationURLs = make(map[string]cachedAuthorizationURL)
		}
		a.authorizationURLs[oauthCompletionKey(kind, sessionID)] = cachedAuthorizationURL{url: value, expiresAt: expiresAt}
	}
	a.mu.Unlock()
}

func (a *webOAuthAdapter) authorizationURL(kind provider.Kind, sessionID string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.authorizationURLs == nil {
		return ""
	}
	return a.authorizationURLs[oauthCompletionKey(kind, sessionID)].url
}

func (a *webOAuthAdapter) forgetAuthorizationURL(kind provider.Kind, sessionID string) {
	a.mu.Lock()
	delete(a.authorizationURLs, oauthCompletionKey(kind, sessionID))
	a.mu.Unlock()
}

// sweep is the independent expiry/completion sweeper invoked from Run's
// bounded ticker. It is the sole eviction authority when the browser never
// polls, and it clears cached URLs on exact callback completion without
// relying on Web Get/Cancel:
//
//   - Expired entries are evicted by their own ExpiresAt metadata, independent
//     of any provider lookup, so an abandoned flow whose lifecycle is gone
//     still frees its cache slot.
//   - Remaining entries are probed via LoginStatus; any terminal status
//     (completed/cancelled/denied/expired/failed) — including a Devin callback
//     completion that arrived out-of-band through the admin callback handler —
//     is cleared. xAI sessions that report authorized/consumed (or pending past
//     ExpiresAt) are proactively resumed so a no-poll completion does not
//     strand the URL until the next Get.
//
// The sweeper is bounded: one ticker, no per-session timers, and shutdown
// drains it via ctx cancellation. Raw OAuth state is never persisted or logged;
// only the safe URL and ExpiresAt are held in memory.
func (a *webOAuthAdapter) sweep(ctx context.Context) {
	now := a.now()
	var probes []sweepTarget
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	for key, cached := range a.authorizationURLs {
		if !cached.expiresAt.IsZero() && !now.Before(cached.expiresAt) {
			delete(a.authorizationURLs, key)
			continue
		}
		probes = append(probes, sweepTarget{key: key})
	}
	a.mu.Unlock()
	for _, target := range probes {
		if ctx.Err() != nil {
			return
		}
		kind, sessionID, ok := splitOAuthCompletionKey(target.key)
		if !ok {
			continue
		}
		value, err := a.accounts.LoginStatus(ctx, kind, provider.SessionID(sessionID))
		if err != nil {
			continue
		}
		if webOAuthFlowTerminal(string(value.Status)) {
			a.forgetAuthorizationURL(kind, sessionID)
			continue
		}
		if kind == provider.XAI && (value.Status == provider.AuthorizationAuthorized || value.Status == provider.AuthorizationConsumed || (value.Status == provider.AuthorizationPending && !a.now().Before(value.ExpiresAt))) {
			a.resume(kind, sessionID)
		}
	}
}

type sweepTarget struct{ key string }

func splitOAuthCompletionKey(key string) (provider.Kind, string, bool) {
	idx := strings.Index(key, "\x00")
	if idx <= 0 || idx == len(key)-1 {
		return "", "", false
	}
	return provider.Kind(key[:idx]), key[idx+1:], true
}

func webOAuthFlowTerminal(status string) bool {
	switch status {
	case "completed", "cancelled", "denied", "expired", "failed":
		return true
	default:
		return false
	}
}

func projectWebOAuthFlow(selected web.Provider, value provider.AuthorizationSession, now time.Time) web.OAuthFlow {
	status := string(value.Status)
	message := value.SanitizedMessage
	switch value.Status {
	case provider.AuthorizationAuthorized, provider.AuthorizationConsumed:
		status = "pending"
		if message == "" {
			message = "Authorization received. Finishing account setup."
		}
	case provider.AuthorizationPending:
		if !now.Before(value.ExpiresAt) {
			status = "expired"
			if message == "" {
				if selected == web.ProviderXAI {
					message = "The xAI device code expired. Start a new connection."
				} else {
					message = "Devin authorization expired. Start a new connection."
				}
			}
		}
	case provider.AuthorizationCompleted:
	case provider.AuthorizationCancelled:
		if message == "" {
			message = providerLabelForWeb(selected) + " authorization was cancelled."
		}
	case provider.AuthorizationExpired:
		if message == "" {
			if selected == web.ProviderXAI {
				message = "The xAI device code expired. Start a new connection."
			} else {
				message = "Devin authorization expired. Start a new connection."
			}
		}
	default:
		status = "failed"
		if message == "" {
			message = providerLabelForWeb(selected) + " authorization failed. Start a new connection."
		}
	}
	sessionID := value.SessionID.String()
	return web.OAuthFlow{
		Provider:         selected,
		SessionID:        sessionID,
		State:            oauthManagementRef(selected, sessionID),
		Status:           status,
		UserCode:         value.UserCode,
		AuthorizationURL: preferredAuthorizationURL(value.VerificationURLComplete, value.VerificationURL),
		ExpiresAt:        value.ExpiresAt,
		PollAfter:        value.PollInterval,
		AccountID:        value.AccountID,
		SanitizedMessage: message,
	}
}

func providerLabelForWeb(selected web.Provider) string {
	if selected == web.ProviderXAI {
		return "xAI"
	}
	return "Devin"
}

// webProviderKind maps a Web-layer Provider to the provider-neutral Kind. The
// boolean is false for an unknown provider so callers fail closed without
// exposing runtime registry details.
func webProviderKind(selected web.Provider) (provider.Kind, bool) {
	switch selected {
	case web.ProviderXAI:
		return provider.XAI, true
	case web.ProviderDevin:
		return provider.Devin, true
	}
	return "", false
}

// oauthManagementRef renders a provider-qualified safe management reference for
// the frozen server-rendered template actions. It mirrors web.oauthManagementRef
// but lives in the app package so the adapter does not depend on web internals.
func oauthManagementRef(selected web.Provider, sessionID string) string {
	return string(selected) + "/" + sessionID
}
func preferredAuthorizationURL(complete, fallback string) string {
	if complete != "" {
		return complete
	}
	return fallback
}
