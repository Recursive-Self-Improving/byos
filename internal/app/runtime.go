package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"byos/internal/accounts"
	"byos/internal/api"
	"byos/internal/api/admin"
	apianthropic "byos/internal/api/anthropic"
	apiopenai "byos/internal/api/openai"
	"byos/internal/auththrottle"
	"byos/internal/config"
	appcrypto "byos/internal/crypto"
	"byos/internal/devin"
	"byos/internal/models"
	oauthdevin "byos/internal/oauth/devin"
	oauthxai "byos/internal/oauth/xai"
	"byos/internal/provider"
	"byos/internal/requestsource"
	"byos/internal/routing"
	"byos/internal/sessions"
	"byos/internal/store"
	"byos/internal/translate"
	"byos/internal/translate/registry"
	"byos/internal/usage"
	"byos/internal/web"
	"byos/internal/xai"
)

type Runtime struct {
	Config                             config.Config
	Server                             *http.Server
	Store                              *store.SQLite
	Accounts                           *accounts.Service
	CallbackHandler                    http.Handler
	capabilityRegistry                 *provider.RuntimeCapabilityRegistry
	credentialUsabilityRegistry        *provider.RuntimeCredentialUsabilityRegistry
	modelWorker                        *models.Worker
	usageWorker                        *usage.Worker
	refreshWorker                      *accounts.RefreshWorker
	cleanupWorker                      *CleanupWorker
	webOAuth                           *webOAuthAdapter
	activity                           *api.ActivityTracker
	shutdownTimeout, forceDrainTimeout time.Duration
}

type lazyIdentity struct {
	discovery *oauthxai.DiscoveryClient
	clientID  string
	mu        sync.Mutex
	verifier  *oauthxai.IdentityVerifier
}

func (v *lazyIdentity) Verify(ctx context.Context, raw string) (oauthxai.Identity, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.verifier == nil {
		document, err := v.discovery.Discover(ctx)
		if err != nil {
			return oauthxai.Identity{}, err
		}
		v.verifier = oauthxai.NewIdentityVerifier(ctx, document.Issuer, document.JWKSURI, v.clientID, document.IDTokenSigningAlgs)
	}
	return v.verifier.Verify(ctx, raw)
}

type modelRefresh struct {
	repo   *store.AccountRepository
	worker *models.Worker
}

func (a modelRefresh) Refresh(ctx context.Context, id string) error {
	account, err := a.repo.Get(ctx, id)
	if err != nil {
		return err
	}
	return a.worker.RefreshAccount(ctx, models.Account{ID: account.ID, Provider: account.Provider, Enabled: account.Enabled})
}

type usageRefresh struct {
	repo   *store.AccountRepository
	worker *usage.Worker
}

func (a usageRefresh) Refresh(ctx context.Context, id string) error {
	account, err := a.repo.Get(ctx, id)
	if err != nil {
		return err
	}
	return a.worker.RefreshAccount(ctx, usage.Account{ID: account.ID, Provider: account.Provider, Enabled: account.Enabled})
}

type usageRecorder struct{ service *usage.Service }

func (r usageRecorder) Record(ctx context.Context, accountID string, delta routing.LocalUsageDelta) error {
	return r.service.Record(ctx, accountID, usage.Delta{Requests: delta.Requests, Failures: delta.Failures, InputTokens: delta.InputTokens, OutputTokens: delta.OutputTokens})
}

type publicCatalog struct {
	catalog         *models.Catalog
	models          []provider.ResolvedModel
	accounts        *store.AccountRepository
	cooldowns       *store.CooldownRepository
	now             func() time.Time
	defaultModel    string
	catalogResolver provider.ModelCatalog
	registry        provider.CapabilityRegistry
}

func newPublicCatalog(catalog *models.Catalog, static *provider.StaticModelCatalog, resolver provider.ModelCatalog, accounts *store.AccountRepository, cooldowns *store.CooldownRepository, now func() time.Time, defaultModel string, registry provider.CapabilityRegistry) publicCatalog {
	return publicCatalog{catalog: catalog, models: static.Models(), accounts: accounts, cooldowns: cooldowns, now: now, defaultModel: defaultModel, catalogResolver: resolver, registry: registry}
}

func (a publicCatalog) PublicModels(ctx context.Context) ([]apiopenai.Model, error) {
	accounts, err := a.accounts.List(ctx)
	if err != nil {
		return nil, err
	}
	now := a.now()
	result := make([]apiopenai.Model, 0, len(a.models))
	for _, resolved := range a.models {
		if !a.hasRuntimeCapabilities(resolved) {
			continue
		}
		routable, err := a.modelRoutable(ctx, accounts, resolved, now)
		if err != nil {
			return nil, err
		}
		if routable {
			result = append(result, apiopenai.Model{ID: resolved.PublicName, OwnedBy: resolved.OwnedBy})
		}
	}
	return result, nil
}

// hasRuntimeCapabilities reports whether the registry has the exact
// (Provider, PolicyKey) entry with the complete generation trio required to
// route the resolved model. A missing or incomplete capability suppresses
// public listing and readiness so a static model can never be advertised
// without exact runtime generation support.
func (a publicCatalog) hasRuntimeCapabilities(resolved provider.ResolvedModel) bool {
	if a.registry == nil {
		return false
	}
	capabilities, ok := a.registry.Capabilities(resolved.Provider, resolved.PolicyKey)
	if !ok {
		return false
	}
	return capabilities.Policy != nil && capabilities.Generation != nil && capabilities.Credentials != nil
}

// credentialUsability resolves the exact (Provider, PolicyKey) runtime
// capability and projects its Credentials as a CredentialUsability, mirroring
// Executor.candidates. A missing registry entry, nil Credentials, or a
// CredentialManager that does not implement CredentialUsability fails closed:
// the catalog cannot confirm an account can yield a credential, so no
// provider-matched account is admitted to listing or readiness. No
// provider-specific expiry logic lives here; the resolved CredentialManager
// is the sole authority for usability and relogin transitions.
func (a publicCatalog) credentialUsability(resolved provider.ResolvedModel) (provider.CredentialUsability, bool) {
	if a.registry == nil {
		return nil, false
	}
	capabilities, ok := a.registry.Capabilities(resolved.Provider, resolved.PolicyKey)
	if !ok || capabilities.Credentials == nil {
		return nil, false
	}
	usability, ok := capabilities.Credentials.(provider.CredentialUsability)
	if !ok {
		return nil, false
	}
	return usability, true
}

func (a publicCatalog) modelRoutable(ctx context.Context, accounts []store.Account, resolved provider.ResolvedModel, now time.Time) (bool, error) {
	usability, ok := a.credentialUsability(resolved)
	if !ok {
		return false, nil
	}
	for _, account := range accounts {
		if !account.Enabled || account.Status != "ready" || account.Provider != resolved.Provider {
			continue
		}
		usable, err := usability.CredentialUsable(ctx, account.ID)
		if err != nil {
			return false, err
		}
		if !usable {
			continue
		}
		supported, err := a.catalog.AccountSupports(ctx, account.ID, resolved)
		if err != nil {
			return false, err
		}
		if !supported {
			continue
		}
		cooling := false
		for _, scope := range [...]string{resolved.UpstreamName, "*"} {
			state, err := a.cooldowns.Get(ctx, account.ID, scope, now)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return false, err
			}
			if err == nil && state.Until != nil && state.Until.After(now) {
				cooling = true
				break
			}
		}
		if !cooling {
			return true, nil
		}
	}
	return false, nil
}

// validateStaticCatalogCapabilities cross-validates that every static catalog
// (Provider, PolicyKey) pair resolves to a RuntimeCapabilityRegistry entry with
// the complete generation trio (Policy, Generation, Credentials). A missing
// required capability fails startup. Optional capabilities (Lifecycle,
// ModelDiscoverer, UsageFetcher, CredentialRefresher) remain optional.
func validateStaticCatalogCapabilities(static *provider.StaticModelCatalog, registry *provider.RuntimeCapabilityRegistry) error {
	if static == nil {
		return fmt.Errorf("%w: static model catalog is required", provider.ErrInvalidCapabilities)
	}
	if registry == nil {
		return fmt.Errorf("%w: runtime capability registry is required", provider.ErrInvalidCapabilities)
	}
	seen := make(map[provider.Kind]map[string]struct{})
	for _, resolved := range static.Models() {
		if seen[resolved.Provider] == nil {
			seen[resolved.Provider] = make(map[string]struct{})
		}
		if _, ok := seen[resolved.Provider][resolved.PolicyKey]; ok {
			continue
		}
		seen[resolved.Provider][resolved.PolicyKey] = struct{}{}
		capabilities, ok := registry.Capabilities(resolved.Provider, resolved.PolicyKey)
		if !ok {
			return fmt.Errorf("%w: static model %q references unregistered capability (%s,%s)", provider.ErrInvalidCapabilities, resolved.PublicName, resolved.Provider, resolved.PolicyKey)
		}
		if capabilities.Policy == nil || capabilities.Generation == nil || capabilities.Credentials == nil {
			return fmt.Errorf("%w: static model %q capability (%s,%s) is missing the complete generation trio", provider.ErrInvalidCapabilities, resolved.PublicName, resolved.Provider, resolved.PolicyKey)
		}
	}
	return nil
}

func (a publicCatalog) Ready(ctx context.Context) (bool, error) {
	accounts, err := a.accounts.List(ctx)
	if err != nil {
		return false, err
	}
	now := a.now()
	resolved, err := a.catalogResolver.Resolve(a.defaultModel)
	if err != nil {
		return false, nil
	}
	if !a.hasRuntimeCapabilities(resolved) {
		return false, nil
	}
	return a.modelRoutable(ctx, accounts, resolved, now)
}

func deriveWebCSRFKey(sessionKey [32]byte) [32]byte {
	const label = "byos/web-csrf/v1\x00"
	var material [len(label) + 32]byte
	copy(material[:], label)
	copy(material[len(label):], sessionKey[:])
	return sha256.Sum256(material[:])
}

func New(ctx context.Context, cfg config.Config, secrets config.Secrets, logger *slog.Logger) (*Runtime, error) {
	if logger == nil {
		logger = slog.Default()
	}
	masterKey := secrets.MasterKey()
	keys, err := appcrypto.DeriveKeys(masterKey[:])
	if err != nil {
		return nil, err
	}
	database, err := store.Open(ctx, cfg.DataDir)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Runtime, error) { _ = database.Close(); return nil, err }
	accountRepo := store.NewAccountRepository(database.DB, keys)
	capabilityRepo := store.NewModelCapabilityRepository(database.DB)
	cooldownRepo := store.NewCooldownRepository(database.DB)
	oauthRepo := store.NewOAuthSessionRepository(database.DB, keys)
	responseRepo := store.NewResponseRepository(database.DB, keys)
	usageRepo := store.NewUsageRepository(database.DB, keys)
	localUsageRepo := store.NewLocalUsageRepository(database.DB)
	adminSessionRepo := store.NewAdminSessionRepository(database.DB, keys)
	adminThrottleRepo := store.NewAdminAuthThrottleRepository(database.DB)
	apiKeyService := accounts.NewAPIKeyService(store.NewAPIKeyRepository(database.DB))
	upstream := xai.NewClient(xai.HTTPConfig{BaseURL: cfg.Upstream.CLIProxyBaseURL, ClientVersion: cfg.Upstream.GrokClientVersion, UserAgent: "byos", RequestTimeout: cfg.Upstream.RequestTimeout.Duration(), SSEIdleTimeout: cfg.Upstream.SSEIdleTimeout.Duration()})
	modelClient := models.NewClient(upstream)
	modelProvider := models.NewXAIProvider(modelClient)
	catalog := models.NewCatalog(capabilityRepo, cfg.Models.Allowlist, cfg.Models.Aliases)
	staticCatalog, err := models.NewStaticCatalog(cfg.Models.Entries)
	if err != nil {
		return fail(err)
	}
	modelCatalog, err := models.NewStaticCatalogOverlay(staticCatalog, cfg.Models.Aliases)
	if err != nil {
		return fail(err)
	}
	usageProvider := usage.NewXAIProvider(usage.NewClient(upstream))
	usageService := usage.NewService(usageRepo, localUsageRepo)
	discovery := oauthxai.NewDiscoveryClient(nil, "")
	oauthOptions := oauthxai.Options{ClientID: cfg.OAuth.ClientID, Scopes: cfg.OAuth.Scopes}
	oauthService := oauthxai.NewService(discovery, nil, oauthRepo, oauthOptions)
	refreshService := oauthxai.NewRefreshService(nil, accountRepo, oauthOptions)
	identity := &lazyIdentity{discovery: discovery, clientID: oauthOptions.ClientID}
	cooldowns := routing.NewCooldownManager(cooldownRepo, accountRepo)
	credentialManager := oauthxai.NewProviderCredentialManager(accountRepo, refreshService)
	xaiLifecycle := oauthxai.NewProviderLifecycle(oauthService, accountRepo, identity)
	devinCredentialManager := oauthdevin.NewProviderCredentialManager(accountRepo)
	devinExchangeClient, err := oauthdevin.NewClient(oauthdevin.ClientConfig{
		Timeout:              cfg.Devin.Runtime.UnaryTimeout.Duration(),
		MaxCompressedBytes:   cfg.Devin.Runtime.MaxUnaryCompressedBytes,
		MaxDecompressedBytes: cfg.Devin.Runtime.MaxUnaryDecompressedBytes,
	})
	if err != nil {
		return fail(err)
	}
	devinGenerationClient, err := devin.NewClient(devin.ClientConfig{
		AllowedChatHosts:          append([]string(nil), cfg.Devin.Runtime.AllowedChatHosts...),
		UnaryTimeout:              cfg.Devin.Runtime.UnaryTimeout.Duration(),
		MaxCompressedBytes:        cfg.Devin.Runtime.MaxUnaryCompressedBytes,
		MaxDecompressedBytes:      cfg.Devin.Runtime.MaxUnaryDecompressedBytes,
		StreamIdleTimeout:         cfg.Devin.Runtime.StreamIdleTimeout.Duration(),
		StreamDeadline:            cfg.Devin.Runtime.StreamDeadline.Duration(),
		MaxFrameCompressedBytes:   cfg.Devin.Runtime.MaxFrameCompressedBytes,
		MaxFrameDecompressedBytes: cfg.Devin.Runtime.MaxFrameDecompressedBytes,
		MaxStreamBytes:            cfg.Devin.Runtime.MaxStreamBytes,
		MaxToolArgumentBytes:      cfg.Devin.Runtime.MaxToolArgumentBytes,
		MaxNonStreamBytes:         cfg.Devin.Runtime.MaxNonStreamBytes,
	})
	if err != nil {
		return fail(err)
	}
	devinLifecycle := oauthdevin.NewProviderLifecycle(oauthRepo, devinExchangeClient, store.NewDevinOAuthTransaction(database.DB, keys), oauthdevin.OAuthConfig{
		CallbackOrigin: cfg.Devin.OAuth.CallbackOrigin,
		CallbackPath:   cfg.Devin.OAuth.CallbackPath,
	})
	capabilityRegistry, err := provider.NewCapabilityRegistry([]provider.CapabilityRegistration{
		{
			Provider:  provider.XAI,
			PolicyKey: "xai",
			Capabilities: provider.Capabilities{
				Policy:              xai.RequestPolicy{},
				Generation:          xai.NewProviderClient(upstream),
				Credentials:         credentialManager,
				CredentialRefresher: credentialManager,
				Lifecycle:           xaiLifecycle,
				ModelDiscoverer:     modelProvider,
				UsageFetcher:        usageProvider,
			},
		},
		{
			Provider:  provider.Devin,
			PolicyKey: "devin",
			Capabilities: provider.Capabilities{
				Policy:      devin.RequestPolicy{},
				Generation:  devin.NewProviderClient(devinGenerationClient),
				Credentials: devinCredentialManager,
				Lifecycle:   devinLifecycle,
			},
		},
	})
	if err != nil {
		return fail(err)
	}
	if err := validateStaticCatalogCapabilities(staticCatalog, capabilityRegistry); err != nil {
		return fail(err)
	}
	// Purpose-specific credential usability registry for the refresh worker.
	// Devin now registers a complete generation trio in
	// RuntimeCapabilityRegistry, but the refresh worker observes credential
	// usability through this separate purpose-specific registry so maintenance
	// can project usability without depending on generation-facing capability
	// lookup. xAI refreshes explicitly and has no usability projection here.
	credentialUsabilityRegistry, err := provider.NewCredentialUsabilityRegistry([]provider.CredentialUsabilityRegistration{
		{Provider: provider.Devin, Usability: devinCredentialManager},
	})
	if err != nil {
		return fail(err)
	}
	modelWorker := models.NewWorker(models.NewStoreAccountProvider(accountRepo), capabilityRegistry, catalog, 15*time.Minute, cfg.Upstream.RequestTimeout.Duration(), 4)
	usageWorker := usage.NewWorker(usage.NewStoreAccountProvider(accountRepo), capabilityRegistry, usageService, cfg.Usage.RefreshInterval.Duration(), cfg.Upstream.RequestTimeout.Duration(), 4)
	modelRefresher := modelRefresh{accountRepo, modelWorker}
	usageRefresher := usageRefresh{accountRepo, usageWorker}
	accountService := accounts.NewService(accountRepo, capabilityRegistry, modelRefresher, usageRefresher)
	executor := routing.NewExecutor(routing.NewScheduler(), modelCatalog, capabilityRegistry, cooldowns, accountRepo, capabilityRepo, cooldownRepo)
	executor.SetUsageRecorder(usageRecorder{service: usageService})
	transforms := translate.NewRegistry()
	chatTransform, ok := transforms.Get(registry.OpenAIChat)
	if !ok {
		return fail(errors.New("OpenAI Chat translator is not registered"))
	}
	responsesTransform, ok := transforms.Get(registry.OpenAIResponses)
	if !ok {
		return fail(errors.New("OpenAI Responses translator is not registered"))
	}
	anthropicTransform, ok := transforms.Get(registry.Anthropic)
	if !ok {
		return fail(errors.New("Anthropic translator is not registered"))
	}
	sessionService := sessions.NewService(responseRepo)
	publicModels := newPublicCatalog(catalog, staticCatalog, modelCatalog, accountRepo, cooldownRepo, func() time.Time { return time.Now().UTC() }, cfg.Models.Default, capabilityRegistry)
	handlers := api.ServerHandlers{Health: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }), Ready: readyHandler(database.DB, publicModels), Models: apiopenai.ModelsHandler(publicModels), Chat: apiopenai.ChatHandler{Transform: chatTransform, Execute: executor.Execute, OpenStream: func(ctx context.Context, request routing.Request) (api.RoutedStream, error) {
		return executor.Stream(ctx, request)
	}}, Responses: apiopenai.ResponsesHandler{Transform: responsesTransform, Execute: executor.Execute, OpenStream: func(ctx context.Context, request routing.Request) (api.RoutedStream, error) {
		return executor.Stream(ctx, request)
	}, Sessions: sessionService}, Messages: apianthropic.MessagesHandler{Transform: anthropicTransform, Execute: executor.Execute, OpenStream: func(ctx context.Context, request routing.Request) (api.RoutedStream, error) {
		return executor.Stream(ctx, request)
	}}, CountTokens: http.HandlerFunc(apianthropic.CountTokensHandler)}
	webOAuth := newWebOAuthAdapter(ctx, accountService)
	handlers.Admin = admin.NewHandler(admin.Services{Accounts: accountService, Completion: webOAuth, Usage: usageService, UsageRefresh: usageWorker, Models: catalog, ModelsRefresh: modelWorker, Cooldowns: cooldownRepo, APIKeys: apiKeyService, Capabilities: capabilityRegistry})
	handlers.Callback = admin.CallbackHandler(accountService)
	webAccounts := &webAccountAdapter{accounts: accountService, models: catalog, static: staticCatalog, registry: capabilityRegistry, usage: usageService, cooldowns: cooldownRepo, now: func() time.Time { return time.Now().UTC() }}
	trustedProxies, err := requestsource.ParseTrustedProxies(cfg.Server.TrustedProxies)
	if err != nil {
		return fail(err)
	}
	adminAuthGuard, err := auththrottle.NewGuard(adminThrottleRepo, keys.AdminAuthSourceFingerprint, auththrottle.DefaultPolicy(), logger, nil)
	if err != nil {
		return fail(err)
	}
	webHandler, err := web.NewHandler(web.Options{
		AdminPassword: secrets.AdminPassword(),
		SessionStore:  adminSessionRepo,
		LoginAttempts: adminAuthGuard,
		CSRFKey:       deriveWebCSRFKey(keys.WebSession()),
		TrustedProxy:  trustedProxies,
		Services: web.Services{
			Accounts:  webAccounts,
			OAuth:     webOAuth,
			Usage:     &webUsageAdapter{accounts: accountService, usage: usageService, registry: capabilityRegistry, refresher: usageRefresher},
			Models:    &webModelAdapter{accounts: accountService, models: catalog, static: staticCatalog, registry: capabilityRegistry, refresher: modelRefresher},
			APIKeys:   &webAPIKeyAdapter{service: apiKeyService},
			Readiness: publicModels,
		},
	})
	if err != nil {
		return fail(err)
	}
	handlers.Web = webHandler
	callbackPath := strings.TrimSpace(cfg.Devin.OAuth.CallbackPath)
	if callbackPath != "" {
		if err := validateCallbackPath(callbackPath); err != nil {
			return fail(err)
		}
	}
	root := api.NewServer(api.ServerConfig{Handlers: handlers, ClientKeys: apiKeyService, AdminAPIKey: secrets.AdminAPIKey(), AdminAttempts: adminAuthGuard, AdminSources: trustedProxies, CallbackPath: callbackPath, MaxBodyBytes: cfg.Limits.MaxBodyBytes, Logger: logger})
	trackedRoot, activity := api.NewActivityTracker(root)
	runtime := &Runtime{Config: cfg, Store: database, Accounts: accountService, CallbackHandler: admin.CallbackHandler(accountService), capabilityRegistry: capabilityRegistry, credentialUsabilityRegistry: credentialUsabilityRegistry, modelWorker: modelWorker, usageWorker: usageWorker, refreshWorker: accounts.NewRefreshWorker(accountRepo, capabilityRegistry, credentialUsabilityRegistry, modelRefresher, usageRefresher), cleanupWorker: NewCleanupWorker(responseRepo, oauthRepo, adminSessionRepo, usageRepo, adminThrottleRepo, cooldownRepo, 30*24*time.Hour, auththrottle.DefaultPolicy().SourceRetention), webOAuth: webOAuth, activity: activity, shutdownTimeout: 15 * time.Second, forceDrainTimeout: 5 * time.Second}
	runtime.Server = &http.Server{Addr: cfg.Server.Listen, Handler: trackedRoot, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	return runtime, nil
}

func readyHandler(database *sql.DB, readiness web.ReadinessService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := database.PingContext(r.Context()); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		ready, err := readiness.Ready(r.Context())
		if err != nil || !ready {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}
func (r *Runtime) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", r.Server.Addr)
	if err != nil {
		return errors.Join(err, r.Close())
	}
	if ctx.Err() != nil {
		_ = listener.Close()
		return errors.Join(ctx.Err(), r.Close())
	}
	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() error { return ignoreCancellation(r.modelWorker.Run(ctx)) })
	group.Go(func() error { return ignoreCancellation(r.usageWorker.Run(ctx)) })
	group.Go(func() error { return ignoreCancellation(r.refreshWorker.Run(ctx)) })
	group.Go(func() error { return ignoreCancellation(r.webOAuth.Run(ctx)) })
	group.Go(func() error { return ignoreCancellation(r.cleanupWorker.Run(ctx)) })
	group.Go(func() error {
		err := r.Server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	})
	group.Go(func() error {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), r.shutdownTimeout)
		err := r.Server.Shutdown(shutdownCtx)
		cancel()
		if err != nil {
			err = errors.Join(err, r.Server.Close())
		}
		drainCtx, drainCancel := context.WithTimeout(context.Background(), r.forceDrainTimeout)
		defer drainCancel()
		return errors.Join(err, r.activity.Wait(drainCtx))
	})
	err = group.Wait()
	if r.activity.Active() != 0 {
		return errors.Join(err, errors.New("active HTTP handlers did not drain; database left open"))
	}
	return errors.Join(err, r.Close())
}
func (r *Runtime) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return errors.Join(r.Store.Checkpoint(ctx), r.Store.Close())
}

func ignoreCancellation(err error) error {
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// validateCallbackPath rejects a configured Devin callback path that would
// collide with or shadow the health, readiness, public API, or Web subtrees,
// or that contains Go 1.22 ServeMux metacharacters ({, }, $) which would
// broaden the unauthenticated exception into a wildcard. The exact-callback
// dispatcher matches a literal GET+path, so the callback may live under
// /admin/api/v1/ as long as it does not equal a registered admin route. The
// /admin/ Web subtree is reserved separately so the callback cannot shadow it.
func validateCallbackPath(callbackPath string) error {
	if callbackPath == "" {
		return nil
	}
	if !strings.HasPrefix(callbackPath, "/") {
		return fmt.Errorf("Devin callback path must start with '/': %q", callbackPath)
	}
	if strings.HasSuffix(callbackPath, "/") {
		return fmt.Errorf("Devin callback path must not end with '/' (would match a subtree): %q", callbackPath)
	}
	if strings.ContainsAny(callbackPath, "{}$") {
		return fmt.Errorf("Devin callback path must not contain ServeMux metacharacters: %q", callbackPath)
	}
	// Reserved exact routes and subtrees the callback must not equal or shadow.
	// /admin/ (the Web subtree) is reserved as an exact match, but
	// /admin/api/v1/ is allowed because the callback is an exact-match
	// exception within the admin API subtree, secured by AdminAuth for every
	// non-callback path. The outer dispatcher matches a literal GET+path, so a
	// callback under /admin/api/v1/ cannot shadow the Web subtree or bypass
	// admin auth for any neighboring route.
	for _, reserved := range []string{"/healthz", "/readyz", "/v1/models", "/v1/chat/completions", "/v1/responses", "/v1/messages", "/v1/messages/count_tokens", "/admin/"} {
		if callbackPath == reserved {
			return fmt.Errorf("Devin callback path %q collides with a reserved route", callbackPath)
		}
	}
	for _, subtree := range []string{"/healthz/", "/readyz/", "/v1/"} {
		if callbackPath == subtree || strings.HasPrefix(callbackPath, subtree) {
			return fmt.Errorf("Devin callback path %q collides with a reserved subtree", callbackPath)
		}
	}
	// Reject collisions with registered admin API routes. Fixed routes are
	// compared exactly. Dynamic routes (containing {param}) are converted to
	// a prefix so a concrete callback path that would match the pattern — e.g.
	// /admin/api/v1/oauth/devin/status/abc hijacking the status route — is
	// rejected, not just the literal pattern string.
	adminRoutes := []string{
		"/admin/api/v1/oauth/xai/device",
		"/admin/api/v1/oauth/xai/device/{state}",
		"/admin/api/v1/oauth/devin/start",
		"/admin/api/v1/oauth/devin/status/{session}",
		"/admin/api/v1/oauth/devin/cancel/{session}",
		"/admin/api/v1/accounts",
		"/admin/api/v1/accounts/{id}",
		"/admin/api/v1/accounts/{id}/refresh",
		"/admin/api/v1/accounts/{id}/usage",
		"/admin/api/v1/accounts/{id}/usage/refresh",
		"/admin/api/v1/models",
		"/admin/api/v1/models/refresh",
		"/admin/api/v1/usage",
		"/admin/api/v1/api-keys",
		"/admin/api/v1/api-keys/{id}",
	}
	for _, route := range adminRoutes {
		if callbackPath == route {
			return fmt.Errorf("Devin callback path %q collides with an admin route", callbackPath)
		}
		if idx := strings.Index(route, "{"); idx > 0 {
			prefix := route[:idx]
			if strings.HasPrefix(callbackPath, prefix) {
				return fmt.Errorf("Devin callback path %q collides with a dynamic admin route %q", callbackPath, route)
			}
		}
	}
	return nil
}
