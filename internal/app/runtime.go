package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
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
	"byos/internal/models"
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
	return a.worker.RefreshAccount(ctx, models.Account{ID: account.ID, AccessToken: account.Credentials.AccessToken, Enabled: account.Enabled})
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
	return a.worker.RefreshAccount(ctx, usage.Account{ID: account.ID, AccessToken: account.Credentials.AccessToken, Enabled: account.Enabled})
}

type usageRecorder struct{ service *usage.Service }

func (r usageRecorder) Record(ctx context.Context, accountID string, delta routing.LocalUsageDelta) error {
	return r.service.Record(ctx, accountID, usage.Delta{Requests: delta.Requests, Failures: delta.Failures, InputTokens: delta.InputTokens, OutputTokens: delta.OutputTokens})
}

type publicCatalog struct {
	catalog      *models.Catalog
	models       []provider.ResolvedModel
	accounts     *store.AccountRepository
	cooldowns    *store.CooldownRepository
	now          func() time.Time
	defaultModel string
	resolver     routing.ModelResolver
	xaiModels    map[string]provider.ResolvedModel
}

func newPublicCatalog(catalog *models.Catalog, static *provider.StaticModelCatalog, accounts *store.AccountRepository, cooldowns *store.CooldownRepository, now func() time.Time, defaultModel string, resolver routing.ModelResolver) publicCatalog {
	models := static.Models()
	xaiModels := make(map[string]provider.ResolvedModel)
	for _, resolved := range models {
		if resolved.Provider == provider.XAI {
			xaiModels[resolved.UpstreamName] = resolved
		}
	}
	return publicCatalog{catalog: catalog, models: models, accounts: accounts, cooldowns: cooldowns, now: now, defaultModel: defaultModel, resolver: resolver, xaiModels: xaiModels}
}

func (a publicCatalog) PublicModels(ctx context.Context) ([]apiopenai.Model, error) {
	accounts, err := a.accounts.List(ctx)
	if err != nil {
		return nil, err
	}
	now := a.now()
	result := make([]apiopenai.Model, 0, len(a.models))
	for _, resolved := range a.models {
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

func (a publicCatalog) modelRoutable(ctx context.Context, accounts []store.Account, resolved provider.ResolvedModel, now time.Time) (bool, error) {
	for _, account := range accounts {
		if !account.Enabled || account.Status != "ready" || account.Provider != resolved.Provider || !accountCredentialsUsable(account, now) {
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

func accountCredentialsUsable(account store.Account, now time.Time) bool {
	switch account.Provider {
	case provider.XAI:
		return oauthxai.CredentialsUsable(account, now)
	case provider.Devin:
		if strings.TrimSpace(account.Credentials.OpaqueToken) == "" {
			return false
		}
		return account.Credentials.OpaqueTokenExpiresAt == nil || account.Credentials.OpaqueTokenExpiresAt.After(now)
	default:
		return false
	}
}

func (a publicCatalog) Ready(ctx context.Context) (bool, error) {
	accounts, err := a.accounts.List(ctx)
	if err != nil {
		return false, err
	}
	now := a.now()
	upstream, err := a.resolver.Resolve(a.defaultModel)
	if err != nil {
		return false, nil
	}
	resolved, ok := a.xaiModels[upstream]
	if !ok {
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

func legacyXAIModelResolver(static *provider.StaticModelCatalog, catalog *models.Catalog) routing.ModelResolver {
	xaiUpstreams := make(map[string]struct{})
	for _, identity := range static.Models() {
		if identity.Provider == provider.XAI {
			xaiUpstreams[identity.UpstreamName] = struct{}{}
		}
	}
	return routing.ResolverFunc(func(value string) (string, error) {
		resolved, ok := catalog.Resolve(value)
		if !ok {
			return "", routing.ErrModelUnavailable
		}
		if _, ok := xaiUpstreams[resolved]; !ok {
			return "", routing.ErrModelUnavailable
		}
		return resolved, nil
	})
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
	catalog := models.NewCatalog(capabilityRepo, models.NewUpstream(upstream), cfg.Models.Allowlist, cfg.Models.Aliases)
	staticCatalog, err := models.NewStaticCatalog(cfg.Models.Entries)
	if err != nil {
		return fail(err)
	}
	modelWorker := models.NewWorker(models.NewStoreAccountProvider(accountRepo), catalog, 15*time.Minute, cfg.Upstream.RequestTimeout.Duration(), 4)
	usageService := usage.NewService(usage.NewBillingAdapter(upstream), usageRepo, localUsageRepo)
	usageWorker := usage.NewWorker(usage.NewStoreAccountProvider(accountRepo), usageService, cfg.Usage.RefreshInterval.Duration(), cfg.Upstream.RequestTimeout.Duration(), 4)
	discovery := oauthxai.NewDiscoveryClient(nil, "")
	oauthOptions := oauthxai.Options{ClientID: cfg.OAuth.ClientID, Scopes: cfg.OAuth.Scopes}
	oauthService := oauthxai.NewService(discovery, nil, oauthRepo, oauthOptions)
	refreshService := oauthxai.NewRefreshService(nil, accountRepo, oauthOptions)
	identity := &lazyIdentity{discovery: discovery, clientID: oauthOptions.ClientID}
	modelRefresher := modelRefresh{accountRepo, modelWorker}
	usageRefresher := usageRefresh{accountRepo, usageWorker}
	accountService := accounts.NewService(accountRepo, oauthService, identity, refreshService, modelRefresher, usageRefresher)
	cooldowns := routing.NewCooldownManager(cooldownRepo, accountRepo)
	resolver := legacyXAIModelResolver(staticCatalog, catalog)
	executor := routing.NewExecutor(routing.NewScheduler(), upstream, refreshService, cooldowns, accountRepo, capabilityRepo, cooldownRepo, resolver)
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
	publicModels := newPublicCatalog(catalog, staticCatalog, accountRepo, cooldownRepo, func() time.Time { return time.Now().UTC() }, cfg.Models.Default, resolver)
	handlers := api.ServerHandlers{Health: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }), Ready: readyHandler(database.DB, publicModels), Models: apiopenai.ModelsHandler(publicModels), Chat: apiopenai.ChatHandler{Transform: chatTransform, Execute: executor.Execute, OpenStream: func(ctx context.Context, request routing.Request) (api.RoutedStream, error) {
		return executor.Stream(ctx, request)
	}}, Responses: apiopenai.ResponsesHandler{Transform: responsesTransform, Execute: executor.Execute, OpenStream: func(ctx context.Context, request routing.Request) (api.RoutedStream, error) {
		return executor.Stream(ctx, request)
	}, Sessions: sessionService}, Messages: apianthropic.MessagesHandler{Transform: anthropicTransform, Execute: executor.Execute, OpenStream: func(ctx context.Context, request routing.Request) (api.RoutedStream, error) {
		return executor.Stream(ctx, request)
	}}, CountTokens: http.HandlerFunc(apianthropic.CountTokensHandler)}
	webOAuth := newWebOAuthAdapter(ctx, accountService, oauthService)
	handlers.Admin = admin.NewHandler(admin.Services{Accounts: accountService, OAuth: webOAuth, Usage: usageService, UsageRefresh: usageWorker, Models: catalog, ModelsRefresh: modelWorker, Cooldowns: cooldownRepo, APIKeys: apiKeyService})
	webAccounts := &webAccountAdapter{accounts: accountService, models: catalog, usage: usageService, cooldowns: cooldownRepo, now: func() time.Time { return time.Now().UTC() }}
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
			Usage:     &webUsageAdapter{accounts: accountService, usage: usageService, refresher: usageRefresher},
			Models:    &webModelAdapter{accounts: accountService, models: catalog, refresher: modelRefresher},
			APIKeys:   &webAPIKeyAdapter{service: apiKeyService},
			Readiness: publicModels,
		},
	})
	if err != nil {
		return fail(err)
	}
	handlers.Web = webHandler
	root := api.NewServer(api.ServerConfig{Handlers: handlers, ClientKeys: apiKeyService, AdminAPIKey: secrets.AdminAPIKey(), AdminAttempts: adminAuthGuard, AdminSources: trustedProxies, MaxBodyBytes: cfg.Limits.MaxBodyBytes, Logger: logger})
	trackedRoot, activity := api.NewActivityTracker(root)
	runtime := &Runtime{Config: cfg, Store: database, Accounts: accountService, modelWorker: modelWorker, usageWorker: usageWorker, refreshWorker: accounts.NewRefreshWorker(accountRepo, refreshService, modelRefresher, usageRefresher), cleanupWorker: NewCleanupWorker(responseRepo, oauthRepo, adminSessionRepo, usageRepo, adminThrottleRepo, cooldownRepo, 30*24*time.Hour, auththrottle.DefaultPolicy().SourceRetention), webOAuth: webOAuth, activity: activity, shutdownTimeout: 10 * time.Second, forceDrainTimeout: 5 * time.Second}
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
