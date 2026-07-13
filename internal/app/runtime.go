package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"supergrok-api/internal/accounts"
	"supergrok-api/internal/api"
	"supergrok-api/internal/api/admin"
	apianthropic "supergrok-api/internal/api/anthropic"
	apiopenai "supergrok-api/internal/api/openai"
	"supergrok-api/internal/config"
	appcrypto "supergrok-api/internal/crypto"
	"supergrok-api/internal/models"
	oauthxai "supergrok-api/internal/oauth/xai"
	"supergrok-api/internal/routing"
	"supergrok-api/internal/sessions"
	"supergrok-api/internal/store"
	"supergrok-api/internal/translate"
	"supergrok-api/internal/translate/registry"
	"supergrok-api/internal/usage"
	"supergrok-api/internal/web"
	"supergrok-api/internal/xai"
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
		v.verifier = oauthxai.NewIdentityVerifier(ctx, document.Issuer, document.JWKSURI, v.clientID)
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
	accounts     *store.AccountRepository
	capabilities *store.ModelCapabilityRepository
	cooldowns    *store.CooldownRepository
	now          func() time.Time
	defaultModel string
}

func (a publicCatalog) PublicModels(ctx context.Context) ([]apiopenai.Model, error) {
	values, err := a.accounts.List(ctx)
	if err != nil {
		return nil, err
	}
	eligible := make([]store.Account, 0, len(values))
	ids := make([]string, 0, len(values))
	now := a.now()
	for _, account := range values {
		if account.Enabled && account.Status == "ready" && oauthxai.CredentialsUsable(account, now) {
			eligible = append(eligible, account)
			ids = append(ids, account.ID)
		}
	}
	if len(eligible) == 0 {
		return []apiopenai.Model{}, nil
	}
	public, err := a.catalog.Public(ctx, ids)
	if err != nil {
		return nil, err
	}
	result := make([]apiopenai.Model, 0, len(public))
	for _, model := range public {
		resolved, ok := a.catalog.Resolve(model.ID)
		if !ok {
			continue
		}
		routable, err := a.modelRoutable(ctx, eligible, resolved)
		if err != nil {
			return nil, err
		}
		if routable {
			result = append(result, apiopenai.Model{ID: model.ID, OwnedBy: model.OwnedBy})
		}
	}
	return result, nil
}

func (a publicCatalog) modelRoutable(ctx context.Context, accounts []store.Account, model string) (bool, error) {
	now := a.now()
	for _, account := range accounts {
		capabilities, err := a.capabilities.List(ctx, account.ID)
		if err != nil {
			return false, err
		}
		known := len(capabilities) > 0
		supported := !known
		for _, capability := range capabilities {
			if capability.Model == model && capability.Supported && (capability.SupportsBackendSearch == nil || *capability.SupportsBackendSearch) {
				supported = true
				break
			}
		}
		if !supported {
			continue
		}
		cooling := false
		for _, scope := range []string{model, "*"} {
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
func (a publicCatalog) Ready(ctx context.Context) (bool, error) {
	values, err := a.PublicModels(ctx)
	if err != nil {
		return false, err
	}
	for _, model := range values {
		if model.ID == a.defaultModel {
			return true, nil
		}
	}
	return false, nil
}

func deriveWebCSRFKey(sessionKey [32]byte) [32]byte {
	const label = "supergrok-api/web-csrf/v1\x00"
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
	apiKeyService := accounts.NewAPIKeyService(store.NewAPIKeyRepository(database.DB))
	upstream := xai.NewClient(xai.HTTPConfig{BaseURL: cfg.Upstream.CLIProxyBaseURL, ClientVersion: cfg.Upstream.GrokClientVersion, UserAgent: "supergrok-api", RequestTimeout: cfg.Upstream.RequestTimeout.Duration(), SSEIdleTimeout: cfg.Upstream.SSEIdleTimeout.Duration()})
	catalog := models.NewCatalog(capabilityRepo, models.NewUpstream(upstream), cfg.Models.Allowlist, cfg.Models.Aliases)
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
	resolver := routing.ResolverFunc(func(value string) (string, error) {
		resolved, ok := catalog.Resolve(value)
		if !ok {
			return "", routing.ErrModelUnavailable
		}
		return resolved, nil
	})
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
	publicModels := publicCatalog{catalog: catalog, accounts: accountRepo, capabilities: capabilityRepo, cooldowns: cooldownRepo, now: func() time.Time { return time.Now().UTC() }, defaultModel: cfg.Models.Default}
	handlers := api.ServerHandlers{Health: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }), Ready: readyHandler(database.DB, publicModels, cfg.Models.Default), Models: apiopenai.ModelsHandler(publicModels), Chat: apiopenai.ChatHandler{Transform: chatTransform, Execute: executor.Execute, OpenStream: func(ctx context.Context, request routing.Request) (api.RoutedStream, error) {
		return executor.Stream(ctx, request)
	}}, Responses: apiopenai.ResponsesHandler{Transform: responsesTransform, Execute: executor.Execute, OpenStream: func(ctx context.Context, request routing.Request) (api.RoutedStream, error) {
		return executor.Stream(ctx, request)
	}, Sessions: sessionService}, Messages: apianthropic.MessagesHandler{Transform: anthropicTransform, Execute: executor.Execute, OpenStream: func(ctx context.Context, request routing.Request) (api.RoutedStream, error) {
		return executor.Stream(ctx, request)
	}}, CountTokens: http.HandlerFunc(apianthropic.CountTokensHandler)}
	webOAuth := newWebOAuthAdapter(ctx, accountService, oauthService)
	handlers.Admin = admin.NewHandler(admin.Services{Accounts: accountService, OAuth: webOAuth, Usage: usageService, UsageRefresh: usageWorker, Models: catalog, ModelsRefresh: modelWorker, Cooldowns: cooldownRepo, APIKeys: apiKeyService})
	webAccounts := &webAccountAdapter{accounts: accountService, models: catalog, usage: usageService, cooldowns: cooldownRepo, now: func() time.Time { return time.Now().UTC() }}
	trustedProxies, err := web.ParseTrustedProxies(cfg.Server.TrustedProxies)
	if err != nil {
		return fail(err)
	}
	webHandler, err := web.NewHandler(web.Options{
		AdminPassword: secrets.AdminPassword(),
		SessionStore:  adminSessionRepo,
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
	root := api.NewServer(api.ServerConfig{Handlers: handlers, ClientKeys: apiKeyService, AdminAPIKey: secrets.AdminAPIKey(), MaxBodyBytes: cfg.Limits.MaxBodyBytes, Logger: logger})
	trackedRoot, activity := api.NewActivityTracker(root)
	runtime := &Runtime{Config: cfg, Store: database, Accounts: accountService, modelWorker: modelWorker, usageWorker: usageWorker, refreshWorker: accounts.NewRefreshWorker(accountRepo, refreshService, modelRefresher, usageRefresher), cleanupWorker: NewCleanupWorker(responseRepo, oauthRepo, adminSessionRepo, usageRepo, cooldownRepo, 30*24*time.Hour), webOAuth: webOAuth, activity: activity, shutdownTimeout: 10 * time.Second, forceDrainTimeout: 5 * time.Second}
	runtime.Server = &http.Server{Addr: cfg.Server.Listen, Handler: trackedRoot, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	return runtime, nil
}

func readyHandler(database *sql.DB, catalog apiopenai.ModelCatalog, defaultModel string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := database.PingContext(r.Context()); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		values, err := catalog.PublicModels(r.Context())
		if err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		for _, model := range values {
			if model.ID == defaultModel {
				w.WriteHeader(http.StatusOK)
				return
			}
		}
		http.Error(w, "not ready", http.StatusServiceUnavailable)
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
