package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"byos/internal/accounts"
	"byos/internal/api"
	"byos/internal/api/admin"
	apiopenai "byos/internal/api/openai"
	"byos/internal/config"
	appcrypto "byos/internal/crypto"
	"byos/internal/models"
	oauthxai "byos/internal/oauth/xai"
	"byos/internal/provider"
	"byos/internal/routing"
	"byos/internal/store"
	"byos/internal/usage"
	"byos/internal/xai"
)

var _ admin.AccountManager = (*accounts.Service)(nil)
var _ provider.CapabilityRegistry = (*provider.RuntimeCapabilityRegistry)(nil)
var _ provider.LifecycleRegistry = (*provider.RuntimeCapabilityRegistry)(nil)
var _ admin.CompletionCoordinator = (*webOAuthAdapter)(nil)

func TestRuntimeHealthAndReadinessWithoutAccounts(t *testing.T) {
	t.Setenv("BYOS_MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("BYOS_ADMIN_PASSWORD", "password")
	t.Setenv("BYOS_ADMIN_API_KEY", "admin-key")
	secrets, err := config.LoadSecrets()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	runtime, err := New(t.Context(), cfg, secrets, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	for _, test := range []struct {
		path string
		want int
	}{{"/healthz", http.StatusOK}, {"/readyz", http.StatusServiceUnavailable}, {"/v1/models", http.StatusUnauthorized}, {"/v1/completions", http.StatusNotFound}} {
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		response := httptest.NewRecorder()
		runtime.Server.Handler.ServeHTTP(response, request)
		if response.Code != test.want {
			t.Fatalf("%s status=%d body=%s", test.path, response.Code, response.Body.String())
		}
	}
}

func TestRuntimeRegistersCompleteXAIAndLifecycleOnlyDevin(t *testing.T) {
	t.Setenv("BYOS_MASTER_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	t.Setenv("BYOS_ADMIN_PASSWORD", "password")
	t.Setenv("BYOS_ADMIN_API_KEY", "admin-key")
	secrets, err := config.LoadSecrets()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	runtime, err := New(t.Context(), cfg, secrets, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	xaiCapabilities, ok := runtime.capabilityRegistry.Capabilities(provider.XAI, "xai")
	if !ok {
		t.Fatal("xAI capability registration is missing")
	}
	if xaiCapabilities.Policy == nil || xaiCapabilities.Generation == nil || xaiCapabilities.Credentials == nil || xaiCapabilities.CredentialRefresher == nil || xaiCapabilities.Lifecycle == nil || xaiCapabilities.ModelDiscoverer == nil || xaiCapabilities.UsageFetcher == nil {
		t.Fatalf("incomplete xAI capabilities: %+v", xaiCapabilities)
	}
	devinCapabilities, ok := runtime.capabilityRegistry.Capabilities(provider.Devin, "devin")
	if !ok {
		t.Fatal("Devin lifecycle registration is missing")
	}
	if devinCapabilities.Lifecycle == nil || devinCapabilities.Policy != nil || devinCapabilities.Generation != nil || devinCapabilities.Credentials != nil || devinCapabilities.CredentialRefresher != nil || devinCapabilities.ModelDiscoverer != nil || devinCapabilities.UsageFetcher != nil {
		t.Fatalf("Devin registration is not lifecycle-only: %+v", devinCapabilities)
	}
	for _, lookup := range []struct {
		provider provider.Kind
		policy   string
	}{{provider.XAI, "devin"}, {provider.Devin, "xai"}} {
		if _, registered := runtime.capabilityRegistry.Capabilities(lookup.provider, lookup.policy); registered {
			t.Fatalf("unexpected runtime registration for provider=%q policy=%q", lookup.provider, lookup.policy)
		}
	}
}

func TestPublicModelsAndReadinessAreProviderAware(t *testing.T) {
	falseValue := false
	tests := []struct {
		name         string
		entry        config.ModelEntry
		defaultModel string
		account      store.Account
		capabilities []store.ModelCapability
		wantModels   []apiopenai.Model
		wantReady    int
	}{
		{
			name:       "grok owner metadata routes through xai",
			entry:      config.ModelEntry{PublicName: "grok", UpstreamName: "grok-4.5", Provider: config.ProviderXAI, OwnedBy: "byos", PolicyKey: "xai"},
			account:    xaiRuntimeAccount("grok-xai"),
			wantModels: []apiopenai.Model{{ID: "grok", OwnedBy: "byos"}}, wantReady: http.StatusOK,
		},
		{
			name:         "xai alias default resolves to canonical static model",
			entry:        config.ModelEntry{PublicName: "grok-4.5", UpstreamName: "grok-4.5", Provider: config.ProviderXAI, OwnedBy: "xai", PolicyKey: "xai"},
			defaultModel: "fast",
			account:      xaiRuntimeAccount("fast-alias"),
			wantModels:   []apiopenai.Model{{ID: "grok-4.5", OwnedBy: "xai"}}, wantReady: http.StatusOK,
		},
		{
			name:         "xai alias default is not ready when canonical model is unroutable",
			entry:        config.ModelEntry{PublicName: "grok-4.5", UpstreamName: "grok-4.5", Provider: config.ProviderXAI, OwnedBy: "xai", PolicyKey: "xai"},
			defaultModel: "fast",
			account:      xaiRuntimeAccount("fast-unroutable"),
			capabilities: []store.ModelCapability{{Model: "grok-4.5", Supported: true, SupportsBackendSearch: &falseValue}},
			wantReady:    http.StatusServiceUnavailable,
		},
		{
			name:         "unknown default fails closed",
			entry:        config.ModelEntry{PublicName: "grok-4.5", UpstreamName: "grok-4.5", Provider: config.ProviderXAI, OwnedBy: "xai", PolicyKey: "xai"},
			defaultModel: "unknown",
			account:      xaiRuntimeAccount("unknown-default"),
			wantModels:   []apiopenai.Model{{ID: "grok-4.5", OwnedBy: "xai"}}, wantReady: http.StatusServiceUnavailable,
		},
		{
			name:         "xai known search unsupported",
			entry:        config.ModelEntry{PublicName: "grok", UpstreamName: "grok-4.5", Provider: config.ProviderXAI, OwnedBy: "byos", PolicyKey: "xai"},
			account:      xaiRuntimeAccount("xai-search-false"),
			capabilities: []store.ModelCapability{{Model: "grok-4.5", Supported: true, SupportsBackendSearch: &falseValue}},
			wantReady:    http.StatusServiceUnavailable,
		},
		{
			name:         "devin known capability ignores backend search",
			entry:        config.ModelEntry{PublicName: "kimi-k2-7", UpstreamName: "kimi-k2-7", Provider: config.ProviderDevin, OwnedBy: "devin", PolicyKey: "devin"},
			account:      devinRuntimeAccount("devin-known"),
			capabilities: []store.ModelCapability{{Model: "kimi-k2-7", Supported: true, SupportsBackendSearch: &falseValue}},
			wantModels:   []apiopenai.Model{{ID: "kimi-k2-7", OwnedBy: "devin"}}, wantReady: http.StatusServiceUnavailable,
		},
		{
			name:       "devin unknown capability stays provider local",
			entry:      config.ModelEntry{PublicName: "glm-5-2", UpstreamName: "glm-5-2", Provider: config.ProviderDevin, OwnedBy: "devin", PolicyKey: "devin"},
			account:    devinRuntimeAccount("devin-unknown"),
			wantModels: []apiopenai.Model{{ID: "glm-5-2", OwnedBy: "devin"}}, wantReady: http.StatusServiceUnavailable,
		},
		{
			name:      "owner text cannot substitute for provider",
			entry:     config.ModelEntry{PublicName: "mismatch", UpstreamName: "mismatch", Provider: config.ProviderDevin, OwnedBy: "xai", PolicyKey: "devin"},
			account:   xaiRuntimeAccount("owner-match"),
			wantReady: http.StatusServiceUnavailable,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			database, err := store.Open(ctx, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{7}, 32))
			if err != nil {
				t.Fatal(err)
			}
			accountsRepo := store.NewAccountRepository(database.DB, keys)
			account, err := accountsRepo.UpsertLogin(ctx, test.account)
			if err != nil {
				t.Fatal(err)
			}
			capabilities := store.NewModelCapabilityRepository(database.DB)
			if len(test.capabilities) > 0 {
				for i := range test.capabilities {
					test.capabilities[i].AccountID = account.ID
					test.capabilities[i].DiscoveredAt = time.Now().UTC()
				}
				if err := capabilities.Replace(ctx, account.ID, test.capabilities); err != nil {
					t.Fatal(err)
				}
			}
			static, err := models.NewStaticCatalog([]config.ModelEntry{test.entry})
			if err != nil {
				t.Fatal(err)
			}
			catalog := models.NewCatalog(capabilities, []string{"fast", config.DefaultModel}, map[string]string{"grok": config.DefaultModel, "fast": config.DefaultModel})
			aliases := map[string]string{}
			if _, resolveErr := static.Resolve(config.DefaultModel); resolveErr == nil {
				aliases = map[string]string{"grok": config.DefaultModel, "fast": config.DefaultModel}
			}
			resolver, err := models.NewStaticCatalogOverlay(static, aliases)
			if err != nil {
				t.Fatal(err)
			}
			defaultModel := test.defaultModel
			if defaultModel == "" {
				defaultModel = test.entry.PublicName
			}
			projection := newPublicCatalog(catalog, static, resolver, accountsRepo, store.NewCooldownRepository(database.DB), func() time.Time { return time.Now().UTC() }, defaultModel)
			listed, err := projection.PublicModels(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(listed) != len(test.wantModels) {
				t.Fatalf("models=%+v want=%+v", listed, test.wantModels)
			}
			for i := range listed {
				if listed[i] != test.wantModels[i] {
					t.Fatalf("models=%+v want=%+v", listed, test.wantModels)
				}
			}
			response := httptest.NewRecorder()
			readyHandler(database.DB, projection).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if response.Code != test.wantReady {
				t.Fatalf("ready=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}
func TestAliasDefaultDoesNotChangeFiveModelPublicProjection(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accounts := store.NewAccountRepository(database.DB, keys)
	for _, account := range []store.Account{xaiRuntimeAccount("five-model-xai"), devinRuntimeAccount("five-model-devin")} {
		if _, err := accounts.UpsertLogin(ctx, account); err != nil {
			t.Fatal(err)
		}
	}
	capabilities := store.NewModelCapabilityRepository(database.DB)
	static, err := models.NewStaticCatalog(config.Default().Models.Entries)
	if err != nil {
		t.Fatal(err)
	}
	catalog := models.NewCatalog(capabilities, []string{"fast", config.DefaultModel}, map[string]string{"grok": config.DefaultModel, "fast": config.DefaultModel})
	resolver, err := models.NewStaticCatalogOverlay(static, map[string]string{"grok": config.DefaultModel, "fast": config.DefaultModel})
	if err != nil {
		t.Fatal(err)
	}
	projection := newPublicCatalog(catalog, static, resolver, accounts, store.NewCooldownRepository(database.DB), func() time.Time { return time.Now().UTC() }, "fast")
	listed, err := projection.PublicModels(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 5 {
		t.Fatalf("public models=%+v, want exact five static IDs", listed)
	}
	for _, model := range listed {
		if model.ID == "fast" {
			t.Fatalf("legacy alias leaked into public models: %+v", listed)
		}
	}
	ready, err := projection.Ready(ctx)
	if err != nil || !ready {
		t.Fatalf("alias readiness=%v err=%v", ready, err)
	}
}

func TestPublicCatalogCachesStaticSnapshots(t *testing.T) {
	static, err := models.NewStaticCatalog([]config.ModelEntry{
		{PublicName: "grok", UpstreamName: "grok-upstream", Provider: config.ProviderXAI, OwnedBy: "xai", PolicyKey: "xai"},
		{PublicName: "devin", UpstreamName: "devin-upstream", Provider: config.ProviderDevin, OwnedBy: "devin", PolicyKey: "devin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	projection := newPublicCatalog(nil, static, static, nil, nil, time.Now, "grok")
	if len(projection.models) != 2 {
		t.Fatalf("cached models=%+v", projection.models)
	}
	resolved, ok := projection.xaiModels["grok-upstream"]
	if !ok || resolved.PublicName != "grok" {
		t.Fatalf("cached xAI models=%+v", projection.xaiModels)
	}
	if _, ok := projection.xaiModels["devin-upstream"]; ok {
		t.Fatalf("non-xAI model entered canonical lookup: %+v", projection.xaiModels)
	}
	external := static.Models()
	external[0].PublicName = "mutated"
	if projection.models[0].PublicName == "mutated" {
		t.Fatal("cached static rows alias a defensive Models copy")
	}
}

func TestNeutralExecutorCompositionRejectsUnregisteredProvidersBeforeDispatch(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accounts := store.NewAccountRepository(database.DB, keys)
	account, err := accounts.UpsertLogin(ctx, xaiRuntimeAccount("neutral-executor"))
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Fatalf("authorization=%q", got)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"response.completed\"}\n\n"))
	}))
	defer upstream.Close()
	staticCatalog, err := models.NewStaticCatalog(config.Default().Models.Entries)
	if err != nil {
		t.Fatal(err)
	}
	modelCatalog, err := models.NewStaticCatalogOverlay(staticCatalog, map[string]string{"grok": config.DefaultModel, "fast": config.DefaultModel})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := provider.NewCapabilityRegistry([]provider.CapabilityRegistration{{
		Provider:  provider.XAI,
		PolicyKey: "xai",
		Capabilities: provider.Capabilities{
			Policy:      xai.RequestPolicy{},
			Generation:  xai.NewProviderClient(xai.NewClient(xai.HTTPConfig{BaseURL: upstream.URL, RequestTimeout: time.Second, SSEIdleTimeout: time.Second})),
			Credentials: oauthxai.NewProviderCredentialManager(accounts, nil),
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	cooldownStates := store.NewCooldownRepository(database.DB)
	executor := routing.NewExecutor(routing.NewScheduler(), modelCatalog, registry, routing.NewCooldownManager(cooldownStates, accounts), accounts, store.NewModelCapabilityRepository(database.DB), cooldownStates)
	for _, model := range []string{"unknown", "kimi-k2-7", "glm-5-2", "swe-1-6-slow"} {
		before := requests
		body := []byte(`{"model":"public","input":"hello"}`)
		original := bytes.Clone(body)
		_, err := executor.Execute(ctx, routing.Request{Model: model, Body: body, PreferredAccountID: account.ID})
		if !errors.Is(err, routing.ErrModelUnavailable) {
			t.Fatalf("model %q error=%v", model, err)
		}
		if requests != before {
			t.Fatalf("model %q reached xAI client", model)
		}
		if !bytes.Equal(body, original) {
			t.Fatalf("model %q mutated rejected request body: %s", model, body)
		}
	}

	result, err := executor.Execute(ctx, routing.Request{Model: "fast", Body: []byte(`{"input":"hello"}`), PreferredAccountID: account.ID})
	if err != nil {
		t.Fatal(err)
	}
	if result.Model != config.DefaultModel || result.AccountID != account.ID || requests != 1 {
		t.Fatalf("result=%+v requests=%d", result, requests)
	}
}

func TestMixedProviderWorkersDoNotExposeDevinCredentialsToXAIControlPlanes(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{6}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accountRepo := store.NewAccountRepository(database.DB, keys)
	const devinSentinel = "devin-opaque-token-must-never-reach-xai"
	devinAccount, err := accountRepo.UpsertLogin(ctx, devinRuntimeAccount(devinSentinel))
	if err != nil {
		t.Fatal(err)
	}
	xaiAccount, err := accountRepo.UpsertLogin(ctx, xaiRuntimeAccount("mixed-provider-xai"))
	if err != nil {
		t.Fatal(err)
	}

	type requestKey struct{ path, query string }
	var requestMu sync.Mutex
	requests := make(map[requestKey]int)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestMu.Lock()
		requests[requestKey{r.URL.Path, r.URL.RawQuery}]++
		requestMu.Unlock()
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Errorf("authorization = %q", got)
		}
		if bytes.Contains([]byte(r.Header.Get("Authorization")), []byte(devinSentinel)) {
			t.Error("Devin sentinel reached xAI authorization header")
		}
		switch (requestKey{r.URL.Path, r.URL.RawQuery}) {
		case requestKey{"/models-v2", ""}:
			w.WriteHeader(http.StatusNotFound)
		case requestKey{"/models", ""}:
			_, _ = w.Write([]byte(`[{"id":"grok-control","displayName":"Grok Control"}]`))
		case requestKey{"/billing", ""}:
			_, _ = w.Write([]byte(`{"config":{"monthlyLimit":{"val":1000},"used":{"val":250},"billingPeriodEnd":"2030-01-01T00:00:00Z"}}`))
		case requestKey{"/billing", "format=credits"}:
			_, _ = w.Write([]byte(`{"config":{"currentPeriod":{"type":"USAGE_PERIOD_TYPE_WEEKLY"},"creditUsagePercent":20,"billingPeriodEnd":"2030-01-02T00:00:00Z"}}`))
		default:
			t.Errorf("unexpected xAI control endpoint: %s?%s", r.URL.Path, r.URL.RawQuery)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer upstream.Close()

	credentialManager := &countingCredentialManager{delegate: oauthxai.NewProviderCredentialManager(accountRepo, nil), calls: make(map[string]int)}
	xaiClient := xai.NewClient(xai.HTTPConfig{BaseURL: upstream.URL, RequestTimeout: time.Second, SSEIdleTimeout: time.Second})
	registry, err := provider.NewCapabilityRegistry([]provider.CapabilityRegistration{{
		Provider: provider.XAI, PolicyKey: "xai", Capabilities: provider.Capabilities{
			Policy: xai.RequestPolicy{}, Generation: xai.NewProviderClient(xaiClient), Credentials: credentialManager,
			ModelDiscoverer: models.NewXAIProvider(models.NewClient(xaiClient)),
			UsageFetcher:    usage.NewXAIProvider(usage.NewClient(xaiClient)),
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	modelRepo := store.NewModelCapabilityRepository(database.DB)
	usageRepo := store.NewUsageRepository(database.DB, keys)
	modelWorker := models.NewWorker(models.NewStoreAccountProvider(accountRepo), registry, models.NewCatalog(modelRepo, nil, nil), time.Hour, time.Second, 1)
	usageWorker := usage.NewWorker(usage.NewStoreAccountProvider(accountRepo), registry, usage.NewService(usageRepo, store.NewLocalUsageRepository(database.DB)), time.Hour, time.Second, 1)

	modelAccounts, err := models.NewStoreAccountProvider(accountRepo).ModelAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	usageAccounts, err := usage.NewStoreAccountProvider(accountRepo).UsageAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	modelByID := make(map[string]models.Account, len(modelAccounts))
	for _, account := range modelAccounts {
		modelByID[account.ID] = account
	}
	usageByID := make(map[string]usage.Account, len(usageAccounts))
	for _, account := range usageAccounts {
		usageByID[account.ID] = account
	}
	devinModelAccount, ok := modelByID[devinAccount.ID]
	if !ok || devinModelAccount.Provider != provider.Devin || !devinModelAccount.Enabled {
		t.Fatalf("Devin model projection=%+v present=%v", devinModelAccount, ok)
	}
	devinUsageAccount, ok := usageByID[devinAccount.ID]
	if !ok || devinUsageAccount.Provider != provider.Devin || !devinUsageAccount.Enabled {
		t.Fatalf("Devin usage projection=%+v present=%v", devinUsageAccount, ok)
	}
	xaiModelAccount, ok := modelByID[xaiAccount.ID]
	if !ok || xaiModelAccount.Provider != provider.XAI || !xaiModelAccount.Enabled {
		t.Fatalf("xAI model projection=%+v present=%v", xaiModelAccount, ok)
	}
	xaiUsageAccount, ok := usageByID[xaiAccount.ID]
	if !ok || xaiUsageAccount.Provider != provider.XAI || !xaiUsageAccount.Enabled {
		t.Fatalf("xAI usage projection=%+v present=%v", xaiUsageAccount, ok)
	}
	if err := modelWorker.RefreshAccount(ctx, devinModelAccount); err != nil {
		t.Fatal(err)
	}
	if err := usageWorker.RefreshAccount(ctx, devinUsageAccount); err != nil {
		t.Fatal(err)
	}
	requestMu.Lock()
	devinRequests := len(requests)
	requestMu.Unlock()
	if devinRequests != 0 || credentialManager.count(devinAccount.ID) != 0 {
		t.Fatalf("Devin crossed xAI boundary: endpoints=%v credential_calls=%d", requests, credentialManager.count(devinAccount.ID))
	}
	if rows, err := modelRepo.List(ctx, devinAccount.ID); err != nil || len(rows) != 0 {
		t.Fatalf("Devin model rows=%+v err=%v", rows, err)
	}
	if _, err := usageRepo.Latest(ctx, devinAccount.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("Devin usage snapshot err=%v, want sql.ErrNoRows", err)
	}
	if status := modelWorker.Status(devinAccount.ID); status != (models.RefreshStatus{}) {
		t.Fatalf("Devin model status mutated: %+v", status)
	}
	if status := usageWorker.Status(devinAccount.ID); status != (usage.RefreshStatus{}) {
		t.Fatalf("Devin usage status mutated: %+v", status)
	}
	storedDevin, err := accountRepo.Get(ctx, devinAccount.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(storedDevin, devinAccount) {
		t.Fatalf("Devin account mutated: before=%+v after=%+v", devinAccount, storedDevin)
	}

	if err := modelWorker.RefreshAccount(ctx, xaiModelAccount); err != nil {
		t.Fatal(err)
	}
	if err := usageWorker.RefreshAccount(ctx, xaiUsageAccount); err != nil {
		t.Fatal(err)
	}
	requestMu.Lock()
	gotRequests := make(map[requestKey]int, len(requests))
	for key, count := range requests {
		gotRequests[key] = count
	}
	requestMu.Unlock()
	wantRequests := map[requestKey]int{{"/models-v2", ""}: 1, {"/models", ""}: 1, {"/billing", ""}: 1, {"/billing", "format=credits"}: 1}
	if len(gotRequests) != len(wantRequests) {
		t.Fatalf("xAI endpoints=%v want=%v", gotRequests, wantRequests)
	}
	for key, want := range wantRequests {
		if gotRequests[key] != want {
			t.Fatalf("xAI endpoint %v calls=%d want=%d (all=%v)", key, gotRequests[key], want, gotRequests)
		}
	}
	if credentialManager.count(xaiAccount.ID) != 2 {
		t.Fatalf("xAI credential calls=%d want=2", credentialManager.count(xaiAccount.ID))
	}
	modelStatus := modelWorker.Status(xaiAccount.ID)
	if modelStatus.AccountID != xaiAccount.ID || modelStatus.LastSuccess.IsZero() || modelStatus.LastAttempt.IsZero() || modelStatus.LastError != "" || modelStatus.Refreshing || modelStatus.Stale {
		t.Fatalf("xAI model refresh status=%+v", modelStatus)
	}
	usageStatus := usageWorker.Status(xaiAccount.ID)
	if usageStatus.AccountID != xaiAccount.ID || usageStatus.LastSuccess.IsZero() || usageStatus.LastAttempt.IsZero() || usageStatus.LastError != "" || usageStatus.Refreshing || usageStatus.Stale {
		t.Fatalf("xAI usage refresh status=%+v", usageStatus)
	}
	modelRows, err := modelRepo.List(ctx, xaiAccount.ID)
	if err != nil || len(modelRows) != 1 || modelRows[0].AccountID != xaiAccount.ID || modelRows[0].Model != "grok-control" || modelRows[0].DisplayName != "Grok Control" || !modelRows[0].Supported || modelRows[0].Stale || modelRows[0].DiscoveredAt.IsZero() {
		t.Fatalf("xAI model persistence=%+v err=%v", modelRows, err)
	}
	storedXAI, err := accountRepo.Get(ctx, xaiAccount.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(storedXAI, xaiAccount) {
		t.Fatalf("xAI account mutated: before=%+v after=%+v", xaiAccount, storedXAI)
	}
	storedUsage, err := usageRepo.Latest(ctx, xaiAccount.ID)
	if err != nil || storedUsage.AccountID != xaiAccount.ID || len(storedUsage.Normalized) == 0 || len(storedUsage.Raw) == 0 || storedUsage.Stale || storedUsage.Error != "" {
		t.Fatalf("xAI usage persistence=%+v err=%v", storedUsage, err)
	}
	var normalized struct {
		Monthly *usage.Monthly `json:"monthly"`
		Weekly  *usage.Weekly  `json:"weekly"`
	}
	if err := json.Unmarshal(storedUsage.Normalized, &normalized); err != nil || normalized.Monthly == nil || normalized.Monthly.Limit != 1000 || normalized.Monthly.Used != 250 || normalized.Monthly.Remaining != 750 || normalized.Monthly.ResetAt != time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) || normalized.Weekly == nil || normalized.Weekly.UsedPercent != 20 || normalized.Weekly.RemainingPercent != 80 || normalized.Weekly.ResetAt != time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC) {
		t.Fatalf("xAI normalized usage=%s decoded=%+v err=%v", storedUsage.Normalized, normalized, err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(storedUsage.Raw, &raw); err != nil || len(raw) != 2 || string(raw["monthly"]) != `{"config":{"monthlyLimit":{"val":1000},"used":{"val":250},"billingPeriodEnd":"2030-01-01T00:00:00Z"}}` || string(raw["credits"]) != `{"config":{"currentPeriod":{"type":"USAGE_PERIOD_TYPE_WEEKLY"},"creditUsagePercent":20,"billingPeriodEnd":"2030-01-02T00:00:00Z"}}` {
		t.Fatalf("xAI raw usage=%s decoded=%v err=%v", storedUsage.Raw, raw, err)
	}
}

type countingCredentialManager struct {
	delegate provider.CredentialManager
	mu       sync.Mutex
	calls    map[string]int
}

func (m *countingCredentialManager) Credential(ctx context.Context, accountID string) (provider.Credential, error) {
	m.mu.Lock()
	m.calls[accountID]++
	m.mu.Unlock()
	return m.delegate.Credential(ctx, accountID)
}

func (m *countingCredentialManager) AuthenticationFailed(ctx context.Context, accountID string, upstream *provider.UpstreamError) error {
	return m.delegate.AuthenticationFailed(ctx, accountID, upstream)
}

func (m *countingCredentialManager) count(accountID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls[accountID]
}

func xaiRuntimeAccount(subject string) store.Account {
	return store.Account{Provider: provider.XAI, Status: "ready", Credentials: store.AccountCredentials{Issuer: "issuer", Subject: subject, AccessToken: "token"}}
}

func devinRuntimeAccount(token string) store.Account {
	expires := time.Now().Add(time.Hour)
	return store.Account{Provider: provider.Devin, Status: "ready", ExpiresAt: &expires, Credentials: store.AccountCredentials{OpaqueToken: token, OpaqueTokenExpiresAt: &expires}}
}

func TestRuntimeRunStopsOnCancellation(t *testing.T) {
	t.Setenv("BYOS_MASTER_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)))
	t.Setenv("BYOS_ADMIN_PASSWORD", "password")
	t.Setenv("BYOS_ADMIN_API_KEY", "admin-key")
	secrets, err := config.LoadSecrets()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Server.Listen = "127.0.0.1:0"
	runtime, err := New(t.Context(), cfg, secrets, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error=%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestRuntimeRunDrainsOrLeavesDatabaseOpenForActiveHandlers(t *testing.T) {
	for _, test := range []struct {
		name  string
		stuck bool
	}{{"force close drains", false}, {"undrained leaves database open", true}} {
		t.Run(test.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := listener.Addr().String()
			_ = listener.Close()
			t.Setenv("BYOS_MASTER_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)))
			t.Setenv("BYOS_ADMIN_PASSWORD", "password")
			t.Setenv("BYOS_ADMIN_API_KEY", "admin-key")
			secrets, err := config.LoadSecrets()
			if err != nil {
				t.Fatal(err)
			}
			cfg := config.Default()
			cfg.DataDir = t.TempDir()
			cfg.Server.Listen = address
			runtime, err := New(t.Context(), cfg, secrets, nil)
			if err != nil {
				t.Fatal(err)
			}
			runtime.shutdownTimeout = 20 * time.Millisecond
			runtime.forceDrainTimeout = 50 * time.Millisecond
			started := make(chan struct{})
			release := make(chan struct{})
			handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				close(started)
				if test.stuck {
					<-release
				} else {
					<-r.Context().Done()
				}
			})
			tracked, activity := api.NewActivityTracker(handler)
			runtime.Server.Handler = tracked
			runtime.activity = activity
			ctx, cancel := context.WithCancel(context.Background())
			runDone := make(chan error, 1)
			go func() { runDone <- runtime.Run(ctx) }()
			requestDone := make(chan struct{})
			go func() {
				defer close(requestDone)
				client := &http.Client{Timeout: 2 * time.Second}
				for {
					_, err := client.Get("http://" + address)
					if err == nil {
						return
					}
					select {
					case <-time.After(5 * time.Millisecond):
					case <-ctx.Done():
						return
					}
				}
			}()
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("handler did not start")
			}
			cancel()
			select {
			case <-runDone:
			case <-time.After(2 * time.Second):
				t.Fatal("Run did not return")
			}
			if test.stuck {
				if err := runtime.Store.DB.PingContext(context.Background()); err != nil {
					t.Fatalf("database closed with active handler: %v", err)
				}
				close(release)
				<-requestDone
				if err := runtime.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				<-requestDone
				if err := runtime.Store.DB.PingContext(context.Background()); err == nil {
					t.Fatal("database remained open after handler drain")
				}
			}
		})
	}
}
