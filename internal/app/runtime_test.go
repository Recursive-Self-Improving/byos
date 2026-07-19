package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"byos/internal/api"
	apiopenai "byos/internal/api/openai"
	"byos/internal/config"
	appcrypto "byos/internal/crypto"
	"byos/internal/models"
	"byos/internal/provider"
	"byos/internal/routing"
	"byos/internal/store"
	"byos/internal/xai"
)

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
			catalog := models.NewCatalog(capabilities, nil, []string{"fast", config.DefaultModel}, map[string]string{"grok": config.DefaultModel, "fast": config.DefaultModel})
			defaultModel := test.defaultModel
			if defaultModel == "" {
				defaultModel = test.entry.PublicName
			}
			resolver := legacyXAIModelResolver(static, catalog)
			projection := newPublicCatalog(catalog, static, accountsRepo, store.NewCooldownRepository(database.DB), func() time.Time { return time.Now().UTC() }, defaultModel, resolver)
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
	catalog := models.NewCatalog(capabilities, nil, []string{"fast", config.DefaultModel}, map[string]string{"grok": config.DefaultModel, "fast": config.DefaultModel})
	projection := newPublicCatalog(catalog, static, accounts, store.NewCooldownRepository(database.DB), func() time.Time { return time.Now().UTC() }, "fast", legacyXAIModelResolver(static, catalog))
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
	projection := newPublicCatalog(nil, static, nil, nil, time.Now, "grok", nil)
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

func TestLegacyXAIExecutorResolverRejectsDevinModelsBeforeDispatch(t *testing.T) {
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
	account, err := accounts.UpsertLogin(ctx, xaiRuntimeAccount("legacy-executor"))
	if err != nil {
		t.Fatal(err)
	}

	requests := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"response.completed\"}\n\n"))
	}))
	defer upstream.Close()

	capabilities := store.NewModelCapabilityRepository(database.DB)
	cooldownStates := store.NewCooldownRepository(database.DB)
	staticCatalog, err := models.NewStaticCatalog(config.Default().Models.Entries)
	if err != nil {
		t.Fatal(err)
	}
	newExecutor := func(allowlist []string, aliases map[string]string) *routing.Executor {
		catalog := models.NewCatalog(capabilities, nil, allowlist, aliases)
		return routing.NewExecutor(
			routing.NewScheduler(),
			xai.NewClient(xai.HTTPConfig{BaseURL: upstream.URL, RequestTimeout: time.Second, SSEIdleTimeout: time.Second}),
			nil,
			routing.NewCooldownManager(cooldownStates, accounts),
			accounts,
			capabilities,
			cooldownStates,
			legacyXAIModelResolver(staticCatalog, catalog),
		)
	}

	variants := []struct {
		name      string
		allowlist []string
		aliases   map[string]string
		model     string
	}{
		{name: "unknown model", allowlist: []string{"grok-4.5"}, aliases: map[string]string{"grok": "grok-4.5"}, model: "unknown"},
		{name: "Devin public name added to allowlist", allowlist: []string{"grok-4.5", "kimi-k2-7"}, aliases: map[string]string{"grok": "grok-4.5"}, model: "kimi-k2-7"},
		{name: "Devin alias added to allowlist", allowlist: []string{"grok-4.5", "glm-5-2"}, aliases: map[string]string{"grok": "grok-4.5", "devin": "glm-5-2"}, model: "devin"},
		{name: "xAI alias redirected to Devin", allowlist: []string{"grok-4.5", "swe-1-6-slow"}, aliases: map[string]string{"grok": "swe-1-6-slow"}, model: "grok"},
	}
	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			before := requests
			executor := newExecutor(variant.allowlist, variant.aliases)
			_, err := executor.Execute(ctx, routing.Request{Model: variant.model, Body: []byte(`{"input":"hello","tools":[{"type":"x_search"}]}`), PreferredAccountID: account.ID})
			if !errors.Is(err, routing.ErrModelUnavailable) {
				t.Fatalf("model %q error=%v, want ErrModelUnavailable", variant.model, err)
			}
			if requests != before {
				t.Fatalf("model %q reached xAI client: requests=%d, want %d", variant.model, requests, before)
			}
		})
	}

	executor := newExecutor([]string{"grok-4.5"}, map[string]string{"grok": "grok-4.5", "fast": "grok-4.5"})
	for _, model := range []string{"fast", "grok", "grok-4.5"} {
		result, err := executor.Execute(ctx, routing.Request{Model: model, Body: []byte(`{"input":"hello","tools":[{"type":"x_search"}]}`), PreferredAccountID: account.ID})
		if err != nil {
			t.Fatalf("model %q: %v", model, err)
		}
		if result.Model != "grok-4.5" {
			t.Fatalf("model %q resolved to %q", model, result.Model)
		}
	}
	if requests != 3 {
		t.Fatalf("legacy xAI models dispatched requests=%d, want 3", requests)
	}
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
