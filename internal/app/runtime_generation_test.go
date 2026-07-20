package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"byos/internal/config"
	appcrypto "byos/internal/crypto"
	"byos/internal/models"
	oauthdevin "byos/internal/oauth/devin"
	oauthxai "byos/internal/oauth/xai"
	"byos/internal/provider"
	"byos/internal/store"
	"byos/internal/xai"
)

// testCapabilityRegistry builds a RuntimeCapabilityRegistry with the complete
// generation trio (Policy, Generation, Credentials) for both xAI and Devin so
// publicCatalog.hasRuntimeCapabilities admits every fixed static model. The
// generation clients are nil-safe placeholders; routing tests in the routing
// package exercise real dispatch, while these app-level tests only need the
// registry to satisfy the capability gate.
func testCapabilityRegistry(t *testing.T, accounts *store.AccountRepository) *provider.RuntimeCapabilityRegistry {
	t.Helper()
	xaiClient := xai.NewClient(xai.HTTPConfig{BaseURL: "https://unused.invalid", RequestTimeout: time.Second, SSEIdleTimeout: time.Second})
	registry, err := provider.NewCapabilityRegistry([]provider.CapabilityRegistration{
		{
			Provider:  provider.XAI,
			PolicyKey: "xai",
			Capabilities: provider.Capabilities{
				Policy:      xai.RequestPolicy{},
				Generation:  xai.NewProviderClient(xaiClient),
				Credentials: oauthxai.NewProviderCredentialManager(accounts, nil),
			},
		},
		{
			Provider:  provider.Devin,
			PolicyKey: "devin",
			Capabilities: provider.Capabilities{
				Policy:      devinPassthroughPolicy{},
				Generation:  &noOpGenerationClient{},
				Credentials: oauthdevin.NewProviderCredentialManager(accounts),
			},
		},
	})
	if err != nil {
		t.Fatalf("build test capability registry: %v", err)
	}
	return registry
}

// testCapabilityRegistryFor builds a registry that registers the complete
// generation trio only for the single provider of the supplied model entry.
// Other static models have no registered capability and must be suppressed from
// public listing and readiness.
func testCapabilityRegistryFor(t *testing.T, accounts *store.AccountRepository, entry config.ModelEntry) *provider.RuntimeCapabilityRegistry {
	t.Helper()
	xaiClient := xai.NewClient(xai.HTTPConfig{BaseURL: "https://unused.invalid", RequestTimeout: time.Second, SSEIdleTimeout: time.Second})
	registrations := []provider.CapabilityRegistration{}
	switch entry.Provider {
	case config.ProviderXAI:
		registrations = append(registrations, provider.CapabilityRegistration{
			Provider:  provider.XAI,
			PolicyKey: entry.PolicyKey,
			Capabilities: provider.Capabilities{
				Policy:      xai.RequestPolicy{},
				Generation:  xai.NewProviderClient(xaiClient),
				Credentials: oauthxai.NewProviderCredentialManager(accounts, nil),
			},
		})
	case config.ProviderDevin:
		registrations = append(registrations, provider.CapabilityRegistration{
			Provider:  provider.Devin,
			PolicyKey: entry.PolicyKey,
			Capabilities: provider.Capabilities{
				Policy:      devinPassthroughPolicy{},
				Generation:  &noOpGenerationClient{},
				Credentials: oauthdevin.NewProviderCredentialManager(accounts),
			},
		})
	}
	registry, err := provider.NewCapabilityRegistry(registrations)
	if err != nil {
		t.Fatalf("build single-provider test capability registry: %v", err)
	}
	return registry
}

type devinPassthroughPolicy struct{}

func (devinPassthroughPolicy) Prepare(_ context.Context, _ provider.ResolvedModel, _ provider.CanonicalRequest) error {
	return nil
}

type noOpGenerationClient struct{}

func (*noOpGenerationClient) Execute(context.Context, provider.GenerationRequest) ([]provider.Event, error) {
	return nil, errors.New("noOp generation client is not expected in app-level catalog tests")
}
func (*noOpGenerationClient) Stream(context.Context, provider.GenerationRequest) (provider.Stream, error) {
	return nil, errors.New("noOp generation client is not expected in app-level catalog tests")
}

// TestRegistryConstructionAcceptsCompleteXAIAndDevin asserts C9.1:
// RuntimeCapabilityRegistry construction accepts both xAI and Devin
// registrations when each carries the complete generation trio (Policy,
// Generation, Credentials), and permits absent optional capabilities
// (Lifecycle, ModelDiscoverer, UsageFetcher, CredentialRefresher).
func TestRegistryConstructionAcceptsCompleteXAIAndDevin(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{77}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accountRepo := store.NewAccountRepository(database.DB, keys)
	xaiClient := xai.NewClient(xai.HTTPConfig{BaseURL: "https://unused.invalid", RequestTimeout: time.Second, SSEIdleTimeout: time.Second})
	registry, err := provider.NewCapabilityRegistry([]provider.CapabilityRegistration{
		{
			Provider:  provider.XAI,
			PolicyKey: "xai",
			Capabilities: provider.Capabilities{
				Policy:      xai.RequestPolicy{},
				Generation:  xai.NewProviderClient(xaiClient),
				Credentials: oauthxai.NewProviderCredentialManager(accountRepo, nil),
			},
		},
		{
			Provider:  provider.Devin,
			PolicyKey: "devin",
			Capabilities: provider.Capabilities{
				Policy:      devinPassthroughPolicy{},
				Generation:  &noOpGenerationClient{},
				Credentials: oauthdevin.NewProviderCredentialManager(accountRepo),
			},
		},
	})
	if err != nil {
		t.Fatalf("complete xAI+Devin trio rejected: %v", err)
	}
	for _, lookup := range []struct {
		kind     provider.Kind
		key      string
		wantTrio bool
	}{
		{provider.XAI, "xai", true},
		{provider.Devin, "devin", true},
		{provider.XAI, "devin", false},
		{provider.Devin, "xai", false},
	} {
		caps, ok := registry.Capabilities(lookup.kind, lookup.key)
		if lookup.wantTrio {
			if !ok || caps.Policy == nil || caps.Generation == nil || caps.Credentials == nil {
				t.Fatalf("expected complete trio for (%s,%s): ok=%v caps=%+v", lookup.kind, lookup.key, ok, caps)
			}
		} else if ok {
			t.Fatalf("unexpected registration for (%s,%s)", lookup.kind, lookup.key)
		}
	}
}

// TestRegistryConstructionRejectsStaticModelMissingGenerationTrio asserts C9.1:
// any static model whose (Provider, PolicyKey) registration is missing one of
// Policy/Generation/Credentials is rejected at registry construction time.
func TestRegistryConstructionRejectsStaticModelMissingGenerationTrio(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{78}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accountRepo := store.NewAccountRepository(database.DB, keys)
	xaiClient := xai.NewClient(xai.HTTPConfig{BaseURL: "https://unused.invalid", RequestTimeout: time.Second, SSEIdleTimeout: time.Second})
	completeXAI := provider.Capabilities{Policy: xai.RequestPolicy{}, Generation: xai.NewProviderClient(xaiClient), Credentials: oauthxai.NewProviderCredentialManager(accountRepo, nil)}
	completeDevin := provider.Capabilities{Policy: devinPassthroughPolicy{}, Generation: &noOpGenerationClient{}, Credentials: oauthdevin.NewProviderCredentialManager(accountRepo)}
	for _, tc := range []struct {
		name string
		reg  []provider.CapabilityRegistration
	}{
		{name: "xAI missing policy", reg: []provider.CapabilityRegistration{
			{Provider: provider.XAI, PolicyKey: "xai", Capabilities: provider.Capabilities{Generation: completeXAI.Generation, Credentials: completeXAI.Credentials}},
		}},
		{name: "xAI missing generation", reg: []provider.CapabilityRegistration{
			{Provider: provider.XAI, PolicyKey: "xai", Capabilities: provider.Capabilities{Policy: completeXAI.Policy, Credentials: completeXAI.Credentials}},
		}},
		{name: "xAI missing credentials", reg: []provider.CapabilityRegistration{
			{Provider: provider.XAI, PolicyKey: "xai", Capabilities: provider.Capabilities{Policy: completeXAI.Policy, Generation: completeXAI.Generation}},
		}},
		{name: "Devin missing policy", reg: []provider.CapabilityRegistration{
			{Provider: provider.Devin, PolicyKey: "devin", Capabilities: provider.Capabilities{Generation: completeDevin.Generation, Credentials: completeDevin.Credentials}},
		}},
		{name: "Devin missing generation", reg: []provider.CapabilityRegistration{
			{Provider: provider.Devin, PolicyKey: "devin", Capabilities: provider.Capabilities{Policy: completeDevin.Policy, Credentials: completeDevin.Credentials}},
		}},
		{name: "Devin missing credentials", reg: []provider.CapabilityRegistration{
			{Provider: provider.Devin, PolicyKey: "devin", Capabilities: provider.Capabilities{Policy: completeDevin.Policy, Generation: completeDevin.Generation}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := provider.NewCapabilityRegistry(tc.reg); err == nil {
				t.Fatalf("registry accepted incomplete trio: %s", tc.name)
			}
		})
	}
}

// TestRegistryConstructionPermitsAbsentOptionalCapabilities asserts C9.1: a
// registration with only the generation trio (no Lifecycle, ModelDiscoverer,
// UsageFetcher, CredentialRefresher) is accepted.
func TestRegistryConstructionPermitsAbsentOptionalCapabilities(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{79}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accountRepo := store.NewAccountRepository(database.DB, keys)
	xaiClient := xai.NewClient(xai.HTTPConfig{BaseURL: "https://unused.invalid", RequestTimeout: time.Second, SSEIdleTimeout: time.Second})
	registry, err := provider.NewCapabilityRegistry([]provider.CapabilityRegistration{
		{Provider: provider.XAI, PolicyKey: "xai", Capabilities: provider.Capabilities{Policy: xai.RequestPolicy{}, Generation: xai.NewProviderClient(xaiClient), Credentials: oauthxai.NewProviderCredentialManager(accountRepo, nil)}},
		{Provider: provider.Devin, PolicyKey: "devin", Capabilities: provider.Capabilities{Policy: devinPassthroughPolicy{}, Generation: &noOpGenerationClient{}, Credentials: oauthdevin.NewProviderCredentialManager(accountRepo)}},
	})
	if err != nil {
		t.Fatalf("trio-only registration rejected: %v", err)
	}
	xaiCaps, ok := registry.Capabilities(provider.XAI, "xai")
	if !ok || xaiCaps.Lifecycle != nil || xaiCaps.ModelDiscoverer != nil || xaiCaps.UsageFetcher != nil || xaiCaps.CredentialRefresher != nil {
		t.Fatalf("optional capabilities leaked into trio-only xAI registration: %+v", xaiCaps)
	}
	devinCaps, ok := registry.Capabilities(provider.Devin, "devin")
	if !ok || devinCaps.Lifecycle != nil || devinCaps.ModelDiscoverer != nil || devinCaps.UsageFetcher != nil || devinCaps.CredentialRefresher != nil {
		t.Fatalf("optional capabilities leaked into trio-only Devin registration: %+v", devinCaps)
	}
}

// TestPublicCatalogListsAllFiveNamesOnlyWhenProviderRoutable asserts C9.2: with
// both providers' complete trios registered and routable accounts for each
// provider, the public catalog lists exactly the five fixed static names. When
// a provider's capability registration is missing, that provider's static names
// are suppressed from the public listing even when accounts exist.
func TestPublicCatalogListsAllFiveNamesOnlyWhenProviderRoutable(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{81}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accountRepo := store.NewAccountRepository(database.DB, keys)
	for _, account := range []store.Account{xaiRuntimeAccount("five-routable-xai"), devinRuntimeAccount("five-routable-devin")} {
		if _, err := accountRepo.UpsertLogin(ctx, account); err != nil {
			t.Fatal(err)
		}
	}
	static, err := models.NewStaticCatalog(config.Default().Models.Entries)
	if err != nil {
		t.Fatal(err)
	}
	catalog := models.NewCatalog(store.NewModelCapabilityRepository(database.DB), []string{"fast", config.DefaultModel}, map[string]string{"grok": config.DefaultModel, "fast": config.DefaultModel})
	resolver, err := models.NewStaticCatalogOverlay(static, map[string]string{"grok": config.DefaultModel, "fast": config.DefaultModel})
	if err != nil {
		t.Fatal(err)
	}
	cooldowns := store.NewCooldownRepository(database.DB)
	now := func() time.Time { return time.Now().UTC() }

	// Both providers registered: all five names listed.
	both := newPublicCatalog(catalog, static, resolver, accountRepo, cooldowns, now, config.DefaultModel, testCapabilityRegistry(t, accountRepo))
	listed, err := both.PublicModels(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 5 {
		t.Fatalf("both providers: public models=%+v, want five", listed)
	}
	seen := map[string]bool{}
	for _, model := range listed {
		seen[model.ID] = true
	}
	for _, name := range []string{"grok", "grok-4.5", "kimi-k2-7", "glm-5-2", "swe-1-6-slow"} {
		if !seen[name] {
			t.Fatalf("both providers: missing %q in %+v", name, listed)
		}
	}

	// Only xAI registered: Devin static names suppressed, only the two xAI
	// names listed.
	xaiOnly := newPublicCatalog(catalog, static, resolver, accountRepo, cooldowns, now, config.DefaultModel, testCapabilityRegistryFor(t, accountRepo, config.ModelEntry{Provider: config.ProviderXAI, PolicyKey: "xai"}))
	xaiListed, err := xaiOnly.PublicModels(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(xaiListed) != 2 {
		t.Fatalf("xAI-only: public models=%+v, want two xAI names", xaiListed)
	}
	for _, model := range xaiListed {
		if model.ID != "grok" && model.ID != "grok-4.5" {
			t.Fatalf("xAI-only: Devin name leaked into listing: %+v", xaiListed)
		}
	}

	// Only Devin registered: xAI static names suppressed, only the three Devin
	// names listed.
	devinOnly := newPublicCatalog(catalog, static, resolver, accountRepo, cooldowns, now, "kimi-k2-7", testCapabilityRegistryFor(t, accountRepo, config.ModelEntry{Provider: config.ProviderDevin, PolicyKey: "devin"}))
	devinListed, err := devinOnly.PublicModels(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(devinListed) != 3 {
		t.Fatalf("Devin-only: public models=%+v, want three Devin names", devinListed)
	}
	for _, model := range devinListed {
		if model.ID != "kimi-k2-7" && model.ID != "glm-5-2" && model.ID != "swe-1-6-slow" {
			t.Fatalf("Devin-only: xAI name leaked into listing: %+v", devinListed)
		}
	}

	// No registry: nothing listed.
	none := newPublicCatalog(catalog, static, resolver, accountRepo, cooldowns, now, config.DefaultModel, nil)
	noneListed, err := none.PublicModels(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(noneListed) != 0 {
		t.Fatalf("nil registry: public models=%+v, want none", noneListed)
	}
}

// TestReadinessFollowsDevinDefaultAccountAndCapabilities asserts C9.2: when the
// default model is a Devin static model, readiness follows the Devin account's
// resolved-provider usable state and the runtime Devin capability registration.
// With no Devin account, readiness is false; with a usable Devin account and
// the Devin trio registered, readiness is true. With the Devin trio missing,
// readiness is false even when a Devin account exists.
func TestReadinessFollowsDevinDefaultAccountAndCapabilities(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{82}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accountRepo := store.NewAccountRepository(database.DB, keys)
	static, err := models.NewStaticCatalog(config.Default().Models.Entries)
	if err != nil {
		t.Fatal(err)
	}
	catalog := models.NewCatalog(store.NewModelCapabilityRepository(database.DB), []string{"kimi-k2-7"}, nil)
	resolver, err := models.NewStaticCatalogOverlay(static, nil)
	if err != nil {
		t.Fatal(err)
	}
	cooldowns := store.NewCooldownRepository(database.DB)
	now := func() time.Time { return time.Now().UTC() }

	// No Devin account: readiness false even with Devin trio registered.
	noAccount := newPublicCatalog(catalog, static, resolver, accountRepo, cooldowns, now, "kimi-k2-7", testCapabilityRegistry(t, accountRepo))
	if ready, err := noAccount.Ready(ctx); err != nil || ready {
		t.Fatalf("no Devin account: ready=%v err=%v", ready, err)
	}

	// Usable Devin account + Devin trio registered: readiness true.
	devinAccount, err := accountRepo.UpsertLogin(ctx, devinRuntimeAccount("readiness-devin"))
	if err != nil {
		t.Fatal(err)
	}
	_ = devinAccount
	withAccount := newPublicCatalog(catalog, static, resolver, accountRepo, cooldowns, now, "kimi-k2-7", testCapabilityRegistry(t, accountRepo))
	if ready, err := withAccount.Ready(ctx); err != nil || !ready {
		t.Fatalf("usable Devin account + trio: ready=%v err=%v", ready, err)
	}

	// Devin trio missing: readiness false even with usable Devin account.
	xaiOnlyRegistry := testCapabilityRegistryFor(t, accountRepo, config.ModelEntry{Provider: config.ProviderXAI, PolicyKey: "xai"})
	missingTrio := newPublicCatalog(catalog, static, resolver, accountRepo, cooldowns, now, "kimi-k2-7", xaiOnlyRegistry)
	if ready, err := missingTrio.Ready(ctx); err != nil || ready {
		t.Fatalf("Devin trio missing: ready=%v err=%v", ready, err)
	}

	// Nil registry: readiness false.
	nilRegistry := newPublicCatalog(catalog, static, resolver, accountRepo, cooldowns, now, "kimi-k2-7", nil)
	if ready, err := nilRegistry.Ready(ctx); err != nil || ready {
		t.Fatalf("nil registry: ready=%v err=%v", ready, err)
	}
}

// TestReadinessFollowsXAIAndDevinDefaultsSymmetrically asserts C9.2: readiness
// resolves the default model's actual provider. An xAI default requires an xAI
// account + xAI trio; a Devin default requires a Devin account + Devin trio.
// A Devin account alone must not satisfy an xAI default, and vice versa.
func TestReadinessFollowsXAIAndDevinDefaultsSymmetrically(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{83}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accountRepo := store.NewAccountRepository(database.DB, keys)
	static, err := models.NewStaticCatalog(config.Default().Models.Entries)
	if err != nil {
		t.Fatal(err)
	}
	catalog := models.NewCatalog(store.NewModelCapabilityRepository(database.DB), []string{config.DefaultModel, "kimi-k2-7"}, map[string]string{"grok": config.DefaultModel})
	resolver, err := models.NewStaticCatalogOverlay(static, map[string]string{"grok": config.DefaultModel})
	if err != nil {
		t.Fatal(err)
	}
	cooldowns := store.NewCooldownRepository(database.DB)
	now := func() time.Time { return time.Now().UTC() }
	registry := testCapabilityRegistry(t, accountRepo)

	// Only a Devin account: xAI default not ready, Devin default ready.
	if _, err := accountRepo.UpsertLogin(ctx, devinRuntimeAccount("symmetric-devin")); err != nil {
		t.Fatal(err)
	}
	xaiDefault := newPublicCatalog(catalog, static, resolver, accountRepo, cooldowns, now, config.DefaultModel, registry)
	if ready, err := xaiDefault.Ready(ctx); err != nil || ready {
		t.Fatalf("xAI default with only Devin account: ready=%v err=%v", ready, err)
	}
	devinDefault := newPublicCatalog(catalog, static, resolver, accountRepo, cooldowns, now, "kimi-k2-7", registry)
	if ready, err := devinDefault.Ready(ctx); err != nil || !ready {
		t.Fatalf("Devin default with Devin account: ready=%v err=%v", ready, err)
	}

	// Add an xAI account: xAI default becomes ready.
	if _, err := accountRepo.UpsertLogin(ctx, xaiRuntimeAccount("symmetric-xai")); err != nil {
		t.Fatal(err)
	}
	xaiDefaultWithXAI := newPublicCatalog(catalog, static, resolver, accountRepo, cooldowns, now, config.DefaultModel, registry)
	if ready, err := xaiDefaultWithXAI.Ready(ctx); err != nil || !ready {
		t.Fatalf("xAI default with xAI account: ready=%v err=%v", ready, err)
	}
}

// TestPublicCatalogSuppressesUnroutableProviderViaCapabilityGate asserts C9.2:
// a static model whose provider has a complete trio registered but no routable
// account is suppressed from the public listing, while a provider with a
// routable account is listed. This guards against listing a model name when the
// provider is not actually routable at runtime.
func TestPublicCatalogSuppressesUnroutableProviderViaCapabilityGate(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{84}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accountRepo := store.NewAccountRepository(database.DB, keys)
	// Only an xAI account exists.
	if _, err := accountRepo.UpsertLogin(ctx, xaiRuntimeAccount("suppress-devin-xai")); err != nil {
		t.Fatal(err)
	}
	static, err := models.NewStaticCatalog(config.Default().Models.Entries)
	if err != nil {
		t.Fatal(err)
	}
	catalog := models.NewCatalog(store.NewModelCapabilityRepository(database.DB), []string{config.DefaultModel}, map[string]string{"grok": config.DefaultModel})
	resolver, err := models.NewStaticCatalogOverlay(static, map[string]string{"grok": config.DefaultModel})
	if err != nil {
		t.Fatal(err)
	}
	projection := newPublicCatalog(catalog, static, resolver, accountRepo, store.NewCooldownRepository(database.DB), func() time.Time { return time.Now().UTC() }, config.DefaultModel, testCapabilityRegistry(t, accountRepo))
	listed, err := projection.PublicModels(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 {
		t.Fatalf("public models=%+v, want only the two xAI names (no routable Devin account)", listed)
	}
	for _, model := range listed {
		if model.ID != "grok" && model.ID != "grok-4.5" {
			t.Fatalf("Devin name listed without routable Devin account: %+v", listed)
		}
	}
}

// countingUsabilityCredentialManager wraps a production provider.
// CredentialManager and counts CredentialUsable calls per account, proving the
// catalog invokes the same CredentialUsability contract as Executor.candidates
// rather than a duplicated expiry branch.
type countingUsabilityCredentialManager struct {
	delegate provider.CredentialManager
	usable   map[string]int
}

func (m *countingUsabilityCredentialManager) Credential(ctx context.Context, accountID string) (provider.Credential, error) {
	return m.delegate.Credential(ctx, accountID)
}

func (m *countingUsabilityCredentialManager) AuthenticationFailed(ctx context.Context, accountID string, upstream *provider.UpstreamError) error {
	return m.delegate.AuthenticationFailed(ctx, accountID, upstream)
}

func (m *countingUsabilityCredentialManager) CredentialUsable(ctx context.Context, accountID string) (bool, error) {
	if m.usable == nil {
		m.usable = make(map[string]int)
	}
	m.usable[accountID]++
	return m.delegate.(provider.CredentialUsability).CredentialUsable(ctx, accountID)
}

func (m *countingUsabilityCredentialManager) usabilityCount(accountID string) int {
	return m.usable[accountID]
}

// testCountingCapabilityRegistry builds a RuntimeCapabilityRegistry whose
// Credentials are countingUsabilityCredentialManager wrappers around the real
// production provider credential managers (oauthdevin.NewProviderCredentialManager
// and oauthxai.NewProviderCredentialManager). This proves the catalog invokes
// production provider serialization/builders through the CredentialUsability
// contract, not a fake or duplicated expiry branch.
func testCountingCapabilityRegistry(t *testing.T, accounts *store.AccountRepository) (*provider.RuntimeCapabilityRegistry, *countingUsabilityCredentialManager, *countingUsabilityCredentialManager) {
	t.Helper()
	xaiClient := xai.NewClient(xai.HTTPConfig{BaseURL: "https://unused.invalid", RequestTimeout: time.Second, SSEIdleTimeout: time.Second})
	xaiCounter := &countingUsabilityCredentialManager{delegate: oauthxai.NewProviderCredentialManager(accounts, nil)}
	devinCounter := &countingUsabilityCredentialManager{delegate: oauthdevin.NewProviderCredentialManager(accounts)}
	registry, err := provider.NewCapabilityRegistry([]provider.CapabilityRegistration{
		{Provider: provider.XAI, PolicyKey: "xai", Capabilities: provider.Capabilities{
			Policy: xai.RequestPolicy{}, Generation: xai.NewProviderClient(xaiClient), Credentials: xaiCounter,
		}},
		{Provider: provider.Devin, PolicyKey: "devin", Capabilities: provider.Capabilities{
			Policy: devinPassthroughPolicy{}, Generation: &noOpGenerationClient{}, Credentials: devinCounter,
		}},
	})
	if err != nil {
		t.Fatalf("build counting capability registry: %v", err)
	}
	return registry, xaiCounter, devinCounter
}

// TestReadinessDevinNilExpiryFailsClosedAndTransitionsRelogin asserts that a
// Devin durable row with a nil account-level ExpiresAt is not admitted to
// readiness or listing, and that the real Devin CredentialManager transitions
// the account to relogin_required as a side effect of the usability projection.
// The prior duplicated opaque-token expiry branch admitted such rows by checking
// Credentials.OpaqueTokenExpiresAt instead of account.ExpiresAt; the refactored
// catalog delegates to provider.CredentialUsability and matches the real Devin
// CredentialManager behavior (which uses account.ExpiresAt and calls
// MarkReloginRequired when unusable).
func TestReadinessDevinNilExpiryFailsClosedAndTransitionsRelogin(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{91}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accountRepo := store.NewAccountRepository(database.DB, keys)
	// Devin account with a valid opaque token but nil account-level ExpiresAt.
	// The real Devin CredentialManager treats nil ExpiresAt as not usable.
	nilExpiryAccount, err := accountRepo.UpsertLogin(ctx, store.Account{
		Provider:    provider.Devin,
		Status:      "ready",
		Credentials: store.AccountCredentials{OpaqueToken: "nil-expiry-devin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	static, err := models.NewStaticCatalog(config.Default().Models.Entries)
	if err != nil {
		t.Fatal(err)
	}
	catalog := models.NewCatalog(store.NewModelCapabilityRepository(database.DB), []string{"kimi-k2-7"}, nil)
	resolver, err := models.NewStaticCatalogOverlay(static, nil)
	if err != nil {
		t.Fatal(err)
	}
	cooldowns := store.NewCooldownRepository(database.DB)
	now := func() time.Time { return time.Now().UTC() }
	registry, _, devinCounter := testCountingCapabilityRegistry(t, accountRepo)
	projection := newPublicCatalog(catalog, static, resolver, accountRepo, cooldowns, now, "kimi-k2-7", registry)

	// Readiness must fail closed: nil ExpiresAt means the real Devin
	// CredentialManager cannot project usability.
	if ready, err := projection.Ready(ctx); err != nil || ready {
		t.Fatalf("nil ExpiresAt: ready=%v err=%v", ready, err)
	}

	// The catalog invoked the real Devin CredentialManager's CredentialUsable
	// exactly once for the provider-matched account.
	if got := devinCounter.usabilityCount(nilExpiryAccount.ID); got != 1 {
		t.Fatalf("Devin CredentialUsable calls=%d want=1", got)
	}

	// The real Devin CredentialManager transitions the account to
	// relogin_required as a side effect of the unusable projection.
	stored, err := accountRepo.Get(ctx, nilExpiryAccount.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "relogin_required" || stored.Enabled {
		t.Fatalf("nil ExpiresAt did not transition relogin: status=%q enabled=%v", stored.Status, stored.Enabled)
	}

	// Public listing must not include Devin models when no usable Devin account exists.
	listed, err := projection.PublicModels(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, model := range listed {
		if model.ID == "kimi-k2-7" || model.ID == "glm-5-2" || model.ID == "swe-1-6-slow" {
			t.Fatalf("Devin model listed with nil-expiry account: %+v", listed)
		}
	}
}

// TestReadinessDevinExpiredExpiryFailsClosedAndTransitionsRelogin asserts that
// a Devin durable row with a past account-level ExpiresAt is not admitted to
// readiness, and the real Devin CredentialManager transitions it to
// relogin_required. The mismatched Credentials.OpaqueTokenExpiresAt field is
// intentionally set to a future time to prove the catalog no longer consults
// that field — only the real Devin CredentialManager's account.ExpiresAt
// matters.
func TestReadinessDevinExpiredExpiryFailsClosedAndTransitionsRelogin(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{92}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accountRepo := store.NewAccountRepository(database.DB, keys)
	pastExpiry := time.Now().Add(-time.Hour).UTC()
	futureOpaqueExpiry := time.Now().Add(time.Hour).UTC()
	expiredAccount, err := accountRepo.UpsertLogin(ctx, store.Account{
		Provider:  provider.Devin,
		Status:    "ready",
		ExpiresAt: &pastExpiry,
		// OpaqueTokenExpiresAt is deliberately future to prove the catalog no
		// longer consults this duplicated field.
		Credentials: store.AccountCredentials{OpaqueToken: "expired-devin", OpaqueTokenExpiresAt: &futureOpaqueExpiry},
	})
	if err != nil {
		t.Fatal(err)
	}
	static, err := models.NewStaticCatalog(config.Default().Models.Entries)
	if err != nil {
		t.Fatal(err)
	}
	catalog := models.NewCatalog(store.NewModelCapabilityRepository(database.DB), []string{"kimi-k2-7"}, nil)
	resolver, err := models.NewStaticCatalogOverlay(static, nil)
	if err != nil {
		t.Fatal(err)
	}
	cooldowns := store.NewCooldownRepository(database.DB)
	now := func() time.Time { return time.Now().UTC() }
	registry, _, devinCounter := testCountingCapabilityRegistry(t, accountRepo)
	projection := newPublicCatalog(catalog, static, resolver, accountRepo, cooldowns, now, "kimi-k2-7", registry)

	if ready, err := projection.Ready(ctx); err != nil || ready {
		t.Fatalf("expired ExpiresAt with future OpaqueTokenExpiresAt: ready=%v err=%v", ready, err)
	}
	if got := devinCounter.usabilityCount(expiredAccount.ID); got != 1 {
		t.Fatalf("Devin CredentialUsable calls=%d want=1", got)
	}
	stored, err := accountRepo.Get(ctx, expiredAccount.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "relogin_required" || stored.Enabled {
		t.Fatalf("expired ExpiresAt did not transition relogin: status=%q enabled=%v", stored.Status, stored.Enabled)
	}
}

// TestReadinessXAIEmptyTokenFailsClosedWithoutReloginTransition asserts that an
// xAI account with an empty AccessToken is not admitted to readiness, and the
// real xAI CredentialManager does NOT transition the account to relogin — it
// simply returns false. This matches the prior behavior and confirms xAI is
// unchanged by the refactor.
func TestReadinessXAIEmptyTokenFailsClosedWithoutReloginTransition(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{93}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accountRepo := store.NewAccountRepository(database.DB, keys)
	// xAI account with valid issuer/subject but no AccessToken: the real xAI
	// CredentialManager projects not-usable without a relogin transition.
	emptyTokenAccount, err := accountRepo.UpsertLogin(ctx, store.Account{
		Provider:    provider.XAI,
		Status:      "ready",
		Credentials: store.AccountCredentials{Issuer: "issuer", Subject: "empty-token-xai"},
	})
	if err != nil {
		t.Fatal(err)
	}
	static, err := models.NewStaticCatalog(config.Default().Models.Entries)
	if err != nil {
		t.Fatal(err)
	}
	catalog := models.NewCatalog(store.NewModelCapabilityRepository(database.DB), []string{config.DefaultModel}, map[string]string{"grok": config.DefaultModel})
	resolver, err := models.NewStaticCatalogOverlay(static, map[string]string{"grok": config.DefaultModel})
	if err != nil {
		t.Fatal(err)
	}
	cooldowns := store.NewCooldownRepository(database.DB)
	now := func() time.Time { return time.Now().UTC() }
	registry, xaiCounter, _ := testCountingCapabilityRegistry(t, accountRepo)
	projection := newPublicCatalog(catalog, static, resolver, accountRepo, cooldowns, now, config.DefaultModel, registry)

	if ready, err := projection.Ready(ctx); err != nil || ready {
		t.Fatalf("empty xAI token: ready=%v err=%v", ready, err)
	}
	if got := xaiCounter.usabilityCount(emptyTokenAccount.ID); got != 1 {
		t.Fatalf("xAI CredentialUsable calls=%d want=1", got)
	}
	stored, err := accountRepo.Get(ctx, emptyTokenAccount.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "ready" || !stored.Enabled {
		t.Fatalf("xAI empty token mutated account: status=%q enabled=%v", stored.Status, stored.Enabled)
	}
}

// TestReadinessCountsCredentialUsableOnlyForProviderMatchedAccounts asserts
// that the catalog invokes CredentialUsable only on provider-matched accounts.
// When the default model is a Devin model, only the Devin account's
// CredentialUsable is called; the xAI account is skipped by the provider
// filter before the usability projection runs. This directly counts credential
// calls and proves the catalog uses the same provider-matched CredentialUsability
// contract as Executor.candidates.
func TestReadinessCountsCredentialUsableOnlyForProviderMatchedAccounts(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{94}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accountRepo := store.NewAccountRepository(database.DB, keys)
	xaiAccount, err := accountRepo.UpsertLogin(ctx, xaiRuntimeAccount("counting-xai"))
	if err != nil {
		t.Fatal(err)
	}
	devinAccount, err := accountRepo.UpsertLogin(ctx, devinRuntimeAccount("counting-devin"))
	if err != nil {
		t.Fatal(err)
	}
	static, err := models.NewStaticCatalog(config.Default().Models.Entries)
	if err != nil {
		t.Fatal(err)
	}
	catalog := models.NewCatalog(store.NewModelCapabilityRepository(database.DB), []string{"kimi-k2-7"}, nil)
	resolver, err := models.NewStaticCatalogOverlay(static, nil)
	if err != nil {
		t.Fatal(err)
	}
	cooldowns := store.NewCooldownRepository(database.DB)
	now := func() time.Time { return time.Now().UTC() }
	registry, xaiCounter, devinCounter := testCountingCapabilityRegistry(t, accountRepo)
	devinDefault := newPublicCatalog(catalog, static, resolver, accountRepo, cooldowns, now, "kimi-k2-7", registry)

	if ready, err := devinDefault.Ready(ctx); err != nil || !ready {
		t.Fatalf("Devin default with usable Devin account: ready=%v err=%v", ready, err)
	}
	// The Devin account's CredentialUsable was called exactly once.
	if got := devinCounter.usabilityCount(devinAccount.ID); got != 1 {
		t.Fatalf("Devin CredentialUsable calls=%d want=1", got)
	}
	// The xAI account's CredentialUsable was never called: the provider filter
	// skips mismatched accounts before the usability projection runs.
	if got := xaiCounter.usabilityCount(xaiAccount.ID); got != 0 {
		t.Fatalf("xAI CredentialUsable calls=%d want=0 (provider mismatch)", got)
	}
}

// TestRuntimeConstructionValidatesStaticCatalogCapabilities asserts C9.1 at the
// runtime composition boundary: New() fails when a static catalog's
// (Provider, PolicyKey) pair lacks a matching RuntimeCapabilityRegistry entry
// with the complete generation trio. This is the production startup gate that
// prevents advertising a static model without exact runtime generation support.
func TestRuntimeConstructionValidatesStaticCatalogCapabilities(t *testing.T) {
	t.Setenv("BYOS_MASTER_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{85}, 32)))
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
		t.Fatalf("production runtime rejected complete static catalog: %v", err)
	}
	defer runtime.Close()
	// Every fixed static model must resolve to a complete trio in the runtime
	// registry, so all five names pass the capability gate when accounts exist.
	static, err := models.NewStaticCatalog(cfg.Models.Entries)
	if err != nil {
		t.Fatal(err)
	}
	for _, resolved := range static.Models() {
		caps, ok := runtime.capabilityRegistry.Capabilities(resolved.Provider, resolved.PolicyKey)
		if !ok || caps.Policy == nil || caps.Generation == nil || caps.Credentials == nil {
			t.Fatalf("static model %q lacks complete runtime trio: ok=%v caps=%+v", resolved.PublicName, ok, caps)
		}
	}
}

// TestRuntimeReadinessEndpointReportsDevinDefaultReady asserts C9.2 end-to-end
// through the /readyz HTTP handler: when the default model is a Devin static
// model and a usable Devin account exists, /readyz returns 200; without a Devin
// account it returns 503.
func TestRuntimeReadinessEndpointReportsDevinDefaultReady(t *testing.T) {
	t.Setenv("BYOS_MASTER_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{86}, 32)))
	t.Setenv("BYOS_ADMIN_PASSWORD", "password")
	t.Setenv("BYOS_ADMIN_API_KEY", "admin-key")
	secrets, err := config.LoadSecrets()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	// Configure a Devin default through the allowlist surface.
	cfg.Models.Default = "kimi-k2-7"
	cfg.Models.Allowlist = []string{"kimi-k2-7"}
	runtime, err := New(t.Context(), cfg, secrets, nil)
	if err != nil {
		t.Fatalf("runtime with Devin default rejected: %v", err)
	}
	defer runtime.Close()

	// No Devin account: /readyz 503.
	response := httptest.NewRecorder()
	runtime.Server.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz without Devin account=%d, want 503", response.Code)
	}

	// Insert a usable Devin account through the account repository backed by
	// the runtime's database and the derived keys.
	ctx := context.Background()
	masterKey := secrets.MasterKey()
	keys, err := appcrypto.DeriveKeys(masterKey[:])
	if err != nil {
		t.Fatal(err)
	}
	accountRepo := store.NewAccountRepository(runtime.Store.DB, keys)
	if _, err := accountRepo.UpsertLogin(ctx, devinRuntimeAccount("readyz-devin")); err != nil {
		t.Fatal(err)
	}
	response2 := httptest.NewRecorder()
	runtime.Server.Handler.ServeHTTP(response2, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response2.Code != http.StatusOK {
		t.Fatalf("readyz with usable Devin account=%d, want 200", response2.Code)
	}
}

// c9fakeLifecycle is a no-op AccountLifecycle used to register a lifecycle-only
// capability (no generation trio) for the negative validateStaticCatalogCapabilities
// test. NewCapabilityRegistry accepts a lifecycle-only registration because
// Lifecycle is a valid optional capability; validateStaticCatalogCapabilities
// must then reject it for any static model that references that (Provider,
// PolicyKey) pair, since the generation trio is absent.
type c9fakeLifecycle struct{}

func (c9fakeLifecycle) Start(context.Context) (provider.Authorization, error) {
	return provider.Authorization{}, nil
}
func (c9fakeLifecycle) Status(context.Context, provider.AuthorizationRef) (provider.AuthorizationSession, error) {
	return provider.AuthorizationSession{}, nil
}
func (c9fakeLifecycle) Complete(context.Context, provider.AuthorizationRef, provider.AuthorizationCompletion) (provider.AccountResult, error) {
	return provider.AccountResult{}, nil
}
func (c9fakeLifecycle) Cancel(context.Context, provider.AuthorizationRef) error { return nil }
func (c9fakeLifecycle) Resume(context.Context) ([]provider.AuthorizationSession, error) {
	return nil, nil
}

// TestValidateStaticCatalogCapabilitiesRejectsAbsentExactRegistration asserts
// C9.1: validateStaticCatalogCapabilities fails with ErrInvalidCapabilities
// when a static catalog (Provider, PolicyKey) pair has no matching
// RuntimeCapabilityRegistry entry. The production static catalog carries xAI
// entries, but the registry registers only Devin, so every xAI static model
// references an unregistered capability.
func TestValidateStaticCatalogCapabilitiesRejectsAbsentExactRegistration(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{87}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accountRepo := store.NewAccountRepository(database.DB, keys)
	static, err := models.NewStaticCatalog(config.Default().Models.Entries)
	if err != nil {
		t.Fatal(err)
	}
	// Registry registers only Devin; xAI static entries have no matching entry.
	registry, err := provider.NewCapabilityRegistry([]provider.CapabilityRegistration{
		{Provider: provider.Devin, PolicyKey: "devin", Capabilities: provider.Capabilities{
			Policy: devinPassthroughPolicy{}, Generation: &noOpGenerationClient{}, Credentials: oauthdevin.NewProviderCredentialManager(accountRepo),
		}},
	})
	if err != nil {
		t.Fatalf("build devin-only registry: %v", err)
	}
	err = validateStaticCatalogCapabilities(static, registry)
	if !errors.Is(err, provider.ErrInvalidCapabilities) {
		t.Fatalf("absent xAI registration: err=%v, want ErrInvalidCapabilities", err)
	}
}

// TestValidateStaticCatalogCapabilitiesRejectsLifecycleOnlyMissingTrio asserts
// C9.1: validateStaticCatalogCapabilities fails with ErrInvalidCapabilities
// when a static catalog entry's registry registration carries only optional
// capabilities (Lifecycle) and is missing the complete generation trio
// (Policy, Generation, Credentials). NewCapabilityRegistry accepts the
// lifecycle-only registration, but the startup gate must reject it because the
// static model cannot be served without the generation trio.
func TestValidateStaticCatalogCapabilitiesRejectsLifecycleOnlyMissingTrio(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{88}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accountRepo := store.NewAccountRepository(database.DB, keys)
	static, err := models.NewStaticCatalog(config.Default().Models.Entries)
	if err != nil {
		t.Fatal(err)
	}
	// xAI registered with Lifecycle only (no Policy/Generation/Credentials).
	// Devin registered with the complete trio so the first xAI static entry is
	// the one that triggers the rejection.
	registry, err := provider.NewCapabilityRegistry([]provider.CapabilityRegistration{
		{Provider: provider.XAI, PolicyKey: "xai", Capabilities: provider.Capabilities{Lifecycle: c9fakeLifecycle{}}},
		{Provider: provider.Devin, PolicyKey: "devin", Capabilities: provider.Capabilities{
			Policy: devinPassthroughPolicy{}, Generation: &noOpGenerationClient{}, Credentials: oauthdevin.NewProviderCredentialManager(accountRepo),
		}},
	})
	if err != nil {
		t.Fatalf("build lifecycle-only registry: %v", err)
	}
	err = validateStaticCatalogCapabilities(static, registry)
	if !errors.Is(err, provider.ErrInvalidCapabilities) {
		t.Fatalf("lifecycle-only xAI: err=%v, want ErrInvalidCapabilities", err)
	}
}
