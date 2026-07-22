//go:build smoke

// Package app contains the C12 launched smoke harness. It is gated behind the
// `smoke` build tag so ordinary `go test` never invokes git, builds prior
// binaries, or touches the network. Run with:
//
//	go test -tags smoke -race -run TestC12SmokeHarness ./internal/app -timeout 300s
//
// The harness composes the real production component graph in-process with
// fake provider lifecycle/generation clients injected at approved network
// boundaries. It completes both xAI device and Devin callback logins into a
// real temp SQLite DB, serves real HTTP handlers, exercises both providers
// across Chat/Responses/Anthropic stream+non-stream with call-ledger
// assertions, restarts/reopens the runtime, and proves a pre-v5 binary opens
// and serves a restored v4 backup via `git archive` (not worktree mutation).
package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	_ "modernc.org/sqlite"

	"byos/internal/accounts"
	"byos/internal/api"
	admin "byos/internal/api/admin"
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
	"byos/migrations"
)

// ---------------------------------------------------------------------------
// Fake xAI OAuth issuer
// ---------------------------------------------------------------------------

// smokeFakeIssuer is a local HTTPS-free HTTP server that masquerades as
// auth.x.ai: it serves the OpenID discovery document, JWKS, device
// authorization, and token endpoints. ID tokens are ES256-signed and
// verifiable by the real oauthxai.IdentityVerifier via a host-rewriting
// transport.
type smokeFakeIssuer struct {
	server *httptest.Server
	key    *ecdsa.PrivateKey
	kid    string
	t      *testing.T
}

func newSmokeFakeIssuer(t *testing.T) *smokeFakeIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ES256 key: %v", err)
	}
	issuer := &smokeFakeIssuer{key: key, kid: "smoke-es256", t: t}
	issuer.server = httptest.NewServer(http.HandlerFunc(issuer.handle))
	t.Cleanup(issuer.server.Close)
	return issuer
}

func (f *smokeFakeIssuer) baseURL() string { return f.server.URL }

func (f *smokeFakeIssuer) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		doc := map[string]any{
			"issuer":                                oauthxai.Issuer,
			"authorization_endpoint":                oauthxai.Issuer + "/authorize",
			"device_authorization_endpoint":         oauthxai.Issuer + "/device_auth",
			"token_endpoint":                        oauthxai.Issuer + "/token",
			"jwks_uri":                              oauthxai.Issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"ES256"},
			"response_types_supported":              []string{"token"},
			"grant_types_supported":                 []string{"device_code", "refresh_token"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	case "/jwks":
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &f.key.PublicKey, KeyID: f.kid, Algorithm: string(jose.ES256), Use: "sig"},
		}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	case "/device_auth":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":      "smoke-device-code",
			"user_code":        "SMOKE",
			"verification_uri": oauthxai.Issuer + "/device",
			"expires_in":       300,
			"interval":         1,
		})
	case "/token":
		idToken := f.signIDToken(f.t)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "smoke-xai-access",
			"refresh_token": "smoke-xai-refresh",
			"id_token":      idToken,
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *smokeFakeIssuer) signIDToken(t *testing.T) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: f.key, KeyID: f.kid, Algorithm: string(jose.ES256), Use: "sig"}}, nil)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	claims := map[string]any{
		"iss":   oauthxai.Issuer,
		"aud":   oauthxai.DefaultClientID,
		"sub":   "smoke-xai-subject",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"email": "smoke@xai.example.com",
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign id token: %v", err)
	}
	return raw
}

// ---------------------------------------------------------------------------
// Host-rewriting transport
// ---------------------------------------------------------------------------

// smokeHostTransport rewrites requests to approved upstream hosts to a local
// httptest server. It preserves the path and query while replacing the scheme
// and host. This is the approved seam: the real oauthxai/oauthdevin clients
// still target production URLs (https://auth.x.ai, https://api.devin.ai) but
// the transport transparently redirects to local fakes.
type smokeHostTransport struct {
	base     http.RoundTripper
	rewrites map[string]*url.URL // host → local URL
}

func newSmokeHostTransport() *smokeHostTransport {
	return &smokeHostTransport{base: http.DefaultTransport.(*http.Transport).Clone()}
}

func (t *smokeHostTransport) rewrite(host string, target *url.URL) {
	if t.rewrites == nil {
		t.rewrites = make(map[string]*url.URL)
	}
	t.rewrites[host] = target
}

func (t *smokeHostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	target, ok := t.rewrites[req.URL.Host]
	if !ok {
		// Fail-closed: only hosts explicitly rewritten to a loopback fixture
		// may proceed. Any other host (production endpoint, stray DNS target,
		// newly introduced upstream) is rejected without dialing so the
		// deterministic local smoke can never reach the public network.
		return nil, fmt.Errorf("smoke transport: host %q is not rewritten to a local fixture; refusing to dial", req.URL.Host)
	}
	clone := req.Clone(req.Context())
	clone.URL.Scheme = target.Scheme
	clone.URL.Host = target.Host
	return t.base.RoundTrip(clone)
}

func (t *smokeHostTransport) client() *http.Client {
	return &http.Client{Transport: t, Timeout: 30 * time.Second}
}

// ---------------------------------------------------------------------------
// Fake Devin token exchange endpoint
// ---------------------------------------------------------------------------

// smokeDevinExchange is a local server masquerading as api.devin.ai's token
// exchange endpoint. It returns an opaque token on every exchange.
type smokeDevinExchange struct {
	server *httptest.Server
	mu     sync.Mutex
	calls  int
}

func newSmokeDevinExchange(t *testing.T) *smokeDevinExchange {
	t.Helper()
	exchange := &smokeDevinExchange{}
	exchange.server = httptest.NewServer(http.HandlerFunc(exchange.handle))
	t.Cleanup(exchange.server.Close)
	return exchange
}

func (e *smokeDevinExchange) handle(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	e.calls++
	e.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token": "smoke-devin-opaque-token",
	})
}

func (e *smokeDevinExchange) callCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls
}

// ---------------------------------------------------------------------------
// Call ledger + recording generation clients
// ---------------------------------------------------------------------------

type smokeLedgerEntry struct {
	protocol      string // "chat", "responses", or "anthropic"
	provider      provider.Kind
	publicModel   string // resolved public model name (alias preserved)
	upstreamModel string // resolved upstream model name
	policyKey     string // provider policy key
	stream        bool
	xSearch       bool // xAI injects an x_search tool; Devin never does
}

// smokeXSearchPresent reports whether the policy-prepared canonical request
// carries an x_search tool, the xAI backend-search invariant. Devin's policy
// never injects one, so this is false for every Devin call.
func smokeXSearchPresent(canonical provider.CanonicalRequest) bool {
	tools, ok := canonical["tools"].([]any)
	if !ok {
		return false
	}
	for _, raw := range tools {
		if item, ok := raw.(map[string]any); ok {
			if item["type"] == "x_search" {
				return true
			}
		}
	}
	return false
}

// smokeProtocolKey tags a request context with the originating protocol so the
// recording generation client can ledger which API surface dispatched the call.
type smokeProtocolKey struct{}

func withSmokeProtocol(ctx context.Context, protocol string) context.Context {
	return context.WithValue(ctx, smokeProtocolKey{}, protocol)
}

func smokeProtocolFrom(ctx context.Context) string {
	if v, ok := ctx.Value(smokeProtocolKey{}).(string); ok {
		return v
	}
	return ""
}

type smokeLedger struct {
	mu      sync.Mutex
	entries []smokeLedgerEntry
}

func (l *smokeLedger) record(e smokeLedgerEntry) {
	l.mu.Lock()
	l.entries = append(l.entries, e)
	l.mu.Unlock()
}

func (l *smokeLedger) count(predicate func(smokeLedgerEntry) bool) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	count := 0
	for _, e := range l.entries {
		if predicate(e) {
			count++
		}
	}
	return count
}

// snapshot returns a defensive copy of the recorded entries in dispatch order
// so callers can assert an exact, ordered ledger without racing the recorder.
func (l *smokeLedger) snapshot() []smokeLedgerEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]smokeLedgerEntry(nil), l.entries...)
}

func (l *smokeLedger) reset() {
	l.mu.Lock()
	l.entries = nil
	l.mu.Unlock()
}

// smokeCompletedEvent returns a provider-neutral response.completed event that
// all three translators (Chat, Responses, Anthropic) can parse. The response id
// is unique per call so stored (store=true) Responses requests never collide on
// the response_sessions primary key.
func smokeCompletedEvent(id string) provider.Event {
	tmpl := `{"type":"response.completed","response":{"id":"%s","model":"smoke","created_at":1,"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"smoke answer"}]}],"usage":{"input_tokens":3,"output_tokens":4,"total_tokens":7}}}`
	return provider.Event{Data: []byte(fmt.Sprintf(tmpl, id))}
}

// smokeRecordingClient is the fake generation client injected at the provider
// network boundary. It records every Execute/Stream call into the ledger
// (protocol, provider, public/upstream model, policy key, stream mode, x_search
// presence) and returns a deterministic completed event with a unique response
// id so cross-restart Responses continuation can chain distinct stored nodes.
type smokeRecordingClient struct {
	kind    provider.Kind
	ledger  *smokeLedger
	counter uint64
}

// nextResponseID returns a unique response id for each generation call so
// stored (store=true) Responses requests never collide on the
// response_sessions primary key. The seed subtest captures the actual id from
// the response body and uses it as the continuation anchor.
func (c *smokeRecordingClient) nextResponseID() string {
	return fmt.Sprintf("resp_smoke_%d", atomic.AddUint64(&c.counter, 1))
}

func (c *smokeRecordingClient) Execute(ctx context.Context, req provider.GenerationRequest) ([]provider.Event, error) {
	c.ledger.record(smokeLedgerEntry{
		protocol:      smokeProtocolFrom(ctx),
		provider:      c.kind,
		publicModel:   req.Model.PublicName,
		upstreamModel: req.Model.UpstreamName,
		policyKey:     req.Model.PolicyKey,
		stream:        false,
		xSearch:       smokeXSearchPresent(req.Canonical),
	})
	return []provider.Event{smokeCompletedEvent(c.nextResponseID())}, nil
}

func (c *smokeRecordingClient) Stream(ctx context.Context, req provider.GenerationRequest) (provider.Stream, error) {
	c.ledger.record(smokeLedgerEntry{
		protocol:      smokeProtocolFrom(ctx),
		provider:      c.kind,
		publicModel:   req.Model.PublicName,
		upstreamModel: req.Model.UpstreamName,
		policyKey:     req.Model.PolicyKey,
		stream:        true,
		xSearch:       smokeXSearchPresent(req.Canonical),
	})
	return &smokeEventStream{events: []provider.Event{smokeCompletedEvent(c.nextResponseID())}}, nil
}

type smokeEventStream struct {
	events []provider.Event
	index  int
}

func (s *smokeEventStream) Next(_ context.Context) (provider.Event, error) {
	if s.index >= len(s.events) {
		return provider.Event{}, io.EOF
	}
	event := s.events[s.index]
	s.index++
	return event, nil
}

func (s *smokeEventStream) Close() error { return nil }

// ---------------------------------------------------------------------------
// Recording model discoverer + usage fetcher
// ---------------------------------------------------------------------------

type smokeModelDiscoverer struct {
	mu    sync.Mutex
	calls int
}

func (d *smokeModelDiscoverer) Discover(_ context.Context, _ provider.Credential) ([]provider.DiscoveredModel, error) {
	d.mu.Lock()
	d.calls++
	d.mu.Unlock()
	return []provider.DiscoveredModel{
		{UpstreamName: "grok-4.5", DisplayName: "Grok 4.5", ContextWindow: 131072, MaxOutputTokens: 16384},
	}, nil
}

func (d *smokeModelDiscoverer) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

type smokeUsageFetcher struct {
	mu    sync.Mutex
	calls int
}

func (f *smokeUsageFetcher) FetchUsage(_ context.Context, _ provider.Credential) (provider.UsageSnapshot, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	monthly := provider.MonthlyUsage{Limit: 1000, Used: 100, Remaining: 900}
	return provider.UsageSnapshot{Monthly: &monthly, FetchedAt: time.Now().UTC()}, nil
}

func (f *smokeUsageFetcher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// ---------------------------------------------------------------------------
// Smoke runtime assembly
// ---------------------------------------------------------------------------

type smokeRuntime struct {
	cfg                config.Config
	secrets            config.Secrets
	keys               appcrypto.Keys
	database           *store.SQLite
	server             *httptest.Server
	ledger             *smokeLedger
	xaiDiscoverer      *smokeModelDiscoverer
	xaiUsageFetcher    *smokeUsageFetcher
	devinExchange      *smokeDevinExchange
	xaiIssuer          *smokeFakeIssuer
	accountService     *accounts.Service
	apiKeyService      *accounts.APIKeyService
	apiKeyPlaintext    string
	capabilityRegistry *provider.RuntimeCapabilityRegistry
	modelWorker        *models.Worker
	usageWorker        *usage.Worker
	refreshWorker      *accounts.RefreshWorker
	webOAuth           *webOAuthAdapter
	publicModels       publicCatalog
	sessionService     *sessions.Service
	responseRepo       *store.ResponseRepository
}

// newSmokeRuntime assembles the full production component graph with fakes
// injected at the approved provider network boundaries: xAI OAuth (host
// rewrite to fake issuer), Devin exchange (host rewrite to fake endpoint),
// and generation (recording clients). All other components—store, accounts,
// routing, translators, admin, web, workers—are real.
func newSmokeRuntime(t *testing.T, dataDir string) *smokeRuntime {
	t.Helper()
	ctx := context.Background()

	// --- Secrets + keys ---
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = 42
	}
	keys, err := appcrypto.DeriveKeys(masterKey)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	secrets := config.Secrets{}
	// Build secrets via env so LoadSecrets works for the prior binary too.
	t.Setenv("BYOS_MASTER_KEY", base64.StdEncoding.EncodeToString(masterKey))
	t.Setenv("BYOS_ADMIN_PASSWORD", "smoke-admin-pass")
	t.Setenv("BYOS_ADMIN_API_KEY", "smoke-admin-api-key")
	secrets, err = config.LoadSecrets()
	if err != nil {
		t.Fatalf("load secrets: %v", err)
	}

	// --- Config ---
	cfg := config.Default()
	cfg.DataDir = dataDir
	cfg.Server.Listen = "127.0.0.1:0"
	cfg.Devin.OAuth.CallbackOrigin = "http://127.0.0.1:59653"
	cfg.Devin.OAuth.CallbackPath = "/callback"
	cfg.Models.Allowlist = []string{"grok-4.5", "glm-5-2", "swe-1-6", "swe-1-7"}
	cfg.Models.Aliases = map[string]string{"grok": "grok-4.5"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}

	// --- Store ---
	database, err := store.Open(ctx, cfg.DataDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	// --- Fakes ---
	xaiIssuer := newSmokeFakeIssuer(t)
	devinExchange := newSmokeDevinExchange(t)
	transport := newSmokeHostTransport()
	xaiURL, _ := url.Parse(xaiIssuer.baseURL())
	transport.rewrite("auth.x.ai", xaiURL)
	devinURL, _ := url.Parse(devinExchange.server.URL)
	transport.rewrite("api.devin.ai", devinURL)
	fakeClient := transport.client()

	// --- Repositories ---
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

	// --- Catalogs ---
	catalog := models.NewCatalog(capabilityRepo, cfg.Models.Allowlist, cfg.Models.Aliases)
	staticCatalog, err := models.NewStaticCatalog(cfg.Models.Entries)
	if err != nil {
		t.Fatalf("static catalog: %v", err)
	}
	modelCatalog, err := models.NewStaticCatalogOverlay(staticCatalog, cfg.Models.Aliases)
	if err != nil {
		t.Fatalf("static overlay: %v", err)
	}

	// --- xAI OAuth (real service, fake transport) ---
	discovery := oauthxai.NewDiscoveryClient(fakeClient, "")
	oauthOptions := oauthxai.Options{ClientID: cfg.OAuth.ClientID, Scopes: cfg.OAuth.Scopes}
	oauthService := oauthxai.NewService(discovery, fakeClient, oauthRepo, oauthOptions)
	refreshService := oauthxai.NewRefreshService(fakeClient, accountRepo, oauthOptions)
	verifyCtx := oidc.ClientContext(ctx, fakeClient)
	identity := oauthxai.NewIdentityVerifier(verifyCtx, oauthxai.Issuer, oauthxai.Issuer+"/jwks", oauthxai.DefaultClientID, []string{"ES256"})
	xaiCredentialManager := oauthxai.NewProviderCredentialManager(accountRepo, refreshService)
	xaiLifecycle := oauthxai.NewProviderLifecycle(oauthService, accountRepo, identity)

	// --- Devin OAuth (real client, fake transport) ---
	devinExchangeClient, err := oauthdevin.NewClient(oauthdevin.ClientConfig{
		HTTPClient:           fakeClient,
		Timeout:              15 * time.Second,
		MaxCompressedBytes:   2 << 20,
		MaxDecompressedBytes: 8 << 20,
	})
	if err != nil {
		t.Fatalf("devin exchange client: %v", err)
	}
	devinCredentialManager := oauthdevin.NewProviderCredentialManager(accountRepo)
	devinLifecycle := oauthdevin.NewProviderLifecycle(oauthRepo, devinExchangeClient, store.NewDevinOAuthTransaction(database.DB, keys), oauthdevin.OAuthConfig{
		CallbackOrigin: cfg.Devin.OAuth.CallbackOrigin,
		CallbackPath:   cfg.Devin.OAuth.CallbackPath,
	})

	// --- Recording generation clients ---
	ledger := &smokeLedger{}
	xaiDiscoverer := &smokeModelDiscoverer{}
	xaiUsageFetcher := &smokeUsageFetcher{}

	capabilityRegistry, err := provider.NewCapabilityRegistry([]provider.CapabilityRegistration{
		{
			Provider:  provider.XAI,
			PolicyKey: "xai",
			Capabilities: provider.Capabilities{
				Policy:              xai.RequestPolicy{},
				Generation:          &smokeRecordingClient{kind: provider.XAI, ledger: ledger},
				Credentials:         xaiCredentialManager,
				CredentialRefresher: xaiCredentialManager,
				Lifecycle:           xaiLifecycle,
				ModelDiscoverer:     xaiDiscoverer,
				UsageFetcher:        xaiUsageFetcher,
			},
		},
		{
			Provider:  provider.Devin,
			PolicyKey: "devin",
			Capabilities: provider.Capabilities{
				Policy:      devin.RequestPolicy{},
				Generation:  &smokeRecordingClient{kind: provider.Devin, ledger: ledger},
				Credentials: devinCredentialManager,
				Lifecycle:   devinLifecycle,
			},
		},
	})
	if err != nil {
		t.Fatalf("capability registry: %v", err)
	}

	if err := validateStaticCatalogCapabilities(staticCatalog, capabilityRegistry); err != nil {
		t.Fatalf("validate static catalog: %v", err)
	}

	// --- Credential usability registry (for refresh worker) ---
	credentialUsabilityRegistry, err := provider.NewCredentialUsabilityRegistry([]provider.CredentialUsabilityRegistration{
		{Provider: provider.Devin, Usability: devinCredentialManager},
	})
	if err != nil {
		t.Fatalf("credential usability registry: %v", err)
	}

	// --- Workers ---
	usageService := usage.NewService(usageRepo, localUsageRepo)
	modelWorker := models.NewWorker(models.NewStoreAccountProvider(accountRepo), capabilityRegistry, catalog, 15*time.Minute, 2*time.Minute, 4)
	usageWorker := usage.NewWorker(usage.NewStoreAccountProvider(accountRepo), capabilityRegistry, usageService, 5*time.Minute, 2*time.Minute, 4)
	modelRefresher := modelRefresh{accountRepo, modelWorker}
	usageRefresher := usageRefresh{accountRepo, usageWorker}
	accountService := accounts.NewService(accountRepo, capabilityRegistry, modelRefresher, usageRefresher)
	refreshWorker := accounts.NewRefreshWorker(accountRepo, capabilityRegistry, credentialUsabilityRegistry, modelRefresher, usageRefresher)

	// --- Routing ---
	cooldowns := routing.NewCooldownManager(cooldownRepo, accountRepo)
	executor := routing.NewExecutor(routing.NewScheduler(), modelCatalog, capabilityRegistry, cooldowns, accountRepo, capabilityRepo, cooldownRepo)
	executor.SetUsageRecorder(usageRecorder{service: usageService})
	transforms := translate.NewRegistry()
	chatTransform, ok := transforms.Get(registry.OpenAIChat)
	if !ok {
		t.Fatal("chat transform not found")
	}
	responsesTransform, ok := transforms.Get(registry.OpenAIResponses)
	if !ok {
		t.Fatal("responses transform not found")
	}
	anthropicTransform, ok := transforms.Get(registry.Anthropic)
	if !ok {
		t.Fatal("anthropic transform not found")
	}
	sessionService := sessions.NewService(responseRepo)
	publicModels := newPublicCatalog(catalog, staticCatalog, modelCatalog, accountRepo, cooldownRepo, func() time.Time { return time.Now().UTC() }, cfg.Models.Default, capabilityRegistry)

	// --- HTTP handlers ---
	handlers := api.ServerHandlers{
		Health: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
		Ready:  readyHandler(database.DB, publicModels),
		Models: apiopenai.ModelsHandler(publicModels),
		Chat: apiopenai.ChatHandler{Transform: chatTransform, Execute: func(ctx context.Context, request routing.Request) (routing.Result, error) {
			return executor.Execute(withSmokeProtocol(ctx, "chat"), request)
		}, OpenStream: func(ctx context.Context, request routing.Request) (api.RoutedStream, error) {
			return executor.Stream(withSmokeProtocol(ctx, "chat"), request)
		}},
		Responses: apiopenai.ResponsesHandler{Transform: responsesTransform, Execute: func(ctx context.Context, request routing.Request) (routing.Result, error) {
			return executor.Execute(withSmokeProtocol(ctx, "responses"), request)
		}, OpenStream: func(ctx context.Context, request routing.Request) (api.RoutedStream, error) {
			return executor.Stream(withSmokeProtocol(ctx, "responses"), request)
		}, Sessions: sessionService},
		Messages: apianthropic.MessagesHandler{Transform: anthropicTransform, Execute: func(ctx context.Context, request routing.Request) (routing.Result, error) {
			return executor.Execute(withSmokeProtocol(ctx, "anthropic"), request)
		}, OpenStream: func(ctx context.Context, request routing.Request) (api.RoutedStream, error) {
			return executor.Stream(withSmokeProtocol(ctx, "anthropic"), request)
		}},
		CountTokens: http.HandlerFunc(apianthropic.CountTokensHandler),
	}
	webOAuth := newWebOAuthAdapter(ctx, accountService)
	webOAuth.devinCallbackURL = "http://127.0.0.1:59653/callback"
	handlers.Admin = admin.NewHandler(admin.Services{Accounts: accountService, Completion: webOAuth, Usage: usageService, UsageRefresh: usageWorker, Models: catalog, ModelsRefresh: modelWorker, Cooldowns: cooldownRepo, APIKeys: apiKeyService, Capabilities: capabilityRegistry})
	handlers.Callback = admin.CallbackHandler(accountService)
	webAccounts := &webAccountAdapter{accounts: accountService, models: catalog, static: staticCatalog, registry: capabilityRegistry, usage: usageService, cooldowns: cooldownRepo, now: func() time.Time { return time.Now().UTC() }}
	trustedProxies, err := requestsource.ParseTrustedProxies(cfg.Server.TrustedProxies)
	if err != nil {
		t.Fatalf("parse trusted proxies: %v", err)
	}
	adminAuthGuard, err := auththrottle.NewGuard(adminThrottleRepo, keys.AdminAuthSourceFingerprint, auththrottle.DefaultPolicy(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("admin guard: %v", err)
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
		t.Fatalf("web handler: %v", err)
	}
	handlers.Web = webHandler

	// --- Server ---
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	root := api.NewServer(api.ServerConfig{Handlers: handlers, ClientKeys: apiKeyService, AdminAPIKey: secrets.AdminAPIKey(), AdminAttempts: adminAuthGuard, AdminSources: trustedProxies, CallbackPath: cfg.Devin.OAuth.CallbackPath, MaxBodyBytes: cfg.Limits.MaxBodyBytes, Logger: logger})
	server := httptest.NewServer(root)
	t.Cleanup(server.Close)

	// --- Create API key for client auth ---
	createdKey, err := apiKeyService.Create(ctx, "smoke-test-key")
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}

	return &smokeRuntime{
		cfg:                cfg,
		secrets:            secrets,
		keys:               keys,
		database:           database,
		server:             server,
		ledger:             ledger,
		xaiDiscoverer:      xaiDiscoverer,
		xaiUsageFetcher:    xaiUsageFetcher,
		devinExchange:      devinExchange,
		xaiIssuer:          xaiIssuer,
		accountService:     accountService,
		apiKeyService:      apiKeyService,
		apiKeyPlaintext:    createdKey.Plaintext,
		capabilityRegistry: capabilityRegistry,
		modelWorker:        modelWorker,
		usageWorker:        usageWorker,
		refreshWorker:      refreshWorker,
		webOAuth:           webOAuth,
		publicModels:       publicModels,
	}
}

func (sr *smokeRuntime) close() {
	_ = sr.database.Close()
	sr.server.Close()
}

// ---------------------------------------------------------------------------
// v4 DB helper
// ---------------------------------------------------------------------------

// migrationFSThrough returns a virtual FS containing only migration files up
// to maxVersion. This lets us create a v4-schema DB (migrations 001-004)
// without running migration 005+.
func migrationFSThrough(maxVersion int) fs.FS {
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		panic(fmt.Sprintf("read migrations: %v", err))
	}
	mapFS := fstest.MapFS{}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		prefix, _, ok := strings.Cut(entry.Name(), "_")
		if !ok {
			continue
		}
		version, err := strconv.Atoi(prefix)
		if err != nil || version <= 0 {
			continue
		}
		if version > maxVersion {
			continue
		}
		data, err := fs.ReadFile(migrations.FS, entry.Name())
		if err != nil {
			panic(fmt.Sprintf("read migration %s: %v", entry.Name(), err))
		}
		mapFS[entry.Name()] = &fstest.MapFile{Data: data}
	}
	return mapFS
}

// createV4Database creates a fresh SQLite DB with only migrations 001-004
// applied (v4 schema, pre-provider-identity). Returns the data directory path.
func createV4Database(t *testing.T, dataDir string) string {
	t.Helper()
	ctx := context.Background()
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("mkdir v4 data dir: %v", err)
	}
	dbPath := filepath.Join(dataDir, "byos.db")
	db, err := openRawSQLite(ctx, dbPath)
	if err != nil {
		t.Fatalf("open v4 db: %v", err)
	}
	if err := store.Migrate(ctx, db, migrationFSThrough(4)); err != nil {
		t.Fatalf("migrate v4: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close v4 db: %v", err)
	}
	return dataDir
}

// openRawSQLite opens a SQLite DB at path with the same pragmas as store.Open
// but without running migrations. Returns *sql.DB for direct use with
// store.Migrate and migration inspection.
func openRawSQLite(ctx context.Context, path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	for _, statement := range []string{"PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000"} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("configure sqlite: %w", err)
		}
	}
	return db, nil
}

// migrationCount returns the number of applied migrations in the DB at path.
func migrationCount(t *testing.T, dbPath string) int {
	t.Helper()
	ctx := context.Background()
	db, err := openRawSQLite(ctx, dbPath)
	if err != nil {
		t.Fatalf("open db for migration count: %v", err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatalf("query migration count: %v", err)
	}
	return count
}

// ---------------------------------------------------------------------------
// Prior binary via git archive
// ---------------------------------------------------------------------------

// buildPriorBinary extracts the pre-v5 commit (ecc6a18) via `git archive` into
// a temp dir and builds the byos binary. Returns the binary path.
func buildPriorBinary(t *testing.T) string {
	t.Helper()
	const priorCommit = "ecc6a18"
	// Use a directory outside /tmp to avoid Go's "system temp root" go.mod
	// restriction. t.TempDir() returns a path under /tmp which Go rejects.
	tempDir := filepath.Join(os.Getenv("HOME"), ".byos-smoke-prior", strconv.FormatInt(time.Now().UnixNano(), 10))
	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		t.Fatalf("mkdir prior binary src dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tempDir) })
	// git archive extracts a clean snapshot — no worktree, no prune, no
	// global mutation. Pipe directly through tar.
	archiveCmd := exec.Command("git", "archive", priorCommit)
	archiveCmd.Dir = repoRoot(t)
	archiveCmd.Stderr = os.Stderr
	archiveOutput, err := archiveCmd.Output()
	if err != nil {
		t.Fatalf("git archive: %v", err)
	}
	extract := exec.Command("tar", "-x", "-C", tempDir)
	extract.Stdin = strings.NewReader(string(archiveOutput))
	extract.Stderr = os.Stderr
	if err := extract.Run(); err != nil {
		t.Fatalf("extract archive: %v", err)
	}
	// Verify go.mod was extracted.
	if _, err := os.Stat(filepath.Join(tempDir, "go.mod")); err != nil {
		t.Fatalf("go.mod not found in extracted archive: %v", err)
	}
	binaryPath := filepath.Join(tempDir, "byos")
	build := exec.Command("go", "build", "-o", binaryPath, "./cmd/byos")
	build.Dir = tempDir
	build.Env = append(os.Environ(), "CGO_ENABLED=1")
	output, err := build.CombinedOutput()
	if err != nil {
		t.Fatalf("build prior binary: %v\n%s", err, output)
	}
	return binaryPath
}

// launchPriorBinary starts the prior byos binary with the given data dir and
// returns the base URL. The binary is killed on test cleanup.
//
// Network isolation: the prior binary is a real subprocess that must be
// reachable from the test via HTTP on 127.0.0.1 so the test can verify it
// serves the restored rows. A separate network namespace (unshare -n) would
// isolate loopback and break this communication, so OS-level namespace
// isolation is not suitable here. Instead, three layered controls enforce and
// verify no non-loopback network from the subprocess:
//
//  1. Disabled account: the seeded account is enabled=0, so the prior binary's
//     startup workers (refresh, model discovery, usage) skip it and never
//     attempt to use its token (verified by assertPriorBinaryAccountDisabled).
//  2. Fail-closed proxy env: HTTP_PROXY/HTTPS_PROXY/ALL_PROXY point at a dead
//     loopback port (127.0.0.1:1) so any HTTP client call is refused
//     immediately. NO_PROXY preserves loopback health checks.
//  3. strace verification: the child is launched under strace -f -e
//     trace=network; after it exits, the trace is parsed to verify no
//     connect() targeted a non-loopback address.
//
// To eliminate the bind-close-rebind port race (another process can claim the
// released port before the child binds, making the child exit and the test wait
// the full readiness timeout), the child is started on a freshly reserved port
// and its early exit is detected instead of polling blindly. If the child exits
// before becoming healthy, a new port is reserved and the launch is retried.
func launchPriorBinary(t *testing.T, binaryPath, dataDir string) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	useStrace := straceAvailable()

	const maxAttempts = 5
	var lastPort int
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("find free port: %v", err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		_ = listener.Close()

		attemptCtx, attemptCancel := context.WithCancel(ctx)
		serveArgs := []string{"serve", "--listen", fmt.Sprintf("127.0.0.1:%d", port), "--data-dir", dataDir}

		var cmd *exec.Cmd
		var traceFile string
		if useStrace {
			traceFile = filepath.Join(t.TempDir(), "strace-net.log")
			cmd = exec.CommandContext(attemptCtx, "strace", append([]string{"-f", "-e", "trace=network", "-o", traceFile, binaryPath}, serveArgs...)...)
		} else {
			cmd = exec.CommandContext(attemptCtx, binaryPath, serveArgs...)
		}
		// Put the child in its own process group so we can kill the entire
		// group (strace + the prior binary) on cleanup. Without this, killing
		// strace alone can orphan the prior binary, which holds the stderr fd
		// open and triggers "WaitDelay expired before I/O complete".
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		// Kill the process group (negative PID) when the context is cancelled,
		// then reap with a bounded WaitDelay so I/O pipes close promptly.
		cmd.Cancel = func() error {
			if cmd.Process != nil {
				return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
			return os.ErrProcessDone
		}
		cmd.WaitDelay = 5 * time.Second
		cmd.Stderr = os.Stderr
		// Fail-closed proxy: any HTTP client call through a dead loopback
		// proxy is refused immediately. NO_PROXY preserves loopback health
		// checks. BYOS_* vars are inherited from os.Environ (set via t.Setenv).
		cmd.Env = append(os.Environ(),
			"HTTP_PROXY=http://127.0.0.1:1",
			"HTTPS_PROXY=http://127.0.0.1:1",
			"ALL_PROXY=http://127.0.0.1:1",
			"NO_PROXY=localhost,127.0.0.1,::1",
		)
		if err := cmd.Start(); err != nil {
			attemptCancel()
			t.Fatalf("start prior binary: %v", err)
		}
		exited := make(chan struct{})
		go func() { _ = cmd.Wait(); close(exited) }()

		baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
		if waitPriorHealthy(baseURL, exited, 10*time.Second) {
			if useStrace {
				t.Log("prior binary launched under strace with fail-closed proxy: verifying no non-loopback network after exit")
			} else {
				t.Log("prior binary launched with fail-closed proxy (strace unavailable): disabled account + proxy env fail-closed")
			}
			t.Cleanup(func() {
				attemptCancel()
				<-exited
				if useStrace && traceFile != "" {
					verifyNoNonLoopbackStrace(t, traceFile)
				}
			})
			return baseURL
		}
		// Not healthy: either the port was stolen (early exit) or readiness
		// timed out. Reap this child and retry on a freshly reserved port.
		attemptCancel()
		<-exited
		lastPort = port
		t.Logf("prior binary attempt %d did not become healthy on port %d; retrying", attempt, port)
	}
	t.Fatalf("prior binary did not become healthy after %d attempts (last port %d)", maxAttempts, lastPort)
	return ""
}

// straceAvailable reports whether strace can trace network syscalls. When
// available, the prior binary is launched under strace -f -e trace=network so
// the trace can be parsed after exit to verify no non-loopback connect() was
// attempted. This is the verification layer atop the disabled-account and
// fail-closed-proxy enforcement controls.
func straceAvailable() bool {
	cmd := exec.Command("strace", "-V")
	return cmd.Run() == nil
}

// verifyNoNonLoopbackStrace parses an strace network trace and fails the test
// if any connect() targeted a non-loopback address. Loopback (127.x.x.x,
// 0.0.0.0, ::1, ::) is allowed; everything else is a violation. This is the
// verification fallback when unshare -n is unavailable.
func verifyNoNonLoopbackStrace(t *testing.T, traceFile string) {
	t.Helper()
	data, err := os.ReadFile(traceFile)
	if err != nil {
		t.Fatalf("read strace trace: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, "connect(") {
			continue
		}
		// Loopback and wildcard binds are allowed.
		if strings.Contains(line, `inet_addr("127.`) ||
			strings.Contains(line, `inet_addr("0.0.0.0"`) ||
			strings.Contains(line, `inet_pton(AF_INET6, "::1"`) ||
			strings.Contains(line, `inet_pton(AF_INET6, "::"`) {
			continue
		}
		// Any connect() with a non-loopback inet/inet6 address is a violation.
		if strings.Contains(line, "sin_addr=") || strings.Contains(line, "sin6_addr=") {
			t.Fatalf("prior binary attempted non-loopback network call: %s", line)
		}
	}
}

// waitPriorHealthy polls /healthz until the prior binary responds 200, the
// child process exits (port race / bind failure), or the timeout elapses. It
// returns true only when the binary is healthy.
func waitPriorHealthy(baseURL string, exited <-chan struct{}, timeout time.Duration) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			return false
		default:
		}
		resp, err := client.Get(baseURL + "/healthz")
		if err == nil {
			ok := resp.StatusCode == http.StatusOK
			_ = resp.Body.Close()
			if ok {
				return true
			}
		}
		select {
		case <-exited:
			return false
		case <-time.After(100 * time.Millisecond):
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

func (sr *smokeRuntime) doRequest(t *testing.T, method, path string, body string) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, sr.server.URL+path, bodyReader)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, path, err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if strings.HasPrefix(path, "/v1/messages") {
		req.Header.Set("anthropic-version", "2023-06-01")
	}
	req.Header.Set("Authorization", "Bearer "+sr.apiKeyPlaintext)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request %s %s: %v", method, path, err)
	}
	return resp
}

func (sr *smokeRuntime) doAdminRequest(t *testing.T, method, path string, body string) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, sr.server.URL+path, bodyReader)
	if err != nil {
		t.Fatalf("new admin request %s %s: %v", method, path, err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+sr.secrets.AdminAPIKey())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do admin request %s %s: %v", method, path, err)
	}
	return resp
}

func assertStatus(t *testing.T, resp *http.Response, expected int, context string) {
	t.Helper()
	if resp.StatusCode != expected {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		t.Fatalf("%s: expected status %d, got %d: %s", context, expected, resp.StatusCode, body)
	}
}

func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	_ = resp.Body.Close()
	return body
}

// ---------------------------------------------------------------------------
// Main test
// ---------------------------------------------------------------------------

func TestC12SmokeHarness(t *testing.T) {
	dataDir := t.TempDir()

	// === Phase 1: Assemble runtime and complete both logins ===
	sr := newSmokeRuntime(t, dataDir)
	defer sr.close()

	ctx := context.Background()

	// seedResponseID captures the response id persisted by the Responses
	// continuation seed so the post-restart continuation can reference it via
	// previous_response_id. It is populated in the responses_continuation_seed
	// subtest and read in restart_reopen.
	seedResponseID := ""

	// --- Complete xAI device login ---
	t.Run("xAI_device_login", func(t *testing.T) {
		auth, err := sr.accountService.StartLogin(ctx, provider.XAI)
		if err != nil {
			t.Fatalf("start xAI login: %v", err)
		}
		if auth.VerificationURL == "" {
			t.Fatal("xAI authorization URL is empty")
		}
		// CompleteLogin triggers the device-flow poll. The fake token
		// endpoint returns immediately, so the poll succeeds on the first
		// iteration without waiting. The identity verifier fetches JWKS
		// from the fake issuer via the host-rewriting transport.
		account, err := sr.accountService.CompleteLogin(ctx, provider.XAI, provider.AuthorizationRef{Provider: provider.XAI, SessionID: auth.SessionID}, provider.AuthorizationCompletion{})
		if err != nil {
			t.Fatalf("complete xAI login: %v", err)
		}
		if account.ID == "" {
			t.Fatal("xAI CompleteLogin returned empty account ID")
		}
		if account.Provider != provider.XAI {
			t.Fatalf("xAI account provider: expected xai, got %s", account.Provider)
		}
		if account.Status != "ready" {
			t.Fatalf("xAI account status: expected ready, got %s", account.Status)
		}
		t.Logf("xAI account created: %s", account.ID)
	})

	// --- Complete Devin callback login ---
	var devinAccountID string
	t.Run("Devin_callback_login", func(t *testing.T) {
		auth, err := sr.accountService.StartLogin(ctx, provider.Devin)
		if err != nil {
			t.Fatalf("start Devin login: %v", err)
		}
		if auth.VerificationURL == "" {
			t.Fatal("Devin authorization URL is empty")
		}
		parsed, err := url.Parse(auth.VerificationURL)
		if err != nil {
			t.Fatalf("parse Devin auth URL: %v", err)
		}
		state := parsed.Query().Get("state")
		redirectURI := parsed.Query().Get("redirect_uri")
		if state == "" || redirectURI != "http://127.0.0.1:59653/callback" {
			t.Fatalf("Devin authorization state=%q redirect_uri=%q", state, redirectURI)
		}
		// Simulate Railway/browser-copy completion: Devin redirects to the
		// advertised localhost URI, then the administrator submits that complete
		// URL through the authenticated Admin API. The real adapter validates the
		// exact redirect, binds state to SessionID, exchanges the code, and
		// persists the account.
		callbackURL := redirectURI + "?state=" + url.QueryEscape(state) + "&code=smoke-devin-code"
		payload, err := json.Marshal(map[string]string{"callback_url": callbackURL})
		if err != nil {
			t.Fatal(err)
		}
		resp := sr.doAdminRequest(t, http.MethodPost, "/admin/api/v1/oauth/devin/complete/"+auth.SessionID.String(), string(payload))
		assertStatus(t, resp, http.StatusOK, "Devin manual callback")
		body := readBody(t, resp)
		if bytes.Contains(body, []byte(state)) || bytes.Contains(body, []byte("smoke-devin-code")) {
			t.Fatalf("Devin manual callback response leaked secrets: %s", body)
		}
		// Verify the account was created.
		accounts, err := sr.accountService.List(ctx)
		if err != nil {
			t.Fatalf("list accounts: %v", err)
		}
		for _, acct := range accounts {
			if acct.Provider == provider.Devin {
				devinAccountID = acct.ID
				break
			}
		}
		if devinAccountID == "" {
			t.Fatal("Devin account was not created after callback")
		}
		if sr.devinExchange.callCount() == 0 {
			t.Fatal("Devin token exchange endpoint was never called")
		}
		t.Logf("Devin account created: %s (exchange calls: %d)", devinAccountID, sr.devinExchange.callCount())
	})

	// Verify both accounts exist.
	accounts, err := sr.accountService.List(ctx)
	if err != nil {
		t.Fatalf("list accounts after login: %v", err)
	}
	if len(accounts) < 2 {
		t.Fatalf("expected at least 2 accounts after login, got %d", len(accounts))
	}
	var xaiAccountID string
	for _, acct := range accounts {
		if acct.Provider == provider.XAI {
			xaiAccountID = acct.ID
		}
	}
	if xaiAccountID == "" {
		t.Fatal("no xAI account found after login")
	}
	if devinAccountID == "" {
		t.Fatal("no Devin account found after login")
	}

	// === Phase 2: Provider × protocol × stream matrix with exact ledger ===
	t.Run("generation_matrix", func(t *testing.T) {
		sr.ledger.reset()
		// Every public model the catalog exposes: the three concise aliases and
		// their four canonical targets. Each is dispatched across all three
		// protocols and both stream modes, producing an exact ledger entry per
		// case.
		models := []struct {
			public    string
			upstream  string
			kind      provider.Kind
			policyKey string
			xSearch   bool
		}{
			{"grok-4.5", "grok-4.5", provider.XAI, "xai", true},
			{"grok", "grok-4.5", provider.XAI, "xai", true},
			{"glm", "glm-5-2", provider.Devin, "devin", false},
			{"swe", "swe-1-7", provider.Devin, "devin", false},
			{"glm-5-2", "glm-5-2", provider.Devin, "devin", false},
			{"swe-1-6", "swe-1-6", provider.Devin, "devin", false},
			{"swe-1-7", "swe-1-7", provider.Devin, "devin", false},
		}
		protocols := []struct {
			name string
			path string
			body func(model string) string
		}{
			{"chat", "/v1/chat/completions", func(m string) string {
				return fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hello"}]}`, m)
			}},
			{"responses", "/v1/responses", func(m string) string { return fmt.Sprintf(`{"model":%q,"input":"hello","store":false}`, m) }},
			{"anthropic", "/v1/messages", func(m string) string {
				return fmt.Sprintf(`{"model":%q,"max_tokens":100,"messages":[{"role":"user","content":"hello"}]}`, m)
			}},
		}

		// Build the exact expected ledger in dispatch order (non-stream first,
		// then stream) so a missing, extra, or cross-provider call fails the
		// comparison regardless of which field diverged.
		var expected []smokeLedgerEntry
		for _, streamMode := range []bool{false, true} {
			for _, model := range models {
				for _, protocol := range protocols {
					body := protocol.body(model.public)
					if streamMode {
						body = strings.TrimSuffix(body, "}") + `,"stream":true}`
					}
					resp := sr.doRequest(t, http.MethodPost, protocol.path, body)
					assertStatus(t, resp, http.StatusOK, model.public+"_"+protocol.name+"_stream_"+strconv.FormatBool(streamMode))
					if streamMode {
						_, _ = io.Copy(io.Discard, resp.Body)
					}
					_ = resp.Body.Close()
					expected = append(expected, smokeLedgerEntry{
						protocol:      protocol.name,
						provider:      model.kind,
						publicModel:   model.public,
						upstreamModel: model.upstream,
						policyKey:     model.policyKey,
						stream:        streamMode,
						xSearch:       model.xSearch,
					})
				}
			}
		}

		got := sr.ledger.snapshot()
		if len(got) != len(expected) {
			t.Fatalf("ledger length: expected %d, got %d\ngot=%+v", len(expected), len(got), got)
		}
		for i, want := range expected {
			if got[i] != want {
				t.Fatalf("ledger entry %d mismatch:\nwant=%+v\ngot =%+v", i, want, got[i])
			}
		}
		// Sanity: xAI always carries x_search, Devin never does, and no
		// cross-provider dispatch leaked into the ledger.
		for _, e := range got {
			if e.provider == provider.XAI && !e.xSearch {
				t.Fatalf("xAI call missing x_search policy: %+v", e)
			}
			if e.provider == provider.Devin && e.xSearch {
				t.Fatalf("Devin call unexpectedly carries x_search: %+v", e)
			}
			if e.provider == provider.XAI && e.policyKey != "xai" {
				t.Fatalf("xAI call has wrong policy key: %+v", e)
			}
			if e.provider == provider.Devin && e.policyKey != "devin" {
				t.Fatalf("Devin call has wrong policy key: %+v", e)
			}
		}
		t.Logf("ledger: %d exact entries across 7 models × 3 protocols × 2 stream modes", len(got))
	})

	// === Phase 3: Model/readiness/admin/web/CLI projections ===
	t.Run("projections", func(t *testing.T) {
		// Readiness
		resp := sr.doRequest(t, http.MethodGet, "/readyz", "")
		assertStatus(t, resp, http.StatusOK, "readyz")
		_ = resp.Body.Close()

		// Models: every public model is projected downstream.
		resp = sr.doRequest(t, http.MethodGet, "/v1/models", "")
		assertStatus(t, resp, http.StatusOK, "models")
		modelsBody := readBody(t, resp)
		for _, marker := range []string{"grok", "grok-4.5", "glm", "glm-5-2", "swe", "swe-1-6", "swe-1-7"} {
			if !strings.Contains(string(modelsBody), marker) {
				t.Fatalf("models response missing %q: %s", marker, modelsBody)
			}
		}

		// Admin REST: list accounts (both providers projected).
		resp = sr.doAdminRequest(t, http.MethodGet, "/admin/api/v1/accounts", "")
		assertStatus(t, resp, http.StatusOK, "admin accounts")
		adminBody := readBody(t, resp)
		if !strings.Contains(string(adminBody), "xai") {
			t.Fatalf("admin accounts missing xai: %s", adminBody)
		}
		if !strings.Contains(string(adminBody), "devin") {
			t.Fatalf("admin accounts missing devin: %s", adminBody)
		}

		// Web: POST /admin/login must return 303 See Other with Location
		// /admin/ and set an authenticated session cookie. Reuse that cookie
		// to fetch the authenticated /admin/accounts page and verify both
		// provider projections render.
		authClient, loginResp := sr.doWebLogin(t)
		if loginResp == nil {
			t.Fatal("web login returned no response")
		}
		if loginResp.StatusCode != http.StatusSeeOther {
			body := readBody(t, loginResp)
			t.Fatalf("web login: expected 303, got %d: %s", loginResp.StatusCode, body)
		}
		if loc := loginResp.Header.Get("Location"); loc != "/admin/" {
			t.Fatalf("web login Location: expected /admin/, got %q", loc)
		}
		_ = loginResp.Body.Close()

		accountsResp, err := authClient.Get(sr.server.URL + "/admin/accounts")
		if err != nil {
			t.Fatalf("authenticated /admin/accounts: %v", err)
		}
		accountsBody := readBody(t, accountsResp)
		if accountsResp.StatusCode != http.StatusOK {
			t.Fatalf("authenticated /admin/accounts: expected 200, got %d: %s", accountsResp.StatusCode, accountsBody)
		}
		if !strings.Contains(string(accountsBody), "xAI") {
			t.Fatalf("web /admin/accounts missing xAI projection: %s", accountsBody)
		}
		if !strings.Contains(string(accountsBody), "Devin") {
			t.Fatalf("web /admin/accounts missing Devin projection: %s", accountsBody)
		}

		// CLI: run the companion smoke-tagged cmd/byos test, which exercises
		// the actual provider-aware CLI parser (runWith) and the full login
		// lifecycle for BOTH xAI device and Devin callback completion through
		// dependency seams (fake lifecycles, real accounts.Service, real
		// callback handler) with safe-output assertions. `byos version` alone
		// is insufficient — it only proves the binary builds and prints a
		// version string, not that the parser routes providers or the login
		// lifecycle completes.
		runCLISmokeTest(t)
	})

	// === Phase 4: Workers (model discovery + usage fetch) ===
	t.Run("workers", func(t *testing.T) {
		// CompleteLogin already triggered one model-discovery and one
		// usage-fetch call for the xAI account during login. Each admin
		// refresh must add exactly one more call, so assert the precise delta
		// rather than merely ">0".
		discoverBefore := sr.xaiDiscoverer.callCount()
		usageBefore := sr.xaiUsageFetcher.callCount()

		// Trigger model refresh via admin API (global, not per-account).
		resp := sr.doAdminRequest(t, http.MethodPost, "/admin/api/v1/models/refresh", "")
		assertStatus(t, resp, http.StatusOK, "model refresh")
		_ = resp.Body.Close()

		// Wait for the discoverer to be called exactly once more.
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) && sr.xaiDiscoverer.callCount() != discoverBefore+1 {
			time.Sleep(100 * time.Millisecond)
		}
		if got := sr.xaiDiscoverer.callCount(); got != discoverBefore+1 {
			t.Fatalf("model discoverer call count: expected %d, got %d", discoverBefore+1, got)
		}

		// Trigger usage refresh.
		resp = sr.doAdminRequest(t, http.MethodPost, "/admin/api/v1/accounts/"+xaiAccountID+"/usage/refresh", "")
		assertStatus(t, resp, http.StatusOK, "usage refresh")
		_ = resp.Body.Close()

		deadline = time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) && sr.xaiUsageFetcher.callCount() != usageBefore+1 {
			time.Sleep(100 * time.Millisecond)
		}
		if got := sr.xaiUsageFetcher.callCount(); got != usageBefore+1 {
			t.Fatalf("usage fetcher call count: expected %d, got %d", usageBefore+1, got)
		}
	})

	// === Phase 4b: Seed a stored Responses session for cross-restart continuation ===
	t.Run("responses_continuation_seed", func(t *testing.T) {
		// A real Responses request with store=true persists the completed
		// response so a post-restart request can continue the chain via
		// previous_response_id. store=false requests never persist, so this
		// is the only seeded node. The recording client returns a unique
		// response id per call; capture it from the response body so the
		// continuation anchor is exact rather than hard-coded.
		resp := sr.doRequest(t, http.MethodPost, "/v1/responses", `{"model":"grok-4.5","input":"seed","store":true}`)
		assertStatus(t, resp, http.StatusOK, "responses continuation seed")
		seedBody := readBody(t, resp)
		var seedResp struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(seedBody, &seedResp); err != nil || seedResp.ID == "" {
			t.Fatalf("responses continuation seed: could not parse response id from %s: %v", seedBody, err)
		}
		seedResponseID = seedResp.ID

		// Same-runtime continuation proves the chain reconstructs before
		// exercising the cross-restart path. The continuation completes with a
		// fresh id and persists a second stored node (no primary-key collision).
		contResp := sr.doRequest(t, http.MethodPost, "/v1/responses", fmt.Sprintf(`{"model":"grok-4.5","previous_response_id":%q,"input":"continue","store":true}`, seedResponseID))
		assertStatus(t, contResp, http.StatusOK, "same-runtime responses continuation")
		_ = contResp.Body.Close()
	})

	// === Phase 5: Restart/reopen ===
	t.Run("restart_reopen", func(t *testing.T) {
		// Close current runtime.
		sr.close()

		// Reopen with a fresh runtime on the same data dir.
		sr2 := newSmokeRuntime(t, dataDir)
		defer sr2.close()

		// Verify both accounts survived.
		accounts, err := sr2.accountService.List(ctx)
		if err != nil {
			t.Fatalf("list accounts after restart: %v", err)
		}
		var xaiFound, devinFound bool
		for _, acct := range accounts {
			if acct.Provider == provider.XAI {
				xaiFound = true
			}
			if acct.Provider == provider.Devin {
				devinFound = true
			}
		}
		if !xaiFound {
			t.Fatal("xAI account did not survive restart")
		}
		if !devinFound {
			t.Fatal("Devin account did not survive restart")
		}

		// Continuation: issue requests after restart.
		sr2.ledger.reset()
		resp := sr2.doRequest(t, http.MethodPost, "/v1/chat/completions", `{"model":"grok-4.5","messages":[{"role":"user","content":"continue"}]}`)
		assertStatus(t, resp, http.StatusOK, "post-restart xAI chat")
		_ = resp.Body.Close()

		resp = sr2.doRequest(t, http.MethodPost, "/v1/chat/completions", `{"model":"glm","messages":[{"role":"user","content":"continue"}]}`)
		assertStatus(t, resp, http.StatusOK, "post-restart Devin chat")
		_ = resp.Body.Close()

		if sr2.ledger.count(func(e smokeLedgerEntry) bool { return e.provider == provider.XAI }) != 1 {
			t.Fatal("post-restart xAI generation not recorded")
		}
		if sr2.ledger.count(func(e smokeLedgerEntry) bool { return e.provider == provider.Devin }) != 1 {
			t.Fatal("post-restart Devin generation not recorded")
		}

		// Real Responses previous_response_id continuation across restart: the
		// seeded "resp_smoke" session survived in the DB and the reopened
		// sessionService reconstructs the chain so the continuation request
		// succeeds. A missing/expired session would surface as an error status.
		sr2.ledger.reset()
		resp = sr2.doRequest(t, http.MethodPost, "/v1/responses", fmt.Sprintf(`{"model":"grok-4.5","previous_response_id":%q,"input":"continue","store":true}`, seedResponseID))
		assertStatus(t, resp, http.StatusOK, "post-restart responses continuation")
		_ = resp.Body.Close()
		if sr2.ledger.count(func(e smokeLedgerEntry) bool { return e.provider == provider.XAI && e.protocol == "responses" }) != 1 {
			t.Fatal("post-restart responses continuation not recorded as a single xAI responses call")
		}

		// Readiness after restart.
		resp = sr2.doRequest(t, http.MethodGet, "/readyz", "")
		assertStatus(t, resp, http.StatusOK, "post-restart readyz")
		_ = resp.Body.Close()

		// Models after restart.
		resp = sr2.doRequest(t, http.MethodGet, "/v1/models", "")
		assertStatus(t, resp, http.StatusOK, "post-restart models")
		_ = resp.Body.Close()

		// Admin after restart.
		resp = sr2.doAdminRequest(t, http.MethodGet, "/admin/api/v1/accounts", "")
		assertStatus(t, resp, http.StatusOK, "post-restart admin accounts")
		_ = resp.Body.Close()

		// Web after restart: login must still 303 and the authenticated accounts
		// page must render both providers.
		authClient2, webResp := sr2.doWebLogin(t)
		if webResp == nil {
			t.Fatal("post-restart web login returned no response")
		}
		if webResp.StatusCode != http.StatusSeeOther || webResp.Header.Get("Location") != "/admin/" {
			body := readBody(t, webResp)
			t.Fatalf("post-restart web login: expected 303 /admin/, got %d %q: %s", webResp.StatusCode, webResp.Header.Get("Location"), body)
		}
		_ = webResp.Body.Close()
		accountsPageResp, err := authClient2.Get(sr2.server.URL + "/admin/accounts")
		if err != nil {
			t.Fatalf("post-restart authenticated /admin/accounts: %v", err)
		}
		accountsPageBody := readBody(t, accountsPageResp)
		if accountsPageResp.StatusCode != http.StatusOK || !strings.Contains(string(accountsPageBody), "xAI") || !strings.Contains(string(accountsPageBody), "Devin") {
			t.Fatalf("post-restart /admin/accounts: status %d body %s", accountsPageResp.StatusCode, accountsPageBody)
		}

		t.Log("restart/reopen verified: accounts survived, generation, responses continuation, readiness, models, admin, web all functional")
	})

	// === Phase 6: Populated v4 backup restored and served by prior binary ===
	t.Run("backup_restore_prior_binary", func(t *testing.T) {
		// 1. Build a populated v4 database (migrations 001-004 only) with
		//    representative account/API-key/session rows encrypted under the
		//    same master key the prior binary will load from the environment.
		v4Dir := t.TempDir()
		v4DBPath := filepath.Join(v4Dir, "byos.db")
		populateV4ForPriorBinary(t, ctx, v4Dir, v4DBPath)
		if count := migrationCount(t, v4DBPath); count != 4 {
			t.Fatalf("v4 DB should have 4 migrations, got %d", count)
		}

		// 2. Take the pre-upgrade backup: copy byos.db and WAL/SHM sidecars
		//    into a dedicated backup directory that the prior binary will
		//    restore and serve.
		backupDir := t.TempDir()
		backupDBPath := filepath.Join(backupDir, "byos.db")
		if err := copySQLiteFiles(v4Dir, backupDir); err != nil {
			t.Fatalf("copy populated v4 db to backup: %v", err)
		}

		// 3. Migrate a SEPARATE copy forward with the current binary. The live
		//    data directory is never handed to the prior binary; only this
		//    forward-migrated copy touches the current schema, and the
		//    populated rows survive with provider identity backfilled.
		migratedDir := t.TempDir()
		migratedDBPath := filepath.Join(migratedDir, "byos.db")
		if err := copySQLiteFiles(v4Dir, migratedDir); err != nil {
			t.Fatalf("copy populated v4 db for migration: %v", err)
		}
		migratedStore, err := store.Open(ctx, migratedDir)
		if err != nil {
			t.Fatalf("migrate populated v4 copy forward: %v", err)
		}
		_ = migratedStore.Close()
		currentCount := currentMigrationCount(t)
		if got := migrationCount(t, migratedDBPath); got != currentCount {
			t.Fatalf("migrated DB should have %d migrations (current), got %d", currentCount, got)
		}
		assertPopulatedV4RowsSurvivedMigration(t, ctx, migratedDBPath)

		// 4. Build the prior binary via git archive (no worktree mutation).
		binaryPath := buildPriorBinary(t)

		// 5. Launch the prior binary on the restored backup directory and
		//    verify it opens the populated v4 DB and serves the rows.
		baseURL := launchPriorBinary(t, binaryPath, backupDir)

		resp, err := http.Get(baseURL + "/healthz")
		if err != nil {
			t.Fatalf("prior binary healthz: %v", err)
		}
		assertStatus(t, resp, http.StatusOK, "prior binary healthz")
		_ = resp.Body.Close()

		// The prior binary's admin API lists the restored account row (it
		// decrypts credentials with the same master key) and the restored API
		// key row. Both prove the populated backup is served, not merely opened.
		priorAdmin := http.Client{Timeout: 10 * time.Second}
		acctReq, _ := http.NewRequest(http.MethodGet, baseURL+"/admin/api/v1/accounts", nil)
		acctReq.Header.Set("Authorization", "Bearer "+sr.secrets.AdminAPIKey())
		acctResp, err := priorAdmin.Do(acctReq)
		if err != nil {
			t.Fatalf("prior binary admin accounts: %v", err)
		}
		acctBody := readBody(t, acctResp)
		if acctResp.StatusCode != http.StatusOK {
			t.Fatalf("prior binary admin accounts: expected 200, got %d: %s", acctResp.StatusCode, acctBody)
		}
		if !strings.Contains(string(acctBody), priorBinaryAccountLabel) {
			t.Fatalf("prior binary did not serve restored account %q: %s", priorBinaryAccountLabel, acctBody)
		}

		keyReq, _ := http.NewRequest(http.MethodGet, baseURL+"/admin/api/v1/api-keys", nil)
		keyReq.Header.Set("Authorization", "Bearer "+sr.secrets.AdminAPIKey())
		keyResp, err := priorAdmin.Do(keyReq)
		if err != nil {
			t.Fatalf("prior binary admin api-keys: %v", err)
		}
		keyBody := readBody(t, keyResp)
		if keyResp.StatusCode != http.StatusOK {
			t.Fatalf("prior binary admin api-keys: expected 200, got %d: %s", keyResp.StatusCode, keyBody)
		}
		if !strings.Contains(string(keyBody), priorBinaryAPIKeyPrefix) {
			t.Fatalf("prior binary did not serve restored API key %q: %s", priorBinaryAPIKeyPrefix, keyBody)
		}
		// 6. No in-place downgrade: the restored backup the prior binary opened
		//    still has exactly 4 migrations, the representative session row is
		//    unchanged on disk, and the seeded account remains disabled so the
		//    prior binary's startup workers never attempted to use its token.
		if got := migrationCount(t, backupDBPath); got != 4 {
			t.Fatalf("v4 backup should still have 4 migrations after prior binary, got %d", got)
		}
		assertPriorBinarySessionRowUnchanged(t, ctx, backupDBPath)
		assertPriorBinaryAccountDisabled(t, ctx, backupDBPath)

		t.Log("backup restore verified: prior binary opens populated v4 backup (network-isolated) and serves disabled account/API-key/session rows; separate copy migrated forward; backup unchanged")
	})
}

// ---------------------------------------------------------------------------
// Web login helper
// ---------------------------------------------------------------------------

func (sr *smokeRuntime) doWebLogin(t *testing.T) (*http.Client, *http.Response) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("new cookie jar: %v", err)
	}
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// GET the login page to establish CSRF cookie + token.
	pageResp, err := client.Get(sr.server.URL + "/admin/login")
	if err != nil {
		t.Fatalf("web login GET: %v", err)
	}
	body, err := io.ReadAll(io.LimitReader(pageResp.Body, 1<<20))
	_ = pageResp.Body.Close()
	if err != nil {
		t.Fatalf("web login read body: %v", err)
	}
	token := extractCSRFToken(string(body))
	if token == "" {
		t.Fatal("no CSRF token found in login page")
	}

	// POST credentials with CSRF token.
	form := url.Values{
		"password":           {sr.secrets.AdminPassword()},
		"gorilla.csrf.Token": {token},
	}
	req, err := http.NewRequest(http.MethodPost, sr.server.URL+"/admin/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("web login POST request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("web login POST: %v", err)
	}
	return client, resp
}

var csrfFieldPattern = regexp.MustCompile(`name="gorilla\.csrf\.Token" value="([^"]+)"`)

func extractCSRFToken(htmlBody string) string {
	match := csrfFieldPattern.FindStringSubmatch(htmlBody)
	if len(match) != 2 {
		return ""
	}
	return match[1]
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}

// repoRoot returns the git repository root directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("find git root: %v", err)
	}
	return strings.TrimSpace(string(output))
}

// ---------------------------------------------------------------------------
// Populated v4 backup helpers
// ---------------------------------------------------------------------------

// priorBinaryAccountLabel and priorBinaryAPIKeyPrefix identify the
// representative rows seeded into the populated v4 backup so the prior-binary
// assertions can confirm the restored rows are served, not just present.
const (
	priorBinaryAccountLabel = "smoke-backup-account"
	priorBinaryAPIKeyPrefix = "byos_backup"
)

// smokeMasterKey returns the deterministic 32-byte master key the smoke
// harness configures via BYOS_MASTER_KEY, so seeded rows are encrypted with
// the same key the prior binary loads from the environment.
func smokeMasterKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = 42
	}
	return key
}

// populateV4ForPriorBinary creates a v4-schema database (migrations 001-004
// only) in dataDir and seeds representative account/API-key/session rows
// encrypted under the smoke master key. The prior binary (commit ecc6a18)
// shares the crypto envelope and AccountCredentials shape, so it can decrypt
// and serve the restored account row.
func populateV4ForPriorBinary(t *testing.T, ctx context.Context, dataDir, dbPath string) {
	t.Helper()
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("mkdir v4 data dir: %v", err)
	}
	db, err := openRawSQLite(ctx, dbPath)
	if err != nil {
		t.Fatalf("open v4 db: %v", err)
	}
	if err := store.Migrate(ctx, db, migrationFSThrough(4)); err != nil {
		t.Fatalf("migrate v4: %v", err)
	}
	keys, err := appcrypto.DeriveKeys(smokeMasterKey())
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	// Account credentials match the ecc6a18 AccountCredentials shape so the
	// prior binary's scan path decrypts and unmarshals them successfully.
	// The account is seeded DISABLED (enabled=0) so the prior binary's
	// startup workers (refresh, model discovery, usage) skip it and never
	// attempt to send its token to a real upstream. The admin API lists
	// disabled accounts too (List has no enabled filter), so the restored
	// row is still served and observable without any outbound network call.
	credentials := map[string]any{
		"issuer":         "https://auth.x.ai",
		"subject":        "smoke-backup-subject",
		"email":          "smoke@example.com",
		"access_token":   "smoke-backup-access",
		"refresh_token":  "smoke-backup-refresh",
		"id_token":       "smoke-backup-id",
		"token_endpoint": "https://auth.x.ai/token",
	}
	payload, err := json.Marshal(credentials)
	if err != nil {
		t.Fatalf("marshal credentials: %v", err)
	}
	encrypted, err := appcrypto.Encrypt(keys.OAuth(), payload)
	if err != nil {
		t.Fatalf("encrypt credentials: %v", err)
	}
	fingerprint := keys.IdentityFingerprint("https://auth.x.ai", "smoke-backup-subject")
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx, `INSERT INTO accounts(id, identity_fingerprint, label, enabled, status, credentials_encrypted, expires_at, last_refresh_at, last_error, created_at, updated_at) VALUES(?, ?, ?, 0, 'ready', ?, ?, ?, '', ?, ?)`,
		"acct_backup", fingerprint[:], priorBinaryAccountLabel, encrypted, now.Add(time.Hour).Unix(), now.Unix(), now.Unix(), now.Unix()); err != nil {
		t.Fatalf("insert backup account: %v", err)
	}
	// API key row (v4 schema). key_hash is not decoded by listAPIKeys; a
	// placeholder hash is sufficient for the listing projection.
	keyHash := sha256.Sum256([]byte("smoke-backup-api-key-plaintext"))
	if _, err := db.ExecContext(ctx, `INSERT INTO api_keys(id, prefix, key_hash, label, created_at, last_used_at, revoked_at) VALUES(?, ?, ?, 'Backup key', ?, NULL, NULL)`,
		"key_backup", priorBinaryAPIKeyPrefix, keyHash[:], now.Unix()); err != nil {
		t.Fatalf("insert backup api key: %v", err)
	}
	// Representative stored Responses session row, encrypted with the
	// transcript key so the current binary can decrypt it after migration.
	inputEnc, err := appcrypto.Encrypt(keys.Transcript(), []byte(`{"input":"backup-seed"}`))
	if err != nil {
		t.Fatalf("encrypt session input: %v", err)
	}
	outputEnc, err := appcrypto.Encrypt(keys.Transcript(), []byte(`{"output":[]}`))
	if err != nil {
		t.Fatalf("encrypt session output: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO response_sessions(response_id, upstream_response_id, previous_response_id, model, preferred_account_id, input_encrypted, output_encrypted, store, created_at, expires_at) VALUES('resp_backup', NULL, NULL, 'grok-4.5', 'acct_backup', ?, ?, 1, ?, ?)`,
		inputEnc, outputEnc, now.Unix(), now.Add(24*time.Hour).Unix()); err != nil {
		t.Fatalf("insert backup session: %v", err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatalf("checkpoint v4: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close v4 db: %v", err)
	}
}

// currentMigrationCount opens a fresh data directory with the current
// store.Open and reports how many migrations the current binary applies, so
// the forward-migrated copy can be compared against the live schema rather
// than a hard-coded number.
func currentMigrationCount(t *testing.T) int {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	s, err := store.Open(ctx, dir)
	if err != nil {
		t.Fatalf("open fresh store for migration count: %v", err)
	}
	defer s.Close()
	return migrationCount(t, filepath.Join(dir, "byos.db"))
}

// assertPopulatedV4RowsSurvivedMigration confirms the forward-migrated copy
// kept the seeded account row and backfilled provider identity (v4 had no
// provider column; migration 005 sets it to xai).
func assertPopulatedV4RowsSurvivedMigration(t *testing.T, ctx context.Context, dbPath string) {
	t.Helper()
	db, err := openRawSQLite(ctx, dbPath)
	if err != nil {
		t.Fatalf("open migrated db: %v", err)
	}
	defer db.Close()
	var accountCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM accounts WHERE id='acct_backup'`).Scan(&accountCount); err != nil {
		t.Fatal(err)
	}
	if accountCount != 1 {
		t.Fatalf("migrated backup account row missing: count=%d", accountCount)
	}
	var provider string
	if err := db.QueryRowContext(ctx, `SELECT provider FROM accounts WHERE id='acct_backup'`).Scan(&provider); err != nil {
		t.Fatal(err)
	}
	if provider != "xai" {
		t.Fatalf("migrated backup account provider: expected xai, got %q", provider)
	}
	var enabled int
	if err := db.QueryRowContext(ctx, `SELECT enabled FROM accounts WHERE id='acct_backup'`).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 {
		t.Fatalf("migrated backup account should remain disabled (enabled=0), got enabled=%d", enabled)
	}
	var sessionCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM response_sessions WHERE response_id='resp_backup'`).Scan(&sessionCount); err != nil {
		t.Fatal(err)
	}
	if sessionCount != 1 {
		t.Fatalf("migrated backup session row missing: count=%d", sessionCount)
	}
}

// assertPriorBinarySessionRowUnchanged confirms the restored backup the prior
// binary opened still carries the representative session row unchanged on disk.
func assertPriorBinarySessionRowUnchanged(t *testing.T, ctx context.Context, dbPath string) {
	t.Helper()
	db, err := openRawSQLite(ctx, dbPath)
	if err != nil {
		t.Fatalf("open backup db: %v", err)
	}
	defer db.Close()
	var model, responseID string
	var stored int
	if err := db.QueryRowContext(ctx, `SELECT response_id, model, store FROM response_sessions WHERE response_id='resp_backup'`).Scan(&responseID, &model, &stored); err != nil {
		t.Fatalf("backup session row missing after prior binary: %v", err)
	}
	if responseID != "resp_backup" || model != "grok-4.5" || stored != 1 {
		t.Fatalf("backup session row changed: id=%q model=%q store=%d", responseID, model, stored)
	}
}

// assertPriorBinaryAccountDisabled confirms the restored backup the prior
// binary opened still has the seeded account disabled (enabled=0), proving the
// prior binary's startup workers never had an enabled account to refresh or
// dispatch against — so no outbound token-bearing network call could originate
// from the worker pool.
func assertPriorBinaryAccountDisabled(t *testing.T, ctx context.Context, dbPath string) {
	t.Helper()
	db, err := openRawSQLite(ctx, dbPath)
	if err != nil {
		t.Fatalf("open backup db for disabled check: %v", err)
	}
	defer db.Close()
	var enabled int
	if err := db.QueryRowContext(ctx, `SELECT enabled FROM accounts WHERE id='acct_backup'`).Scan(&enabled); err != nil {
		t.Fatalf("backup account row missing for disabled check: %v", err)
	}
	if enabled != 0 {
		t.Fatalf("backup account should be disabled (enabled=0) so workers skip it, got enabled=%d", enabled)
	}
}

// copySQLiteFiles copies byos.db and its WAL/SHM sidecars from src to dst so a
// pre-upgrade backup or a restore lands an exact on-disk snapshot.
func copySQLiteFiles(src, dst string) error {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		name := "byos.db" + suffix
		data, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("read %s: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(dst, name), data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}

// runCLISmokeTest runs the companion smoke-tagged cmd/byos test
// (TestCLISmokeLifecycle), which exercises the actual provider-aware CLI parser
// (runWith with `login --provider xai|devin`) and the full login lifecycle for
// BOTH xAI device and Devin callback completion through dependency seams (fake
// lifecycles, real accounts.Service, real shared callback handler) with
// safe-output assertions. This replaces the former `byos version`-only check,
// which only proved the binary built and printed a version string — not that
// the parser routes providers or the login lifecycle completes.
//
// The companion test is a separate package (cmd/byos, package main) so it must
// be invoked as a `go test` subprocess rather than called in-process. It
// inherits the smoke build tag from the harness invocation.
func runCLISmokeTest(t *testing.T) {
	t.Helper()
	root := repoRoot(t)
	cmd := exec.Command("go", "test", "-tags", "smoke", "-race", "-run", "TestCLISmokeLifecycle", "-timeout", "120s", "./cmd/byos")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("companion CLI smoke test (go test -tags smoke -race -run TestCLISmokeLifecycle ./cmd/byos) failed: %v\n%s", err, output)
	}
	t.Logf("companion CLI smoke test passed:\n%s", output)
}

// ---------------------------------------------------------------------------
// Fail-closed transport test
// ---------------------------------------------------------------------------

// TestSmokeHostTransportRejectsUnknownHost proves the smoke transport is
// fail-closed: a host that was not explicitly rewritten to a loopback fixture
// is rejected without dialing, so deterministic local smoke can never reach the
// public network.
func TestSmokeHostTransportRejectsUnknownHost(t *testing.T) {
	transport := newSmokeHostTransport()
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(local.Close)
	target, _ := url.Parse(local.URL)
	transport.rewrite("rewritten.example", target)

	// A rewritten host reaches the local fixture.
	req, _ := http.NewRequest(http.MethodGet, "http://rewritten.example/", nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("rewritten host should reach fixture: %v", err)
	}
	_ = resp.Body.Close()

	// An unknown production host is rejected without dialing. Use a host that
	// would hang/succeed if dialed so the explicit rejection (not a network
	// error) is what the assertion observes.
	req, _ = http.NewRequest(http.MethodGet, "http://api.production-upstream.example/", nil)
	_, err = transport.RoundTrip(req)
	if err == nil {
		t.Fatal("unknown host was dialed instead of rejected")
	}
	if !strings.Contains(err.Error(), "not rewritten to a local fixture") {
		t.Fatalf("unknown host rejection error should mention fail-closed reason, got: %v", err)
	}
}
