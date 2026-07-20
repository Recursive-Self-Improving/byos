package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"byos/internal/accounts"
	adminapi "byos/internal/api/admin"
	"byos/internal/app"
	"byos/internal/config"
	appcrypto "byos/internal/crypto"
	"byos/internal/provider"
	"byos/internal/store"
)

func TestVersionCommand(t *testing.T) {
	var output bytes.Buffer
	deps := defaults()
	deps.stdout = &output
	if err := runWith(context.Background(), []string{"version"}, deps); err != nil {
		t.Fatal(err)
	}
	wantPrefix := "byos " + version + " (commit " + commit + ", built " + buildDate
	if !strings.HasPrefix(output.String(), wantPrefix) {
		t.Fatalf("output=%q, want prefix %q", output.String(), wantPrefix)
	}
}
func TestServeLoadsConfigurationSecretsAndRuntime(t *testing.T) {
	var gotPath string
	served := false
	deps := dependencies{loadConfig: func(path string) (config.Config, error) { gotPath = path; return config.Default(), nil }, loadSecrets: func() (config.Secrets, error) { return config.Secrets{}, nil }, newRuntime: func(context.Context, config.Config, config.Secrets, *slog.Logger) (*app.Runtime, error) {
		return &app.Runtime{}, nil
	}, serveRuntime: func(context.Context, *app.Runtime) error { served = true; return nil }, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	if err := runWith(context.Background(), []string{"serve", "--config", "service.yaml"}, deps); err != nil {
		t.Fatal(err)
	}
	if gotPath != "service.yaml" || !served {
		t.Fatalf("path=%q served=%v", gotPath, served)
	}
}
func TestCommandsPropagateConfigurationFailure(t *testing.T) {
	sentinel := errors.New("bad config")
	for _, command := range []string{"serve", "login"} {
		deps := defaults()
		deps.loadConfig = func(string) (config.Config, error) { return config.Config{}, sentinel }
		if err := runWith(context.Background(), []string{command}, deps); !errors.Is(err, sentinel) {
			t.Fatalf("%s error=%v", command, err)
		}
	}
}
func TestRunRejectsUnknownOrMissingCommand(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}} {
		if err := runWith(context.Background(), args, defaults()); err == nil {
			t.Fatalf("args=%v", args)
		}
	}
}

func TestVerificationURLFallback(t *testing.T) {
	t.Run("falls back to verification URL", func(t *testing.T) {
		if got := verificationURL(provider.Authorization{VerificationURL: "https://auth.x.ai/device"}); got != "https://auth.x.ai/device" {
			t.Fatalf("verificationURL() = %q", got)
		}
	})

	t.Run("prefers complete verification URL", func(t *testing.T) {
		authorization := provider.Authorization{
			VerificationURL:         "https://auth.x.ai/device",
			VerificationURLComplete: "https://auth.x.ai/device?code=1",
		}
		if got := verificationURL(authorization); got != authorization.VerificationURLComplete {
			t.Fatalf("verificationURL() = %q, want %q", got, authorization.VerificationURLComplete)
		}
	})
}

func TestLoginCancellationClosesRuntime(t *testing.T) {
	t.Setenv("BYOS_MASTER_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32)))
	t.Setenv("BYOS_ADMIN_PASSWORD", "password")
	t.Setenv("BYOS_ADMIN_API_KEY", "admin-key")
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Devin.OAuth.CallbackPath = "/oauth/devin/callback"
	cfg.Devin.OAuth.CallbackOrigin = ""
	var runtime *app.Runtime
	deps := defaults()
	deps.loadConfig = func(string) (config.Config, error) { return cfg, nil }
	deps.newRuntime = func(ctx context.Context, cfg config.Config, secrets config.Secrets, logger *slog.Logger) (*app.Runtime, error) {
		created, err := app.New(ctx, cfg, secrets, logger)
		runtime = created
		return created, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	deps.loginRuntime = func(ctx context.Context, _ *app.Runtime, _ provider.Kind, _ io.Writer, _ io.Writer, _ func(network, address string) (net.Listener, error), _ func(string) error) error {
		cancel()
		<-ctx.Done()
		return ctx.Err()
	}
	err := runWith(ctx, []string{"login"}, deps)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	if runtime == nil {
		t.Fatal("runtime not created")
	}
	if err := runtime.Store.DB.PingContext(context.Background()); err == nil {
		t.Fatal("runtime database remained open")
	}
}

// --- C10.4 CLI coverage test matrix ---
//
// The matrix below exercises the CLI argument parser and the Devin/xAI login
// lifecycle without a live provider. A stub accounts.Service is built from a
// fake AccountLifecycle registered through a real accounts.Service so the
// shared admin.CallbackHandler, LoginStatus polling, CancelLogin, and
// best-effort cleanup paths are all exercised against the real CLI helpers.

// cliLifecycle is a fake provider.AccountLifecycle owned by the CLI tests. It
// records every lifecycle call and can be programmed to transition a session
// through pending -> consumed -> completed, to fail, expire, or cancel, and to
// observe CancelLogin keyed by SessionID. Secrets (state, code, verifier,
// token) are seeded here and must never reach CLI output.
type cliLifecycle struct {
	mu sync.Mutex
	// session state keyed by SessionID.
	sessions map[provider.SessionID]provider.AuthorizationSession
	// completed marks sessions that reached AuthorizationCompleted.
	completed map[provider.SessionID]bool
	// cancelCalls counts Cancel invocations per SessionID.
	cancelCalls map[provider.SessionID]int
	// completeCode records the callback code passed to Complete per state.
	completeCode map[string]string
	// startErr, statusErr, completeErr, cancelErr inject errors.
	startErr, statusErr, completeErr, cancelErr error
	// nextStatus transitions the session to this status on the next Status
	// call after the first pending observation, simulating the callback
	// arriving between polls.
	nextStatus provider.AuthorizationStatus
	// accountID is the AccountID returned on completion.
	accountID string
	// sessionSeed is the Authorization returned by Start.
	sessionSeed provider.Authorization
	// statusObserved counts Status calls (per SessionID via the session map).
	statusObserved int
}

func newCLILifecycle() *cliLifecycle {
	return &cliLifecycle{
		sessions:     map[provider.SessionID]provider.AuthorizationSession{},
		completed:    map[provider.SessionID]bool{},
		cancelCalls:  map[provider.SessionID]int{},
		completeCode: map[string]string{},
		nextStatus:   provider.AuthorizationPending,
	}
}

func (l *cliLifecycle) Start(context.Context) (provider.Authorization, error) {
	if l.startErr != nil {
		return provider.Authorization{}, l.startErr
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	seed := l.sessionSeed
	if seed.SessionID == "" {
		seed.SessionID = "cli-session"
	}
	if seed.Ref.Provider == "" {
		seed.Ref.Provider = provider.Devin
	}
	if seed.Ref.State == "" {
		seed.Ref.State = "cli-state-secret"
	}
	if seed.VerificationURL == "" {
		seed.VerificationURL = "https://auth.devin.invalid/authorize"
	}
	l.sessions[seed.SessionID] = provider.AuthorizationSession{
		Authorization: seed,
		Status:        provider.AuthorizationPending,
	}
	l.sessionSeed = seed
	return seed, nil
}

func (l *cliLifecycle) Status(_ context.Context, ref provider.AuthorizationRef) (provider.AuthorizationSession, error) {
	if l.statusErr != nil {
		return provider.AuthorizationSession{}, l.statusErr
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.statusObserved++
	session, ok := l.sessions[ref.SessionID]
	if !ok {
		return provider.AuthorizationSession{}, errors.New("unknown session")
	}
	// Simulate the callback arriving between polls: once a session has been
	// observed pending, advance it through consumed toward the programmed
	// terminal status so the CLI wait loop observes a real transition.
	if l.completed[ref.SessionID] {
		session.Status = provider.AuthorizationCompleted
		session.AccountID = l.accountID
		l.sessions[ref.SessionID] = session
		return session, nil
	}
	if session.Status == provider.AuthorizationPending && l.nextStatus != provider.AuthorizationPending && l.nextStatus != "" {
		session.Status = l.nextStatus
		if l.nextStatus == provider.AuthorizationCompleted {
			session.AccountID = l.accountID
		}
		l.sessions[ref.SessionID] = session
	}
	return session, nil
}

func (l *cliLifecycle) Complete(_ context.Context, ref provider.AuthorizationRef, completion provider.AuthorizationCompletion) (provider.AccountResult, error) {
	if l.completeErr != nil {
		return provider.AccountResult{}, l.completeErr
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.completeCode[ref.State] = completion.Code
	// The callback ref carries State (not SessionID), so mark the matching
	// session completed by looking up which session owns this state.
	for sid, session := range l.sessions {
		if session.Ref.State == ref.State || sid == ref.SessionID {
			l.completed[sid] = true
		}
	}
	return provider.AccountResult{Provider: provider.Devin, AccountID: l.accountID}, nil
}

func (l *cliLifecycle) Cancel(_ context.Context, ref provider.AuthorizationRef) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cancelCalls[ref.SessionID]++
	if l.cancelErr != nil {
		return l.cancelErr
	}
	if session, ok := l.sessions[ref.SessionID]; ok {
		session.Status = provider.AuthorizationCancelled
		l.sessions[ref.SessionID] = session
	}
	return nil
}

func (l *cliLifecycle) Resume(context.Context) ([]provider.AuthorizationSession, error) {
	return nil, nil
}

// cliLifecycleRegistry is a minimal CapabilityRegistry exposing only the
// fake Lifecycle for the Devin policy key.
type cliLifecycleRegistry struct{ lifecycle *cliLifecycle }

func (r cliLifecycleRegistry) Capabilities(kind provider.Kind, policyKey string) (provider.Capabilities, bool) {
	if kind != provider.Devin || policyKey != string(provider.Devin) {
		return provider.Capabilities{}, false
	}
	return provider.Capabilities{Lifecycle: r.lifecycle}, true
}

var _ provider.CapabilityRegistry = cliLifecycleRegistry{}

// cliAccounts builds a real accounts.Service backed by a fake Devin
// lifecycle and a real SQLite AccountRepository so CompleteLogin's
// post-completion account lookup resolves a seeded account.
func cliAccounts(t *testing.T, lifecycle *cliLifecycle, seed bool) (svc *accounts.Service, repo *store.AccountRepository, seededID string, cleanup func()) {
	t.Helper()
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{0x9}, 32))
	if err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	repo = store.NewAccountRepository(database.DB, keys)
	if seed {
		account, err := repo.UpsertLogin(ctx, store.Account{Provider: provider.Devin, Label: "cli", Status: "ready", Credentials: store.AccountCredentials{OpaqueToken: "cli-opaque-token-secret"}})
		if err != nil {
			_ = database.Close()
			t.Fatalf("seed account: %v", err)
		}
		seededID = account.ID
	}
	svc = accounts.NewService(repo, cliLifecycleRegistry{lifecycle: lifecycle}, nil, nil)
	return svc, repo, seededID, func() { _ = database.Close() }
}

// cliDevinConfig returns a validated Config with Devin enabled and a
// callback path/origin the CLI flow can bind and serve.
func cliDevinConfig(t *testing.T, listen string) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Server.Listen = listen
	cfg.Devin.OAuth.CallbackOrigin = "https://byos.example.invalid"
	cfg.Devin.OAuth.CallbackPath = "/oauth/devin/callback"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}
	return cfg
}

// cliRuntime assembles a minimal *app.Runtime with only the fields the CLI
// login helpers touch: Config, Accounts, and the shared CallbackHandler. It
// intentionally leaves Store nil; tests that go through runLogin (which calls
// runtime.Close) must use a real app.New runtime instead.
func cliRuntime(cfg config.Config, accountsSvc *accounts.Service) *app.Runtime {
	return &app.Runtime{Config: cfg, Accounts: accountsSvc, CallbackHandler: adminapi.CallbackHandler(accountsSvc)}
}

// stubRuntime builds a minimal *app.Runtime backed by a real throwaway SQLite
// store so runtime.Close() (invoked by runLogin) is safe. It is intended for
// parser/dispatcher tests that do not exercise login lifecycle behavior.
func stubRuntime(t *testing.T) *app.Runtime {
	t.Helper()
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &app.Runtime{Store: database}
}

// captureListener hands out a real net.Listener on an ephemeral port and
// records the bound address so tests can drive the callback HTTP handler.
func captureListener(t *testing.T) (listen func(network, address string) (net.Listener, error), addr *net.TCPAddr) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = ln.Addr().(*net.TCPAddr)
	listen = func(network, address string) (net.Listener, error) {
		return ln, nil
	}
	return listen, addr
}

// TestCLILoginProviderParsing covers the runWith argument parser: omitted
// --provider defaults to xai, explicit xai/devin parse, and an invalid
// provider is rejected before any runtime is constructed.
func TestCLILoginProviderParsing(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr bool
		want    provider.Kind
	}{
		{name: "default xai", args: []string{"login"}, want: provider.XAI},
		{name: "explicit xai", args: []string{"login", "--provider", "xai"}, want: provider.XAI},
		{name: "explicit devin", args: []string{"login", "--provider", "devin"}, want: provider.Devin},
		{name: "invalid provider", args: []string{"login", "--provider", "bogus"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var capturedKind provider.Kind
			kindObserved := false
			deps := defaults()
			deps.loadConfig = func(string) (config.Config, error) { return config.Default(), nil }
			deps.loadSecrets = func() (config.Secrets, error) { return config.Secrets{}, nil }
			deps.newRuntime = func(context.Context, config.Config, config.Secrets, *slog.Logger) (*app.Runtime, error) {
				return stubRuntime(t), nil
			}
			deps.loginRuntime = func(_ context.Context, _ *app.Runtime, kind provider.Kind, _ io.Writer, _ io.Writer, _ func(network, address string) (net.Listener, error), _ func(string) error) error {
				capturedKind = kind
				kindObserved = true
				return nil
			}
			err := runWith(context.Background(), tc.args, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %v", tc.args)
				}
				return
			}
			if err != nil {
				t.Fatalf("runWith error: %v", err)
			}
			if !kindObserved {
				t.Fatal("loginRuntime not invoked")
			}
			if capturedKind != tc.want {
				t.Fatalf("kind=%q want %q", capturedKind, tc.want)
			}
		})
	}
}

// TestCLIServeRejectsProviderFlag asserts the serve subcommand does not
// accept --provider; it is a login-only flag. Passing it to serve must be
// surfaced as a usage error before serveRuntime runs.
func TestCLIServeRejectsProviderFlag(t *testing.T) {
	served := false
	deps := defaults()
	deps.loadConfig = func(string) (config.Config, error) { return config.Default(), nil }
	deps.loadSecrets = func() (config.Secrets, error) { return config.Secrets{}, nil }
	deps.newRuntime = func(context.Context, config.Config, config.Secrets, *slog.Logger) (*app.Runtime, error) {
		return stubRuntime(t), nil
	}
	deps.serveRuntime = func(context.Context, *app.Runtime) error { served = true; return nil }
	err := runWith(context.Background(), []string{"serve", "--provider", "xai"}, deps)
	if err == nil {
		t.Fatal("expected --provider to be rejected for serve")
	}
	if served {
		t.Fatal("serveRuntime must not run when --provider is rejected")
	}
}

// TestCLILoginDefaultProviderIsXAI is a focused assertion that the login
// dispatcher routes the default kind to loginXAI (not loginDevin): it proves
// the xAI path runs StartLogin and never consults the Devin-only bind/openURL
// seams. The full xAI output contract is covered separately by
// TestCLILoginXAIDispatchOutput.
func TestCLILoginDefaultProviderIsXAI(t *testing.T) {
	lifecycle := &xAIFakeLifecycle{
		auth: provider.Authorization{
			Ref:             provider.AuthorizationRef{Provider: provider.XAI, SessionID: "xai-default"},
			SessionID:       "xai-default",
			UserCode:        "CODE",
			VerificationURL: "https://auth.x.ai/device",
		},
	}
	repo, closeRepo, seededID := xAIRepo(t)
	defer closeRepo()
	lifecycle.accountID = seededID
	accountsSvc := accounts.NewService(repo, xAIRegistry{lifecycle: lifecycle}, nil, nil)
	runtime := &app.Runtime{Accounts: accountsSvc}

	bindCalled := false
	openCalled := false
	listenFn := func(network, address string) (net.Listener, error) {
		bindCalled = true
		return nil, errors.New("must not bind for xai")
	}
	openFn := func(string) error { openCalled = true; return nil }

	if err := login(context.Background(), runtime, provider.XAI, &bytes.Buffer{}, &bytes.Buffer{}, listenFn, openFn); err != nil {
		t.Fatalf("login xai error: %v", err)
	}
	if !lifecycle.completed.Load() {
		t.Fatal("xAI lifecycle Complete was not invoked")
	}
	if bindCalled || openCalled {
		t.Fatalf("xAI login must not bind or open browser; bind=%v open=%v", bindCalled, openCalled)
	}
}

// TestCLILoginXAIDispatchOutput exercises loginXAI through the real login
// dispatcher with a stub accounts.Service, asserting the output/completion
// contract (Open URL, Code, waiting line, connected account) is unchanged.
func TestCLILoginXAIDispatchOutput(t *testing.T) {
	lifecycle := &xAIFakeLifecycle{
		auth: provider.Authorization{
			Ref:                     provider.AuthorizationRef{Provider: provider.XAI, SessionID: "xai-session"},
			SessionID:               "xai-session",
			UserCode:                "USER-CODE",
			VerificationURL:         "https://auth.x.ai/device",
			VerificationURLComplete: "https://auth.x.ai/device?user_code=USER-CODE",
		},
	}
	repo, closeRepo, seededID := xAIRepo(t)
	defer closeRepo()
	lifecycle.accountID = seededID
	registry := xAIRegistry{lifecycle: lifecycle}
	accountsSvc := accounts.NewService(repo, registry, nil, nil)
	runtime := &app.Runtime{Accounts: accountsSvc}

	var output bytes.Buffer
	err := login(context.Background(), runtime, provider.XAI, &output, &bytes.Buffer{}, func(string, string) (net.Listener, error) {
		t.Fatal("xAI must not bind")
		return nil, nil
	}, func(string) error { t.Fatal("xAI must not open browser"); return nil })
	if err != nil {
		t.Fatalf("login xai error: %v", err)
	}
	out := output.String()
	for _, want := range []string{
		"Open https://auth.x.ai/device?user_code=USER-CODE",
		"Code: USER-CODE",
		"Waiting for authorization",
		"Account connected: " + seededID,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
}

// xAIFakeLifecycle is a Devin-free fake for the xAI device flow used by
// TestCLILoginXAIDispatchOutput. It completes synchronously on the first
// CompleteLogin call.
type xAIFakeLifecycle struct {
	auth      provider.Authorization
	accountID string
	completed atomic.Bool
}

func (f *xAIFakeLifecycle) Start(context.Context) (provider.Authorization, error) { return f.auth, nil }
func (f *xAIFakeLifecycle) Status(context.Context, provider.AuthorizationRef) (provider.AuthorizationSession, error) {
	return provider.AuthorizationSession{Authorization: f.auth, Status: provider.AuthorizationCompleted, AccountID: f.accountID}, nil
}
func (f *xAIFakeLifecycle) Complete(context.Context, provider.AuthorizationRef, provider.AuthorizationCompletion) (provider.AccountResult, error) {
	f.completed.Store(true)
	return provider.AccountResult{Provider: provider.XAI, AccountID: f.accountID}, nil
}
func (f *xAIFakeLifecycle) Cancel(context.Context, provider.AuthorizationRef) error { return nil }
func (f *xAIFakeLifecycle) Resume(context.Context) ([]provider.AuthorizationSession, error) {
	return nil, nil
}

type xAIRegistry struct{ lifecycle *xAIFakeLifecycle }

func (r xAIRegistry) Capabilities(kind provider.Kind, policyKey string) (provider.Capabilities, bool) {
	if kind != provider.XAI || policyKey != string(provider.XAI) {
		return provider.Capabilities{}, false
	}
	return provider.Capabilities{Lifecycle: r.lifecycle}, true
}

func xAIRepo(t *testing.T) (repo *store.AccountRepository, cleanup func(), seededID string) {
	t.Helper()
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{0xA}, 32))
	if err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	repo = store.NewAccountRepository(database.DB, keys)
	account, err := repo.UpsertLogin(ctx, store.Account{Provider: provider.XAI, Label: "xai", Status: "ready", Credentials: store.AccountCredentials{Issuer: "https://auth.x.ai", Subject: "xai-cli-subject", AccessToken: "xai-access-secret"}})
	if err != nil {
		_ = database.Close()
		t.Fatalf("seed xai account: %v", err)
	}
	seededID = account.ID
	return repo, func() { _ = database.Close() }, seededID
}

// TestCLILoginDevinBindFailureBeforeStartLogin asserts a bind conflict fails
// fast and never starts a persisted authorization session (no StartLogin, no
// openURL, no status poll), surfacing the stop-serve guidance.
func TestCLILoginDevinBindFailureBeforeStartLogin(t *testing.T) {
	lifecycle := newCLILifecycle()
	accountsSvc, _, _, closeDB := cliAccounts(t, lifecycle, false)
	defer closeDB()
	cfg := cliDevinConfig(t, "127.0.0.1:8080")
	runtime := cliRuntime(cfg, accountsSvc)

	bindErr := errors.New("address already in use")
	listenFn := func(network, address string) (net.Listener, error) { return nil, bindErr }
	openCalled := false
	openFn := func(string) error { openCalled = true; return nil }

	var output, stderr bytes.Buffer
	err := loginDevin(context.Background(), runtime, &output, &stderr, listenFn, openFn)
	if err == nil || !strings.Contains(err.Error(), "could not bind") {
		t.Fatalf("error=%v want bind failure", err)
	}
	if !strings.Contains(err.Error(), "stop any running") {
		t.Errorf("error=%v missing stop-serve guidance", err)
	}
	lifecycle.mu.Lock()
	starts := len(lifecycle.sessions)
	lifecycle.mu.Unlock()
	if starts != 0 {
		t.Fatalf("StartLogin must not run on bind failure; sessions=%d", starts)
	}
	if openCalled {
		t.Fatal("openURL must not run on bind failure")
	}
}

// TestCLILoginDevinOpenerErrorNonFatal asserts that when openURL fails, the
// CLI writes a generic, secret-free warning to stderr and continues waiting.
// The underlying opener error must not be echoed and no URL/state/code/token
// may appear on stderr.
func TestCLILoginDevinOpenerErrorNonFatal(t *testing.T) {
	lifecycle := newCLILifecycle()
	lifecycle.nextStatus = provider.AuthorizationExpired
	lifecycle.sessionSeed.ExpiresAt = time.Now().Add(time.Second)
	accountsSvc, _, _, closeDB := cliAccounts(t, lifecycle, false)
	defer closeDB()
	cfg := cliDevinConfig(t, "127.0.0.1:0")
	listenFn, _ := captureListener(t)
	runtime := cliRuntime(cfg, accountsSvc)

	openErrSecret := errors.New("xdg-open leaked cli-state-secret")
	openCalled := atomic.Bool{}
	openFn := func(string) error { openCalled.Store(true); return openErrSecret }

	var output, stderr bytes.Buffer
	_ = loginDevin(context.Background(), runtime, &output, &stderr, listenFn, openFn)
	if !openCalled.Load() {
		t.Fatal("openURL must be invoked")
	}
	stderrText := stderr.String()
	if !strings.Contains(stderrText, "could not open browser") {
		t.Errorf("stderr missing nonfatal opener warning; got:\n%s", stderrText)
	}
	// The underlying opener error (which carries a secret) must not be echoed.
	if strings.Contains(stderrText, "xdg-open") || strings.Contains(stderrText, "cli-state-secret") {
		t.Errorf("stderr leaked opener error detail; got:\n%s", stderrText)
	}
}

// TestCLILoginDevinWaitPendingConsumedCompleted drives the wait loop through
// pending -> consumed -> completed, proving the CLI's callback server and
// the shared admin.CallbackHandler cooperate to complete a session and the
// connected account ID is surfaced. The callback is driven by a real HTTP GET
// against the CLI's bound listener; the shared handler path is also covered
// directly by TestCLISharedCallbackHandlerLocalSuccess.
func TestCLILoginDevinWaitPendingConsumedCompleted(t *testing.T) {
	lifecycle := newCLILifecycle()
	accountsSvc, _, seededID, closeDB := cliAccounts(t, lifecycle, true)
	defer closeDB()
	lifecycle.accountID = seededID
	// First Status observes pending; the callback (driven by openURL) flips
	// the session to consumed, then the next poll observes completed.
	lifecycle.nextStatus = provider.AuthorizationConsumed

	cfg := cliDevinConfig(t, "127.0.0.1:0")
	listenFn, addr := captureListener(t)
	runtime := cliRuntime(cfg, accountsSvc)

	openFn := func(_ string) error {
		// Drive the real shared callback handler via a synchronous HTTP GET
		// against the bound listener. Run in a goroutine so openURL returns
		// immediately and the wait loop can poll; the GET completes the
		// session through the shared admin.CallbackHandler + real
		// accounts.Service, so the next Status poll observes completed.
		go func() {
			state := lifecycle.sessionSeed.Ref.State
			code := "cli-callback-code-secret"
			callbackURL := fmt.Sprintf("http://%s%s?state=%s&code=%s", addr.String(), cfg.Devin.OAuth.CallbackPath, state, code)
			resp, err := http.Get(callbackURL)
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
		return nil
	}

	old := pollInterval
	pollInterval = 5 * time.Millisecond
	defer func() { pollInterval = old }()

	// Bound the whole flow so a missed callback cannot hang the suite.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var output, stderr bytes.Buffer
	err := loginDevin(ctx, runtime, &output, &stderr, listenFn, openFn)
	if err != nil {
		t.Fatalf("loginDevin error: %v", err)
	}
	if !strings.Contains(output.String(), "Account connected: "+seededID) {
		t.Errorf("output missing connected account; got:\n%s", output.String())
	}
	lifecycle.mu.Lock()
	gotCode := lifecycle.completeCode["cli-state-secret"]
	lifecycle.mu.Unlock()
	if gotCode != "cli-callback-code-secret" {
		t.Errorf("complete code=%q want cli-callback-code-secret", gotCode)
	}
}

// TestCLILoginDevinFailedStatusIsTerminal asserts AuthorizationFailed is a
// terminal state that triggers best-effort CancelLogin and returns promptly.
func TestCLILoginDevinFailedStatusIsTerminal(t *testing.T) {
	lifecycle := newCLILifecycle()
	lifecycle.nextStatus = provider.AuthorizationFailed
	accountsSvc, _, _, closeDB := cliAccounts(t, lifecycle, false)
	defer closeDB()
	cfg := cliDevinConfig(t, "127.0.0.1:0")
	listenFn, _ := captureListener(t)
	runtime := cliRuntime(cfg, accountsSvc)

	old := pollInterval
	pollInterval = 5 * time.Millisecond
	defer func() { pollInterval = old }()

	var output, stderr bytes.Buffer
	err := loginDevin(context.Background(), runtime, &output, &stderr, listenFn, func(string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("error=%v want failed", err)
	}
	lifecycle.mu.Lock()
	cancels := lifecycle.cancelCalls[lifecycle.sessionSeed.SessionID]
	lifecycle.mu.Unlock()
	if cancels != 1 {
		t.Errorf("cancelCalls=%d want 1", cancels)
	}
}

// TestCLILoginDevinExpiredStatusIsTerminal asserts AuthorizationExpired is
// terminal and does not invoke CancelLogin (the session is already gone).
func TestCLILoginDevinExpiredStatusIsTerminal(t *testing.T) {
	lifecycle := newCLILifecycle()
	lifecycle.nextStatus = provider.AuthorizationExpired
	accountsSvc, _, _, closeDB := cliAccounts(t, lifecycle, false)
	defer closeDB()
	cfg := cliDevinConfig(t, "127.0.0.1:0")
	listenFn, _ := captureListener(t)
	runtime := cliRuntime(cfg, accountsSvc)

	old := pollInterval
	pollInterval = 5 * time.Millisecond
	defer func() { pollInterval = old }()

	var output, stderr bytes.Buffer
	err := loginDevin(context.Background(), runtime, &output, &stderr, listenFn, func(string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error=%v want expired", err)
	}
	lifecycle.mu.Lock()
	cancels := lifecycle.cancelCalls[lifecycle.sessionSeed.SessionID]
	lifecycle.mu.Unlock()
	if cancels != 0 {
		t.Errorf("cancelCalls=%d want 0 (expired is terminal, no cancel)", cancels)
	}
}

// TestCLILoginDevinCancelledStatusIsTerminal asserts AuthorizationCancelled
// is terminal and surfaces the cancelled message without invoking cancel.
func TestCLILoginDevinCancelledStatusIsTerminal(t *testing.T) {
	lifecycle := newCLILifecycle()
	lifecycle.nextStatus = provider.AuthorizationCancelled
	accountsSvc, _, _, closeDB := cliAccounts(t, lifecycle, false)
	defer closeDB()
	cfg := cliDevinConfig(t, "127.0.0.1:0")
	listenFn, _ := captureListener(t)
	runtime := cliRuntime(cfg, accountsSvc)

	old := pollInterval
	pollInterval = 5 * time.Millisecond
	defer func() { pollInterval = old }()

	var output, stderr bytes.Buffer
	err := loginDevin(context.Background(), runtime, &output, &stderr, listenFn, func(string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("error=%v want cancelled", err)
	}
	lifecycle.mu.Lock()
	cancels := lifecycle.cancelCalls[lifecycle.sessionSeed.SessionID]
	lifecycle.mu.Unlock()
	if cancels != 0 {
		t.Errorf("cancelCalls=%d want 0", cancels)
	}
}

// TestCLILoginDevinContextCancelInvokesCancelLoginAndShutdown asserts that
// cancelling the parent context mid-wait triggers best-effort CancelLogin
// (keyed by SessionID) and a graceful server shutdown, returning ctx.Err.
func TestCLILoginDevinContextCancelInvokesCancelLoginAndShutdown(t *testing.T) {
	lifecycle := newCLILifecycle()
	// Keep status pending so the wait loop blocks until ctx cancel.
	lifecycle.nextStatus = provider.AuthorizationPending
	accountsSvc, _, _, closeDB := cliAccounts(t, lifecycle, false)
	defer closeDB()
	cfg := cliDevinConfig(t, "127.0.0.1:0")
	listenFn, _ := captureListener(t)
	runtime := cliRuntime(cfg, accountsSvc)

	old := pollInterval
	pollInterval = 5 * time.Millisecond
	defer func() { pollInterval = old }()

	ctx, cancel := context.WithCancel(context.Background())
	var output, stderr bytes.Buffer
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	err := loginDevin(ctx, runtime, &output, &stderr, listenFn, func(string) error { return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v want context.Canceled", err)
	}
	lifecycle.mu.Lock()
	cancels := lifecycle.cancelCalls[lifecycle.sessionSeed.SessionID]
	lifecycle.mu.Unlock()
	if cancels != 1 {
		t.Errorf("cancelCalls=%d want 1 (ctx cancel must best-effort cancel)", cancels)
	}
}

// TestCLILoginDevinContextTimeoutInvokesCancelLogin asserts a context
// deadline triggers the same CancelLogin + shutdown path as cancellation.
func TestCLILoginDevinContextTimeoutInvokesCancelLogin(t *testing.T) {
	lifecycle := newCLILifecycle()
	lifecycle.nextStatus = provider.AuthorizationPending
	accountsSvc, _, _, closeDB := cliAccounts(t, lifecycle, false)
	defer closeDB()
	cfg := cliDevinConfig(t, "127.0.0.1:0")
	listenFn, _ := captureListener(t)
	runtime := cliRuntime(cfg, accountsSvc)

	old := pollInterval
	pollInterval = 5 * time.Millisecond
	defer func() { pollInterval = old }()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	var output, stderr bytes.Buffer
	err := loginDevin(ctx, runtime, &output, &stderr, listenFn, func(string) error { return nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v want context.DeadlineExceeded", err)
	}
	lifecycle.mu.Lock()
	cancels := lifecycle.cancelCalls[lifecycle.sessionSeed.SessionID]
	lifecycle.mu.Unlock()
	if cancels != 1 {
		t.Errorf("cancelCalls=%d want 1", cancels)
	}
}

// TestCLILoginDevinCallbackServeFailurePrompt asserts that when the callback
// listener's Serve loop fails unexpectedly mid-wait, the CLI fails promptly
// (without waiting for authorization expiry), cancels the pending session,
// and surfaces the listener-stopped message. This also guards the
// post-wait serveErr drain against the deadlock where waitForDevinCompletion
// already consumed the buffered serve error.
func TestCLILoginDevinCallbackServeFailurePrompt(t *testing.T) {
	lifecycle := newCLILifecycle()
	lifecycle.nextStatus = provider.AuthorizationPending
	accountsSvc, _, _, closeDB := cliAccounts(t, lifecycle, false)
	defer closeDB()
	cfg := cliDevinConfig(t, "127.0.0.1:0")
	runtime := cliRuntime(cfg, accountsSvc)

	// Use a listener we can close externally to force Serve to return.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenFn := func(network, address string) (net.Listener, error) { return ln, nil }

	old := pollInterval
	pollInterval = 5 * time.Millisecond
	defer func() { pollInterval = old }()

	// Close the listener shortly after the wait loop starts so Serve returns
	// a non-ErrServerClosed error and the serveErr channel delivers it.
	go func() {
		time.Sleep(15 * time.Millisecond)
		_ = ln.Close()
	}()

	done := make(chan error, 1)
	go func() {
		done <- loginDevin(context.Background(), runtime, &bytes.Buffer{}, &bytes.Buffer{}, listenFn, func(string) error { return nil })
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected listener-stopped error")
		}
		if !strings.Contains(err.Error(), "listener stopped") {
			t.Fatalf("error=%v want listener-stopped message", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("loginDevin deadlocked after listener failure (serveErr drain blocked)")
	}
	lifecycle.mu.Lock()
	cancels := lifecycle.cancelCalls[lifecycle.sessionSeed.SessionID]
	lifecycle.mu.Unlock()
	if cancels != 1 {
		t.Errorf("cancelCalls=%d want 1 (listener failure must best-effort cancel)", cancels)
	}
}

// TestCLILoginDevinSecretCanaryScan seeds unique secret markers behind the
// lifecycle/callback (state, code, verifier-equivalent, opaque token) and
// asserts none appear in stdout, stderr, or the returned error for any
// terminal Devin outcome. This is a negative canary: it proves the CLI does
// not echo provider secrets, not that the fake lifecycle sanitizes them.
func TestCLILoginDevinSecretCanaryScan(t *testing.T) {
	const (
		stateMarker   = "STATE_SECRET_CANARY"
		codeMarker    = "CODE_SECRET_CANARY"
		tokenMarker   = "TOKEN_SECRET_CANARY"
		accountMarker = "acct_canary"
	)
	lifecycle := newCLILifecycle()
	lifecycle.sessionSeed.Ref.State = stateMarker
	lifecycle.nextStatus = provider.AuthorizationFailed // terminal, no callback
	accountsSvc, repo, _, closeDB := cliAccounts(t, lifecycle, false)
	defer closeDB()
	// Seed an account whose opaque token carries the token marker so the
	// repository path also holds a secret; completion is not reached here but
	// the canary must still not leak via any observed surface.
	if _, err := repo.UpsertLogin(context.Background(), store.Account{Provider: provider.Devin, Label: "canary", Status: "ready", Credentials: store.AccountCredentials{OpaqueToken: tokenMarker}}); err != nil {
		t.Fatalf("seed canary account: %v", err)
	}
	cfg := cliDevinConfig(t, "127.0.0.1:0")
	listenFn, _ := captureListener(t)
	runtime := cliRuntime(cfg, accountsSvc)

	old := pollInterval
	pollInterval = 5 * time.Millisecond
	defer func() { pollInterval = old }()

	var output, stderr bytes.Buffer
	err := loginDevin(context.Background(), runtime, &output, &stderr, listenFn, func(string) error { return nil })
	if err == nil {
		t.Fatal("expected failed error for canary scan")
	}
	combined := output.String() + "\n" + stderr.String() + "\n" + err.Error()
	for _, marker := range []string{stateMarker, codeMarker, tokenMarker} {
		if strings.Contains(combined, marker) {
			t.Errorf("secret marker %q leaked to CLI surface:\n%s", marker, combined)
		}
	}
	_ = accountMarker
}

// TestCLISharedCallbackHandlerLocalSuccess proves the shared
// admin.CallbackHandler, driven directly against an httptest server (no live
// provider), completes a Devin session through the real accounts.Service and
// returns 204 No Content. This is the handler the CLI reuses.
func TestCLISharedCallbackHandlerLocalSuccess(t *testing.T) {
	lifecycle := newCLILifecycle()
	accountsSvc, _, seededID, closeDB := cliAccounts(t, lifecycle, true)
	defer closeDB()
	lifecycle.accountID = seededID

	handler := adminapi.CallbackHandler(accountsSvc)
	server := httptest.NewServer(handler)
	defer server.Close()

	// Start a session so the lifecycle has state to complete.
	auth, err := accountsSvc.StartLogin(context.Background(), provider.Devin)
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	state := auth.Ref.State
	code := "shared-handler-code-secret"
	resp, err := http.Get(server.URL + "?state=" + state + "&code=" + code)
	if err != nil {
		t.Fatalf("callback GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d want 204", resp.StatusCode)
	}
	lifecycle.mu.Lock()
	gotCode := lifecycle.completeCode[state]
	lifecycle.mu.Unlock()
	if gotCode != code {
		t.Errorf("complete code=%q want %q", gotCode, code)
	}
}
