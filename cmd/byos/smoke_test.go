//go:build smoke

// Package main contains the smoke-tagged CLI lifecycle test. It is gated
// behind the `smoke` build tag so ordinary `go test` never exercises the
// login lifecycle. Run with:
//
//	go test -tags smoke -race -run TestCLISmokeLifecycle ./cmd/byos
//
// The test exercises the actual provider-aware CLI parser (runWith with
// `login --provider xai|devin`) and the full login lifecycle for BOTH xAI
// device and Devin callback completion through dependency seams (fake
// lifecycles, real accounts.Service, real shared admin.CallbackHandler) with
// safe-output assertions. `byos version` alone is insufficient — it only
// proves the binary builds and prints a version string, not that the parser
// routes providers or the login lifecycle completes end-to-end.
//
// The C12 launched smoke harness (internal/app) runs this as a companion via
// runCLISmokeTest so a single `go test -tags smoke -race` invocation covers
// both the in-process component graph and the CLI surface.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
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

// TestCLISmokeLifecycle exercises the actual provider-aware CLI parser and
// login lifecycle for BOTH xAI device and Devin callback completion using
// dependency seams (fake lifecycles, real accounts.Service, real shared
// callback handler) with safe-output assertions.
func TestCLISmokeLifecycle(t *testing.T) {
	// --- xAI device login through the real CLI parser + login dispatcher ---
	t.Run("xAI_device_login_via_parser", func(t *testing.T) {
		lifecycle := &xAIFakeLifecycle{
			auth: provider.Authorization{
				Ref:                     provider.AuthorizationRef{Provider: provider.XAI, SessionID: "xai-smoke"},
				SessionID:               "xai-smoke",
				UserCode:                "SMOKE-XAI",
				VerificationURL:         "https://auth.x.ai/device",
				VerificationURLComplete: "https://auth.x.ai/device?user_code=SMOKE-XAI",
			},
		}
		rt, seededID := smokeXAIRuntime(t, lifecycle)

		var output, stderr bytes.Buffer
		deps := defaults()
		deps.loadConfig = func(string) (config.Config, error) { return config.Default(), nil }
		deps.loadSecrets = func() (config.Secrets, error) { return config.Secrets{}, nil }
		deps.newRuntime = func(context.Context, config.Config, config.Secrets, *slog.Logger) (*app.Runtime, error) {
			return rt, nil
		}
		deps.loginRuntime = login
		deps.stdout = &output
		deps.stderr = &stderr
		deps.listen = func(network, address string) (net.Listener, error) {
			t.Fatal("xAI login must not bind a callback listener")
			return nil, nil
		}
		deps.openURL = func(string) error {
			t.Fatal("xAI login must not open a browser")
			return nil
		}

		if err := runWith(context.Background(), []string{"login", "--provider", "xai"}, deps); err != nil {
			t.Fatalf("runWith login --provider xai: %v", err)
		}
		out := output.String()
		for _, want := range []string{
			"Open https://auth.x.ai/device?user_code=SMOKE-XAI",
			"Code: SMOKE-XAI",
			"Waiting for authorization",
			"Account connected: " + seededID,
		} {
			if !strings.Contains(out, want) {
				t.Errorf("output missing %q; got:\n%s", want, out)
			}
		}
		// Safe output: no provider secrets leaked to stdout or stderr.
		for _, secret := range []string{"xai-smoke-access-secret"} {
			if strings.Contains(out, secret) || strings.Contains(stderr.String(), secret) {
				t.Errorf("secret %q leaked to CLI output", secret)
			}
		}
		if !lifecycle.completed.Load() {
			t.Fatal("xAI lifecycle Complete was not invoked")
		}
	})

	// --- Devin callback completion through the real CLI parser + loginDevin ---
	t.Run("Devin_callback_completion_via_parser", func(t *testing.T) {
		lifecycle := newCLILifecycle()
		lifecycle.nextStatus = provider.AuthorizationConsumed
		cfg := cliDevinConfig(t, "127.0.0.1:0")
		rt, seededID := smokeDevinRuntime(t, lifecycle, cfg, true)
		lifecycle.accountID = seededID

		listenFn, addr := captureListener(t)

		var output, stderr bytes.Buffer
		deps := defaults()
		deps.loadConfig = func(string) (config.Config, error) { return cfg, nil }
		deps.loadSecrets = func() (config.Secrets, error) { return config.Secrets{}, nil }
		deps.newRuntime = func(context.Context, config.Config, config.Secrets, *slog.Logger) (*app.Runtime, error) {
			return rt, nil
		}
		deps.loginRuntime = login
		deps.stdout = &output
		deps.stderr = &stderr
		deps.listen = listenFn
		deps.openURL = func(_ string) error {
			// Drive the real shared callback handler via a synchronous HTTP
			// GET against the bound listener. Run in a goroutine so openURL
			// returns immediately and the wait loop can poll; the GET
			// completes the session through the shared admin.CallbackHandler
			// + real accounts.Service, so the next Status poll observes
			// completed.
			go func() {
				state := lifecycle.sessionSeed.Ref.State
				code := "smoke-devin-callback-code"
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

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := runWith(ctx, []string{"login", "--provider", "devin"}, deps); err != nil {
			t.Fatalf("runWith login --provider devin: %v", err)
		}
		out := output.String()
		if !strings.Contains(out, "Account connected: "+seededID) {
			t.Errorf("output missing connected account; got:\n%s", out)
		}
		// Safe output: no provider secrets leaked to stdout or stderr.
		combined := out + "\n" + stderr.String()
		for _, secret := range []string{"cli-state-secret", "smoke-devin-callback-code", "cli-opaque-token-secret"} {
			if strings.Contains(combined, secret) {
				t.Errorf("secret %q leaked to CLI output", secret)
			}
		}
	})

	// --- Parser: invalid provider rejected before runtime construction ---
	t.Run("invalid_provider_rejected", func(t *testing.T) {
		deps := defaults()
		deps.loadConfig = func(string) (config.Config, error) { return config.Default(), nil }
		deps.loadSecrets = func() (config.Secrets, error) { return config.Secrets{}, nil }
		deps.newRuntime = func(context.Context, config.Config, config.Secrets, *slog.Logger) (*app.Runtime, error) {
			t.Fatal("runtime must not be constructed for invalid provider")
			return nil, nil
		}
		err := runWith(context.Background(), []string{"login", "--provider", "bogus"}, deps)
		if err == nil {
			t.Fatal("expected error for invalid provider")
		}
		if !strings.Contains(err.Error(), "invalid --provider") {
			t.Fatalf("error should mention invalid provider, got: %v", err)
		}
	})

	// --- Parser: default provider is xai (not devin) ---
	t.Run("default_provider_is_xai", func(t *testing.T) {
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
		if err := runWith(context.Background(), []string{"login"}, deps); err != nil {
			t.Fatalf("runWith login: %v", err)
		}
		if !kindObserved {
			t.Fatal("loginRuntime not invoked")
		}
		if capturedKind != provider.XAI {
			t.Fatalf("default provider: expected xai, got %q", capturedKind)
		}
	})
}

// smokeXAIRuntime builds a real *app.Runtime backed by a real throwaway SQLite
// store and a fake xAI lifecycle so runLogin's defer runtime.Close() is safe
// and loginXAI's StartLogin/CompleteLogin resolve against a seeded account.
// The access token carries a secret marker for safe-output assertions.
func smokeXAIRuntime(t *testing.T, lifecycle *xAIFakeLifecycle) (*app.Runtime, string) {
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
	repo := store.NewAccountRepository(database.DB, keys)
	account, err := repo.UpsertLogin(ctx, store.Account{
		Provider:    provider.XAI,
		Label:       "xai-smoke",
		Status:      "ready",
		Credentials: store.AccountCredentials{Issuer: "https://auth.x.ai", Subject: "xai-smoke-subject", AccessToken: "xai-smoke-access-secret"},
	})
	if err != nil {
		_ = database.Close()
		t.Fatalf("seed xai account: %v", err)
	}
	lifecycle.accountID = account.ID
	accountsSvc := accounts.NewService(repo, xAIRegistry{lifecycle: lifecycle}, nil, nil)
	return &app.Runtime{Accounts: accountsSvc, Store: database}, account.ID
}

// smokeDevinRuntime builds a real *app.Runtime backed by a real throwaway
// SQLite store and a fake Devin lifecycle so runLogin's defer runtime.Close()
// is safe and loginDevin's bind/callback/poll path works against a seeded
// account. The opaque token carries a secret marker for safe-output assertions.
func smokeDevinRuntime(t *testing.T, lifecycle *cliLifecycle, cfg config.Config, seed bool) (*app.Runtime, string) {
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
	repo := store.NewAccountRepository(database.DB, keys)
	var seededID string
	if seed {
		account, err := repo.UpsertLogin(ctx, store.Account{
			Provider:    provider.Devin,
			Label:       "devin-smoke",
			Status:      "ready",
			Credentials: store.AccountCredentials{OpaqueToken: "cli-opaque-token-secret"},
		})
		if err != nil {
			_ = database.Close()
			t.Fatalf("seed devin account: %v", err)
		}
		seededID = account.ID
	}
	accountsSvc := accounts.NewService(repo, cliLifecycleRegistry{lifecycle: lifecycle}, nil, nil)
	return &app.Runtime{
		Config:          cfg,
		Accounts:        accountsSvc,
		CallbackHandler: adminapi.CallbackHandler(accountsSvc),
		Store:           database,
	}, seededID
}
