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
	"byos/internal/config"
	appcrypto "byos/internal/crypto"
	"byos/internal/models"
	"byos/internal/store"
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

func TestPublicModelsAndReadinessRequireRoutableSearchAccount(t *testing.T) {
	expired := time.Now().Add(-time.Hour)
	for _, test := range []struct {
		name, status          string
		search                *bool
		cooling               bool
		expires               *time.Time
		refresh               string
		wantReady, wantModels int
	}{
		{name: "ready unknown capabilities", status: "ready", wantReady: http.StatusOK, wantModels: 2},
		{name: "invalid status", status: "invalid", wantReady: http.StatusServiceUnavailable},
		{name: "search unsupported", status: "ready", search: func() *bool { v := false; return &v }(), wantReady: http.StatusServiceUnavailable},
		{name: "cooling", status: "ready", cooling: true, wantReady: http.StatusServiceUnavailable},
		{name: "expired without refresh", status: "ready", expires: &expired, wantReady: http.StatusServiceUnavailable},
	} {
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
			account, err := accountsRepo.UpsertLogin(ctx, store.Account{Status: test.status, ExpiresAt: test.expires, Credentials: store.AccountCredentials{Issuer: "issuer", Subject: test.name, AccessToken: "token", RefreshToken: test.refresh, TokenEndpoint: "https://auth.x.ai/token"}})
			if err != nil {
				t.Fatal(err)
			}
			capabilities := store.NewModelCapabilityRepository(database.DB)
			if test.search != nil {
				if err := capabilities.Replace(ctx, account.ID, []store.ModelCapability{{AccountID: account.ID, Model: "grok-4.5", Supported: true, SupportsBackendSearch: test.search, DiscoveredAt: time.Now().UTC()}}); err != nil {
					t.Fatal(err)
				}
			}
			cooldowns := store.NewCooldownRepository(database.DB)
			if test.cooling {
				until := time.Now().Add(time.Hour)
				if err := cooldowns.Put(ctx, store.Cooldown{AccountID: account.ID, Model: "grok-4.5", Until: &until}); err != nil {
					t.Fatal(err)
				}
			}
			catalog := models.NewCatalog(capabilities, nil, []string{"grok-4.5"}, map[string]string{"grok": "grok-4.5"})
			projection := publicCatalog{catalog: catalog, accounts: accountsRepo, capabilities: capabilities, cooldowns: cooldowns, now: func() time.Time { return time.Now().UTC() }}
			listed, err := projection.PublicModels(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(listed) != test.wantModels {
				t.Fatalf("models=%+v", listed)
			}
			request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
			response := httptest.NewRecorder()
			readyHandler(database.DB, projection, "grok-4.5").ServeHTTP(response, request)
			if response.Code != test.wantReady {
				t.Fatalf("ready=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
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
