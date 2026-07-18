package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"byos/internal/app"
	"byos/internal/config"
	oauthxai "byos/internal/oauth/xai"
)

func TestVersionCommand(t *testing.T) {
	var output bytes.Buffer
	deps := defaults()
	deps.stdout = &output
	if err := runWith(context.Background(), []string{"version"}, deps); err != nil {
		t.Fatal(err)
	}
	wantPrefix := "byos " + version + " (commit " + commit + ", built " + buildDate + ", grok-client "
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
	if got := verificationURL(oauthxai.DeviceAuthorization{VerificationURI: "https://auth.x.ai/device"}); got != "https://auth.x.ai/device" {
		t.Fatalf("fallback=%q", got)
	}
	if got := verificationURL(oauthxai.DeviceAuthorization{VerificationURI: "https://auth.x.ai/device", VerificationURIComplete: "https://auth.x.ai/device?code=1"}); got != "https://auth.x.ai/device?code=1" {
		t.Fatalf("complete=%q", got)
	}
}

func TestLoginCancellationClosesRuntime(t *testing.T) {
	t.Setenv("BYOS_MASTER_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32)))
	t.Setenv("BYOS_ADMIN_PASSWORD", "password")
	t.Setenv("BYOS_ADMIN_API_KEY", "admin-key")
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	var runtime *app.Runtime
	deps := defaults()
	deps.loadConfig = func(string) (config.Config, error) { return cfg, nil }
	deps.newRuntime = func(ctx context.Context, cfg config.Config, secrets config.Secrets, logger *slog.Logger) (*app.Runtime, error) {
		created, err := app.New(ctx, cfg, secrets, logger)
		runtime = created
		return created, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	deps.loginRuntime = func(ctx context.Context, _ *app.Runtime, _ io.Writer) error { cancel(); <-ctx.Done(); return ctx.Err() }
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
