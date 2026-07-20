package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"byos/internal/app"
	"byos/internal/config"
	"byos/internal/provider"
)

var version = "dev"
var commit = "unknown"
var buildDate = "unknown"

type dependencies struct {
	loadConfig   func(string) (config.Config, error)
	loadSecrets  func() (config.Secrets, error)
	newRuntime   func(context.Context, config.Config, config.Secrets, *slog.Logger) (*app.Runtime, error)
	serveRuntime func(context.Context, *app.Runtime) error
	loginRuntime func(context.Context, *app.Runtime, provider.Kind, io.Writer, io.Writer, func(network, address string) (net.Listener, error), func(string) error) error
	// listen binds the local TCP address used by the Devin callback-only
	// listener. Injected so tests can fail bind deterministically without
	// occupying a real port.
	listen func(network, address string) (net.Listener, error)
	// openURL launches the user's browser at the authorization URL. It is
	// best-effort: failure is reported to stderr but never blocks the wait.
	// Injected so tests can observe the exact URL without spawning a process.
	openURL func(string) error
	stdout  io.Writer
	stderr  io.Writer
}

func defaults() dependencies {
	return dependencies{
		loadConfig:   config.Load,
		loadSecrets:  config.LoadSecrets,
		newRuntime:   app.New,
		serveRuntime: func(ctx context.Context, runtime *app.Runtime) error { return runtime.Run(ctx) },
		loginRuntime: login,
		listen:       net.Listen,
		openURL:      openURLDefault,
		stdout:       os.Stdout,
		stderr:       os.Stderr,
	}
}

func run(args []string) error { return runWith(context.Background(), args, defaults()) }

func runWith(parent context.Context, args []string, deps dependencies) error {
	if len(args) == 0 {
		return errors.New("usage: byos <serve|login|version>")
	}
	switch args[0] {
	case "version":
		if len(args) != 1 {
			return errors.New("usage: byos version")
		}
		_, err := fmt.Fprintf(deps.stdout, "byos %s (commit %s, built %s)\n", version, commit, buildDate)
		return err
	case "serve":
		flags := flag.NewFlagSet("serve", flag.ContinueOnError)
		flags.SetOutput(deps.stderr)
		configPath := flags.String("config", "", "YAML configuration file")
		listen := flags.String("listen", "", "HTTP listen address override")
		dataDir := flags.String("data-dir", "", "data directory override")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return fmt.Errorf("usage: byos serve [--config path] [--listen address] [--data-dir path]")
		}
		return runServe(parent, deps, *configPath, *listen, *dataDir)
	case "login":
		flags := flag.NewFlagSet("login", flag.ContinueOnError)
		flags.SetOutput(deps.stderr)
		configPath := flags.String("config", "", "YAML configuration file")
		listen := flags.String("listen", "", "HTTP listen address override")
		dataDir := flags.String("data-dir", "", "data directory override")
		providerKind := flags.String("provider", "xai", "provider to authorize (xai|devin)")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return fmt.Errorf("usage: byos login [--provider xai|devin] [--config path] [--listen address] [--data-dir path]")
		}
		kind, err := provider.ParseKind(*providerKind)
		if err != nil {
			return fmt.Errorf("invalid --provider %q: %w", *providerKind, err)
		}
		return runLogin(parent, deps, *configPath, *listen, *dataDir, kind)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func loadRuntime(parent context.Context, deps dependencies, configPath, listen, dataDir string) (context.Context, context.CancelFunc, *app.Runtime, error) {
	cfg, err := deps.loadConfig(configPath)
	if err != nil {
		return nil, nil, nil, err
	}
	if listen != "" {
		cfg.Server.Listen = listen
	}
	if dataDir != "" {
		cfg.DataDir = dataDir
	}
	if err := cfg.Validate(); err != nil {
		return nil, nil, nil, err
	}
	secrets, err := deps.loadSecrets()
	if err != nil {
		return nil, nil, nil, err
	}
	ctx, cancel := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	runtime, err := deps.newRuntime(ctx, cfg, secrets, slog.Default())
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	return ctx, cancel, runtime, nil
}

func runServe(parent context.Context, deps dependencies, configPath, listen, dataDir string) error {
	ctx, cancel, runtime, err := loadRuntime(parent, deps, configPath, listen, dataDir)
	if err != nil {
		return err
	}
	defer cancel()
	return deps.serveRuntime(ctx, runtime)
}

func runLogin(parent context.Context, deps dependencies, configPath, listen, dataDir string, kind provider.Kind) error {
	ctx, cancel, runtime, err := loadRuntime(parent, deps, configPath, listen, dataDir)
	if err != nil {
		return err
	}
	defer cancel()
	defer runtime.Close()
	return deps.loginRuntime(ctx, runtime, kind, deps.stdout, deps.stderr, deps.listen, deps.openURL)
}

func login(ctx context.Context, runtime *app.Runtime, kind provider.Kind, output, stderr io.Writer, listen func(network, address string) (net.Listener, error), openURL func(string) error) error {
	switch kind {
	case provider.XAI:
		return loginXAI(ctx, runtime, output)
	case provider.Devin:
		return loginDevin(ctx, runtime, output, stderr, listen, openURL)
	default:
		return fmt.Errorf("unsupported provider %q", kind)
	}
}

func loginXAI(ctx context.Context, runtime *app.Runtime, output io.Writer) error {
	authorization, err := runtime.Accounts.StartLogin(ctx, provider.XAI)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(output, "Open %s\nCode: %s\nWaiting for authorization...\n", verificationURL(authorization), authorization.UserCode)
	account, err := runtime.Accounts.CompleteLogin(ctx, provider.XAI, authorization.Ref, provider.AuthorizationCompletion{})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Account connected: %s\n", account.ID)
	return err
}

// loginDevin drives Devin's callback-PKCE flow from the CLI. It binds the
// configured server.listen address BEFORE starting a persisted authorization
// attempt so a bind conflict (e.g. `byos serve` already running) fails fast
// without orphaning a pending session. It serves only the configured exact
// callback path via the shared admin.CallbackHandler, prints the
// authorization URL, optionally opens a browser, and polls LoginStatus by
// SessionID until the flow completes, expires, or is cancelled. Raw state,
// callback codes, verifiers, and tokens never appear in CLI output.
// loginDevin drives Devin's callback-PKCE flow from the CLI. It binds the
// configured server.listen address BEFORE starting a persisted authorization
// attempt so a bind conflict (e.g. `byos serve` already running) fails fast
// without orphaning a pending session. It serves only the configured exact
// callback path via the shared admin.CallbackHandler, prints the
// authorization URL, optionally opens a browser, and polls LoginStatus by
// SessionID until the flow completes, expires, or is cancelled. The callback
// listener's serve loop is monitored concurrently with status polling so an
// unexpected server failure fails promptly: the pending session is cancelled
// best-effort, the server is shut down, and the error is returned without
// waiting until authorization expiry. Raw state, callback codes, verifiers,
// and tokens never appear in CLI output; the opener warning is written only
// to the injected stderr writer and is secret-free.
func loginDevin(ctx context.Context, runtime *app.Runtime, output, stderr io.Writer, listen func(network, address string) (net.Listener, error), openURL func(string) error) error {
	if err := runtime.Config.Devin.ValidateEnabled(); err != nil {
		return fmt.Errorf("Devin is not enabled: %w", err)
	}
	callbackPath := runtime.Config.Devin.OAuth.CallbackPath
	if callbackPath == "" {
		return errors.New("Devin callback path is not configured")
	}

	listener, err := listen("tcp", runtime.Config.Server.Listen)
	if err != nil {
		return fmt.Errorf("could not bind %s for Devin callback (stop any running `byos serve` first): %w", runtime.Config.Server.Listen, err)
	}

	mux := http.NewServeMux()
	mux.Handle(callbackPath, runtime.CallbackHandler)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(listener)
	}()

	authorization, err := runtime.Accounts.StartLogin(ctx, provider.Devin)
	if err != nil {
		_ = shutdownServer(server)
		_ = listener.Close()
		<-serveErr
		return err
	}

	_, _ = fmt.Fprintf(output, "Open %s\nWaiting for Devin authorization...\n", verificationURL(authorization))
	if openURL != nil {
		if openErr := openURL(verificationURL(authorization)); openErr != nil {
			_, _ = fmt.Fprintln(stderr, "could not open browser; open the URL above manually")
		}
	}

	waitErr := waitForDevinCompletion(ctx, runtime, authorization, output, serveErr)
	shutdownErr := shutdownServer(server)
	_ = listener.Close()
	// Drain any remaining serve error without blocking. waitForDevinCompletion
	// may have already consumed the buffered value when the listener failed
	// mid-wait; a blocking drain there would deadlock since the serve goroutine
	// has already exited. Only an unconsumed, non-shutdown error that the wait
	// did not observe takes precedence over a nil waitErr.
	select {
	case serveErrValue := <-serveErr:
		if serveErrValue != nil && !errors.Is(serveErrValue, http.ErrServerClosed) && waitErr == nil {
			waitErr = serveErrValue
		}
	default:
	}
	if waitErr != nil {
		return waitErr
	}
	return shutdownErr
}

// pollInterval is the LoginStatus poll cadence for the Devin CLI wait loop.
// It is a package var so tests can shorten it without touching real timers.
var pollInterval = 2 * time.Second

func waitForDevinCompletion(ctx context.Context, runtime *app.Runtime, authorization provider.Authorization, output io.Writer, serveErr <-chan error) error {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	deadline := authorization.ExpiresAt
	hasDeadline := !deadline.IsZero()
	for {
		session, err := runtime.Accounts.LoginStatus(ctx, provider.Devin, authorization.SessionID)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				bestEffortCancelDevin(runtime, authorization.SessionID)
				return err
			}
			return err
		}
		switch session.Status {
		case provider.AuthorizationCompleted:
			if session.AccountID == "" {
				return errors.New("Devin authorization completed without an account")
			}
			_, err := fmt.Fprintf(output, "Account connected: %s\n", session.AccountID)
			return err
		case provider.AuthorizationFailed:
			bestEffortCancelDevin(runtime, authorization.SessionID)
			return errors.New("Devin authorization failed")
		case provider.AuthorizationExpired:
			return errors.New("Devin authorization expired")
		case provider.AuthorizationCancelled:
			return errors.New("Devin authorization was cancelled")
		case provider.AuthorizationPending, provider.AuthorizationConsumed, provider.AuthorizationAuthorized:
			// still in progress; keep waiting
		default:
			bestEffortCancelDevin(runtime, authorization.SessionID)
			return errors.New("Devin authorization entered an unexpected state")
		}
		if hasDeadline {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				bestEffortCancelDevin(runtime, authorization.SessionID)
				return errors.New("Devin authorization expired")
			}
		}
		select {
		case <-ctx.Done():
			bestEffortCancelDevin(runtime, authorization.SessionID)
			return ctx.Err()
		case <-serveErr:
			// The callback listener failed while we were waiting. Fail
			// promptly: cancel the pending attempt best-effort so it does
			// not orphan, then surface the server error. The serve loop
			// has already exited, so the post-wait drain will not block.
			bestEffortCancelDevin(runtime, authorization.SessionID)
			return errors.New("Devin callback listener stopped unexpectedly")
		case <-ticker.C:
		}
	}
}

// bestEffortCancelDevin attempts a provider-bound CancelLogin using a short
// detached context so cleanup never replaces the primary wait error. It is
// only invoked on external termination or a terminal failure status; a
// consumed session (in-flight exchange) is intentionally left alone.
func bestEffortCancelDevin(runtime *app.Runtime, sessionID provider.SessionID) {
	if runtime == nil || sessionID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = runtime.Accounts.CancelLogin(ctx, provider.Devin, sessionID)
}

// shutdownServer gracefully shuts down the callback server with a bounded
// timeout, then falls back to Close if Shutdown stalls. This ordering
// guarantees an in-flight callback cannot touch SQLite after Runtime.Close.
func shutdownServer(server *http.Server) error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
		return err
	}
	return nil
}

func verificationURL(authorization provider.Authorization) string {
	if authorization.VerificationURLComplete != "" {
		return authorization.VerificationURLComplete
	}
	return authorization.VerificationURL
}

// openURLDefault launches the platform browser at the given URL as a single
// argv value, never through a shell. Failure is non-fatal.
func openURLDefault(url string) error {
	var command string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		command = "open"
		args = []string{url}
	case "windows":
		command = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	default:
		command = "xdg-open"
		args = []string{url}
	}
	return exec.Command(command, args...).Start()
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
