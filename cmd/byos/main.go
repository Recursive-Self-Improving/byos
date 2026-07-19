package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"byos/internal/app"
	"byos/internal/config"
	"byos/internal/provider"
)

var version = "dev"
var commit = "unknown"
var buildDate = "unknown"

type dependencies struct {
	loadConfig     func(string) (config.Config, error)
	loadSecrets    func() (config.Secrets, error)
	newRuntime     func(context.Context, config.Config, config.Secrets, *slog.Logger) (*app.Runtime, error)
	serveRuntime   func(context.Context, *app.Runtime) error
	loginRuntime   func(context.Context, *app.Runtime, io.Writer) error
	stdout, stderr io.Writer
}

func defaults() dependencies {
	return dependencies{loadConfig: config.Load, loadSecrets: config.LoadSecrets, newRuntime: app.New, serveRuntime: func(ctx context.Context, runtime *app.Runtime) error { return runtime.Run(ctx) }, loginRuntime: login, stdout: os.Stdout, stderr: os.Stderr}
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
	case "serve", "login":
		flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
		flags.SetOutput(deps.stderr)
		configPath := flags.String("config", "", "YAML configuration file")
		listen := flags.String("listen", "", "HTTP listen address override")
		dataDir := flags.String("data-dir", "", "data directory override")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return fmt.Errorf("usage: byos %s [--config path] [--listen address] [--data-dir path]", args[0])
		}
		cfg, err := deps.loadConfig(*configPath)
		if err != nil {
			return err
		}
		if *listen != "" {
			cfg.Server.Listen = *listen
		}
		if *dataDir != "" {
			cfg.DataDir = *dataDir
		}
		if err := cfg.Validate(); err != nil {
			return err
		}
		secrets, err := deps.loadSecrets()
		if err != nil {
			return err
		}
		ctx, cancel := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
		defer cancel()
		runtime, err := deps.newRuntime(ctx, cfg, secrets, slog.Default())
		if err != nil {
			return err
		}
		if args[0] == "serve" {
			return deps.serveRuntime(ctx, runtime)
		}
		defer runtime.Close()
		return deps.loginRuntime(ctx, runtime, deps.stdout)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
func login(ctx context.Context, runtime *app.Runtime, output io.Writer) error {
	authorization, err := runtime.Accounts.StartLogin(ctx, provider.XAI)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(output, "Open %s\nCode: %s\nWaiting for authorization...\n", verificationURL(authorization), authorization.UserCode)
	account, err := runtime.Accounts.CompleteLogin(ctx, provider.XAI, authorization.Ref.State, provider.AuthorizationCompletion{})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Account connected: %s\n", account.ID)
	return err
}
func verificationURL(authorization provider.Authorization) string {
	if authorization.VerificationURLComplete != "" {
		return authorization.VerificationURLComplete
	}
	return authorization.VerificationURL
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
