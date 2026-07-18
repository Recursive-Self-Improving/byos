package app

import (
	"context"
	"log/slog"

	"byos/internal/config"
)

type App struct {
	Config    config.Config
	Secrets   config.Secrets
	Logger    *slog.Logger
	Lifecycle *Lifecycle
}

func (a *App) Run(ctx context.Context) error { return a.Lifecycle.Run(ctx) }
