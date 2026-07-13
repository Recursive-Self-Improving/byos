package app

import (
	"context"
	"io"
	"log/slog"
)

type contextKey string

const (
	requestIDKey contextKey = "request_id"
	accountIDKey contextKey = "account_id"
)

func NewLogger(output io.Writer, level slog.Leveler) *slog.Logger {
	return slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: level}))
}

func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

func WithAccountID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, accountIDKey, id)
}

func LoggerFor(ctx context.Context, logger *slog.Logger) *slog.Logger {
	attrs := make([]any, 0, 4)
	if id, _ := ctx.Value(requestIDKey).(string); id != "" {
		attrs = append(attrs, "request_id", id)
	}
	if id, _ := ctx.Value(accountIDKey).(string); id != "" {
		attrs = append(attrs, "account_id", id)
	}
	return logger.With(attrs...)
}
