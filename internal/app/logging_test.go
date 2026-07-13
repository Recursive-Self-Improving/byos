package app

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestLoggerForAddsOpaqueIDsOnly(t *testing.T) {
	var output bytes.Buffer
	logger := NewLogger(&output, slog.LevelInfo)
	ctx := WithAccountID(WithRequestID(context.Background(), "request-1"), "account-opaque")
	LoggerFor(ctx, logger).Info("handled")
	text := output.String()
	for _, expected := range []string{"request-1", "account-opaque", "handled"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("log missing %q: %s", expected, text)
		}
	}
	for _, forbidden := range []string{"prompt", "response_body"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("log contains %q", forbidden)
		}
	}
}
