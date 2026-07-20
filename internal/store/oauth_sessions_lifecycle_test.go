package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	appcrypto "byos/internal/crypto"
	"byos/internal/provider"
)

func TestOAuthAuthorizationAndCompletionSurviveRestart(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{17}, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	first, err := Open(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	repository := NewOAuthSessionRepository(first.DB, keys)
	session := OAuthSession{
		Provider:        provider.XAI,
		FlowType:        OAuthFlowDevice,
		State:           "persisted-completion-state",
		DeviceCode:      "device-code-secret",
		UserCode:        "USER-CODE",
		VerificationURI: "https://auth.x.ai/device",
		TokenEndpoint:   "https://auth.x.ai/token",
		PollInterval:    5 * time.Second,
		ExpiresAt:       now.Add(10 * time.Minute),
	}
	if err := repository.Create(ctx, session); err != nil {
		t.Fatal(err)
	}
	if err := repository.Complete(ctx, provider.XAI, OAuthFlowDevice, session.State, "acct_too_early", now); !errors.Is(err, ErrOAuthTerminalConflict) {
		t.Fatalf("pending session completed without authorization: %v", err)
	}
	authorization := OAuthAuthorization{
		AccessToken:  "access-token-secret",
		RefreshToken: "refresh-token-secret",
		IDToken:      "id-token-secret",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		AuthorizedAt: now,
		ExpiresAt:    now.Add(time.Hour),
	}
	if err := repository.Authorize(ctx, provider.XAI, OAuthFlowDevice, session.State, authorization, now); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.GetPending(ctx, provider.XAI, OAuthFlowDevice, session.State, now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("authorized session still pending: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := Open(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	repository = NewOAuthSessionRepository(second.DB, keys)
	resumable, err := repository.ListResumable(ctx, provider.XAI, OAuthFlowDevice, now)
	if err != nil || len(resumable) != 1 {
		t.Fatalf("resumable after restart = %+v, %v", resumable, err)
	}
	if resumable[0].Status != "authorized" || resumable[0].Authorization == nil || resumable[0].Authorization.AccessToken != authorization.AccessToken {
		t.Fatalf("authorized session after restart = %+v", resumable[0])
	}
	if err := repository.Complete(ctx, provider.XAI, OAuthFlowDevice, session.State, "acct_persisted", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	completed, err := repository.Get(ctx, provider.XAI, OAuthFlowDevice, session.State)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != "completed" || completed.AccountID != "acct_persisted" || completed.Authorization != nil || completed.DeviceCode != "" {
		t.Fatalf("completed session = %+v", completed)
	}
	if err := repository.Complete(ctx, provider.XAI, OAuthFlowDevice, session.State, "acct_other", now.Add(2*time.Second)); !errors.Is(err, ErrOAuthTerminalConflict) {
		t.Fatalf("terminal completion mutated: %v", err)
	}
	if values, err := repository.ListResumable(ctx, provider.XAI, OAuthFlowDevice, now); err != nil || len(values) != 0 {
		t.Fatalf("completed session remained resumable: %+v, %v", values, err)
	}

	if err := second.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	databaseBytes, err := os.ReadFile(second.Path())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{session.State, "device-code-secret", "USER-CODE", "access-token-secret", "refresh-token-secret", "id-token-secret"} {
		if bytes.Contains(databaseBytes, []byte(secret)) {
			t.Fatalf("database contains OAuth secret %q", secret)
		}
	}
}
