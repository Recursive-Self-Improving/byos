package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	appcrypto "byos/internal/crypto"
	"byos/internal/provider"
)

func TestOAuthPendingEnumerationAfterRestartAndTerminalImmutability(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	keys, _ := appcrypto.DeriveKeys(bytes.Repeat([]byte{9}, 32))
	now := time.Now().UTC().Truncate(time.Second)
	first, err := Open(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	repo := NewOAuthSessionRepository(first.DB, keys)
	pending := OAuthSession{Provider: provider.XAI, FlowType: OAuthFlowDevice, State: "restart-state", DeviceCode: "restart-device", UserCode: "RESTART", TokenEndpoint: "https://auth.x.ai/token", PollInterval: 5 * time.Second, ExpiresAt: now.Add(time.Hour)}
	if err := repo.Create(ctx, pending); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	repo = NewOAuthSessionRepository(second.DB, keys)
	sessions, err := repo.ListPending(ctx, provider.XAI, OAuthFlowDevice, now)
	if err != nil || len(sessions) != 1 || sessions[0].State != pending.State || sessions[0].DeviceCode != pending.DeviceCode {
		t.Fatalf("pending after restart = %+v, %v", sessions, err)
	}
	authorization := OAuthAuthorization{AccessToken: "restart-access-token", AuthorizedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := repo.Authorize(ctx, provider.XAI, OAuthFlowDevice, pending.State, authorization, now); err != nil {
		t.Fatal(err)
	}
	if err := repo.Complete(ctx, provider.XAI, OAuthFlowDevice, pending.State, "acct_restart", now); err != nil {
		t.Fatal(err)
	}
	terminalMutations := map[string]func() error{
		"cancelled": func() error { return repo.Cancel(ctx, provider.XAI, OAuthFlowDevice, pending.State, "", now) },
		"failed":    func() error { return repo.Fail(ctx, provider.XAI, OAuthFlowDevice, pending.State, "", now) },
		"expired":   func() error { return repo.Expire(ctx, provider.XAI, OAuthFlowDevice, pending.State, "", now) },
		"completed": func() error {
			return repo.Complete(ctx, provider.XAI, OAuthFlowDevice, pending.State, "acct_other", now)
		},
	}
	for status, mutate := range terminalMutations {
		if err := mutate(); err != sql.ErrNoRows {
			t.Fatalf("terminal -> %s error = %v", status, err)
		}
	}
	if sessions, err := repo.ListPending(ctx, provider.XAI, OAuthFlowDevice, now); err != nil || len(sessions) != 0 {
		t.Fatalf("terminal listed as pending: %+v, %v", sessions, err)
	}
	if err := repo.Complete(ctx, provider.XAI, OAuthFlowDevice, "missing", "acct_missing", now); err == nil {
		t.Fatal("invalid terminal status accepted")
	}
}

func TestOAuthConsumedCallbackFinalizesAfterRestartByHashOnly(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	state := "callback-restart-state"
	session := OAuthSession{
		Provider: provider.XAI,
		FlowType: OAuthFlowCallbackPKCE,
		State:    state,
		Pending: &OAuthPendingPayload{
			Verifier:    "callback-verifier-secret",
			RedirectURI: "http://127.0.0.1/callback",
			ExpiresAt:   now.Add(time.Hour),
		},
		ExpiresAt: now.Add(time.Hour),
	}
	first, err := Open(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	repo := NewOAuthSessionRepository(first.DB, keys)
	if err := repo.Create(ctx, session); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := Open(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	repo = NewOAuthSessionRepository(second.DB, keys)
	resumable, err := repo.ListResumable(ctx, provider.XAI, OAuthFlowCallbackPKCE, now)
	if err != nil || len(resumable) != 1 || resumable[0].Status != "pending" || resumable[0].Pending == nil {
		t.Fatalf("pending callback after restart = %+v, %v", resumable, err)
	}
	consumed, err := repo.Consume(ctx, provider.XAI, OAuthFlowCallbackPKCE, state, now)
	if err != nil || consumed.Verifier != session.Pending.Verifier || consumed.RedirectURI != session.Pending.RedirectURI {
		t.Fatalf("consumed callback = %+v, %v", consumed, err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}

	third, err := Open(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	repo = NewOAuthSessionRepository(third.DB, keys)
	resumable, err = repo.ListResumable(ctx, provider.XAI, OAuthFlowCallbackPKCE, now)
	if err != nil || len(resumable) != 1 {
		t.Fatalf("consumed callback after restart = %+v, %v", resumable, err)
	}
	recovered := resumable[0]
	if recovered.Status != "consumed" || recovered.State != "" || recovered.Pending != nil || len(recovered.StateHash) != 32 {
		t.Fatalf("recovered consumed callback exposed secrets = %+v", recovered)
	}
	if _, err := repo.Consume(ctx, provider.XAI, OAuthFlowCallbackPKCE, state, now); err != sql.ErrNoRows {
		t.Fatalf("consumed callback replay error = %v", err)
	}
	if err := repo.Cancel(ctx, provider.XAI, OAuthFlowCallbackPKCE, state, "", now); err != sql.ErrNoRows {
		t.Fatalf("consumed callback cancel error = %v", err)
	}
	if err := repo.Expire(ctx, provider.XAI, OAuthFlowCallbackPKCE, state, "", now); err != sql.ErrNoRows {
		t.Fatalf("consumed callback expire error = %v", err)
	}
	if err := repo.Complete(ctx, provider.XAI, OAuthFlowCallbackPKCE, state, "", now); err == nil {
		t.Fatal("consumed callback completed without account")
	}
	if err := repo.FailConsumedByHash(ctx, provider.XAI, OAuthFlowCallbackPKCE, recovered.StateHash, "restart interrupted", now); err != nil {
		t.Fatal(err)
	}
	failed, err := repo.Get(ctx, provider.XAI, OAuthFlowCallbackPKCE, state)
	if err != nil || failed.Status != "failed" || failed.SanitizedError != "restart interrupted" || failed.Pending != nil {
		t.Fatalf("restart-finalized callback = %+v, %v", failed, err)
	}
	if values, err := repo.ListResumable(ctx, provider.XAI, OAuthFlowCallbackPKCE, now); err != nil || len(values) != 0 {
		t.Fatalf("failed callback remained resumable = %+v, %v", values, err)
	}
}

func TestOAuthElapsedPendingBatchExpiryAfterRestartDisposesSecrets(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{12}, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 19, 20, 0, 0, 0, time.UTC)
	const (
		state    = "RESTART-ELAPSED-STATE-4d82c1"
		verifier = "RESTART-ELAPSED-VERIFIER-b9e30a"
		redirect = "https://restart-elapsed.example.test/callback/7a4f"
	)
	first, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	repo := NewOAuthSessionRepository(first.DB, keys)
	if err := repo.Create(ctx, OAuthSession{Provider: provider.Devin, FlowType: OAuthFlowCallbackPKCE, State: state, Pending: &OAuthPendingPayload{Verifier: verifier, RedirectURI: redirect, ExpiresAt: now}, ExpiresAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	repo = NewOAuthSessionRepository(second.DB, keys)
	if count, err := repo.ExpirePendingBefore(ctx, provider.Devin, OAuthFlowCallbackPKCE, now); err != nil || count != 1 {
		t.Fatalf("expired count = %d, %v", count, err)
	}
	if values, err := repo.ListResumable(ctx, provider.Devin, OAuthFlowCallbackPKCE, now); err != nil || len(values) != 0 {
		t.Fatalf("elapsed session remained resumable = %+v, %v", values, err)
	}
	got, err := repo.Get(ctx, provider.Devin, OAuthFlowCallbackPKCE, state)
	if err != nil || got.Status != "expired" || got.Pending != nil {
		t.Fatalf("expired restart session = %+v, %v", got, err)
	}
	assertOAuthFilesExclude(t, second.Path(), state, verifier, redirect)
	if err := second.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	assertOAuthFilesExclude(t, second.Path(), state, verifier, redirect)
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	assertOAuthFilesExclude(t, second.Path(), state, verifier, redirect)
	third, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	assertOAuthFilesExclude(t, third.Path(), state, verifier, redirect)
	got, err = NewOAuthSessionRepository(third.DB, keys).Get(ctx, provider.Devin, OAuthFlowCallbackPKCE, state)
	if err != nil || got.Status != "expired" || got.Pending != nil {
		t.Fatalf("reopened expired session = %+v, %v", got, err)
	}
}

func TestUsageAndResponsesSurviveRestartAndPreserveBrokenChain(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	keys, _ := appcrypto.DeriveKeys(bytes.Repeat([]byte{10}, 32))
	now := time.Now().UTC().Truncate(time.Second)
	first, err := Open(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	accounts := NewAccountRepository(first.DB, keys)
	account, err := accounts.UpsertLogin(ctx, Account{Provider: provider.XAI, Credentials: AccountCredentials{Issuer: "https://auth.x.ai", Subject: "restart-repo", AccessToken: "token", TokenEndpoint: "https://auth.x.ai/token"}})
	if err != nil {
		t.Fatal(err)
	}
	usage := NewUsageRepository(first.DB, keys)
	if err := usage.Put(ctx, UsageSnapshot{AccountID: account.ID, Normalized: json.RawMessage(`{"weekly":{"used_percent":10}}`), Raw: json.RawMessage(`{"private":"billing"}`), FetchedAt: now}); err != nil {
		t.Fatal(err)
	}
	responses := NewResponseRepository(first.DB, keys)
	parent := ResponseSession{ResponseID: "parent", Model: "grok-4.5", Input: []byte("parent-input"), Output: []byte("parent-output"), Store: true, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Minute)}
	child := ResponseSession{ResponseID: "child", PreviousResponseID: "parent", Model: "grok-4.5", Input: []byte("child-input"), Output: []byte("child-output"), Store: true, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := responses.Put(ctx, parent); err != nil {
		t.Fatal(err)
	}
	if err := responses.Put(ctx, child); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	usage = NewUsageRepository(second.DB, keys)
	snapshot, err := usage.Latest(ctx, account.ID)
	if err != nil || !bytes.Contains(snapshot.Raw, []byte("billing")) {
		t.Fatalf("usage after restart = %+v, %v", snapshot, err)
	}
	fallback, err := usage.StaleFallback(ctx, account.ID, "refresh failed")
	if err != nil || !fallback.Stale || fallback.Error != "refresh failed" {
		t.Fatalf("stale fallback = %+v, %v", fallback, err)
	}
	responses = NewResponseRepository(second.DB, keys)
	loaded, err := responses.Get(ctx, "child", now)
	if err != nil || loaded.PreviousResponseID != "parent" {
		t.Fatalf("child after restart = %+v, %v", loaded, err)
	}
	if count, err := responses.Cleanup(ctx, now.Add(2*time.Minute)); err != nil || count != 1 {
		t.Fatalf("cleanup = %d, %v", count, err)
	}
	loaded, err = responses.Get(ctx, "child", now.Add(2*time.Minute))
	if err != nil || loaded.PreviousResponseID != "parent" {
		t.Fatalf("cleanup truncated chain = %+v, %v", loaded, err)
	}
	if _, err := responses.Get(ctx, "parent", now.Add(2*time.Minute)); err != sql.ErrNoRows {
		t.Fatalf("expired parent error = %v", err)
	}
}
