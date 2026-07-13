package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	appcrypto "supergrok-api/internal/crypto"
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
	pending := OAuthSession{State: "restart-state", DeviceCode: "restart-device", UserCode: "RESTART", TokenEndpoint: "https://auth.x.ai/token", PollInterval: 5 * time.Second, ExpiresAt: now.Add(time.Hour)}
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
	sessions, err := repo.ListPending(ctx, now)
	if err != nil || len(sessions) != 1 || sessions[0].State != pending.State || sessions[0].DeviceCode != pending.DeviceCode {
		t.Fatalf("pending after restart = %+v, %v", sessions, err)
	}
	if err := repo.Transition(ctx, pending.State, "completed", ""); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"cancelled", "failed", "expired", "completed"} {
		if err := repo.Transition(ctx, pending.State, status, ""); err != sql.ErrNoRows {
			t.Fatalf("terminal -> %s error = %v", status, err)
		}
	}
	if sessions, err := repo.ListPending(ctx, now); err != nil || len(sessions) != 0 {
		t.Fatalf("terminal listed as pending: %+v, %v", sessions, err)
	}
	if err := repo.Transition(ctx, "missing", "pending", ""); err == nil {
		t.Fatal("invalid terminal status accepted")
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
	account, err := accounts.UpsertLogin(ctx, Account{Credentials: AccountCredentials{Issuer: "https://auth.x.ai", Subject: "restart-repo", AccessToken: "token", TokenEndpoint: "https://auth.x.ai/token"}})
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
