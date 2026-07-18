package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	appcrypto "byos/internal/crypto"
)

func openRepositories(t *testing.T) (*SQLite, appcrypto.Keys) {
	t.Helper()
	store, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return store, keys
}

func TestAccountPersistenceReloginAndPlaintextAbsence(t *testing.T) {
	ctx := context.Background()
	store, keys := openRepositories(t)
	defer store.Close()
	repo := NewAccountRepository(store.DB, keys)
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	credentials := AccountCredentials{Issuer: "https://auth.x.ai", Subject: "subject-fixture", Email: "secret@example.com", AccessToken: "access-token-fixture", RefreshToken: "refresh-token-fixture", IDToken: "id-token-fixture", TokenEndpoint: "https://auth.x.ai/token", RawIdentity: json.RawMessage(`{"sub":"subject-fixture"}`)}
	created, err := repo.UpsertLogin(ctx, Account{Label: "primary", Credentials: credentials, ExpiresAt: &expires})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(ctx, created.ID, "primary", false); err != nil {
		t.Fatal(err)
	}
	credentials.AccessToken = "rotated-access-token"
	relogged, err := repo.UpsertLogin(ctx, Account{Label: "ignored", Credentials: credentials, ExpiresAt: &expires})
	if err != nil {
		t.Fatal(err)
	}
	if relogged.ID != created.ID || relogged.Label != "primary" || relogged.Enabled || relogged.Credentials.AccessToken != "rotated-access-token" {
		t.Fatalf("relogin result = %+v", relogged)
	}
	list, err := repo.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v, %v", list, err)
	}
	if err := store.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{store.Path(), store.Path() + "-wal", store.Path() + "-shm"} {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"subject-fixture", "secret@example.com", "access-token-fixture", "rotated-access-token", "refresh-token-fixture", "id-token-fixture"} {
			if bytes.Contains(data, []byte(secret)) {
				t.Fatalf("%s contains %q", path, secret)
			}
		}
	}
	if err := repo.Update(ctx, created.ID, "renamed", false); err != nil {
		t.Fatal(err)
	}
	updated, err := repo.Get(ctx, created.ID)
	if err != nil || updated.Enabled || updated.Label != "renamed" {
		t.Fatalf("updated = %+v, %v", updated, err)
	}
	if err := repo.Delete(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Get(ctx, created.ID); err != sql.ErrNoRows {
		t.Fatalf("deleted get error = %v", err)
	}
}

func TestCapabilityAndCooldownSurviveReopen(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	first, err := Open(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := appcrypto.DeriveKeys(bytes.Repeat([]byte{8}, 32))
	accounts := NewAccountRepository(first.DB, keys)
	account, err := accounts.UpsertLogin(ctx, Account{Credentials: AccountCredentials{Issuer: "https://auth.x.ai", Subject: "cap-sub", AccessToken: "token", TokenEndpoint: "https://auth.x.ai/token"}})
	if err != nil {
		t.Fatal(err)
	}
	search := true
	caps := NewModelCapabilityRepository(first.DB)
	if err := caps.Replace(ctx, account.ID, []ModelCapability{{AccountID: account.ID, Model: "grok-4.5", Supported: true, SupportsBackendSearch: &search, ContextWindow: 100, MaxOutputTokens: 10, ReasoningEfforts: []string{"high"}, DiscoveredAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	past := time.Now().UTC().Add(-time.Minute)
	cooldowns := NewCooldownRepository(first.DB)
	if err := cooldowns.Put(ctx, Cooldown{AccountID: account.ID, Model: "grok-4.5", Until: &past, BackoffLevel: 3, LastErrorClass: "rate_limit"}); err != nil {
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
	values, err := NewModelCapabilityRepository(second.DB).List(ctx, account.ID)
	if err != nil || len(values) != 1 || values[0].SupportsBackendSearch == nil || !*values[0].SupportsBackendSearch {
		t.Fatalf("capabilities = %+v, %v", values, err)
	}
	state, err := NewCooldownRepository(second.DB).Get(ctx, account.ID, "grok-4.5", time.Now().UTC())
	if err != nil || state.Until != nil || state.BackoffLevel != 0 {
		t.Fatalf("cooldown = %+v, %v", state, err)
	}
}

func TestEncryptedOAuthUsageAndResponseRepositories(t *testing.T) {
	ctx := context.Background()
	store, keys := openRepositories(t)
	defer store.Close()
	accounts := NewAccountRepository(store.DB, keys)
	account, err := accounts.UpsertLogin(ctx, Account{Credentials: AccountCredentials{Issuer: "https://auth.x.ai", Subject: "repo-sub", AccessToken: "token", TokenEndpoint: "https://auth.x.ai/token"}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	oauth := NewOAuthSessionRepository(store.DB, keys)
	session := OAuthSession{State: "browser-state", DeviceCode: "device-secret", UserCode: "USER-CODE", VerificationURI: "https://auth.x.ai/device", TokenEndpoint: "https://auth.x.ai/token", PollInterval: 5 * time.Second, ExpiresAt: now.Add(time.Hour)}
	if err := oauth.Create(ctx, session); err != nil {
		t.Fatal(err)
	}
	got, err := oauth.GetPending(ctx, session.State, now)
	if err != nil || got.DeviceCode != "device-secret" {
		t.Fatalf("oauth = %+v, %v", got, err)
	}
	if err := oauth.Transition(ctx, session.State, "completed", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := oauth.GetPending(ctx, session.State, now); err != sql.ErrNoRows {
		t.Fatalf("terminal session resumed: %v", err)
	}
	if err := oauth.Transition(ctx, session.State, "failed", ""); err != sql.ErrNoRows {
		t.Fatalf("terminal session mutated: %v", err)
	}
	usage := NewUsageRepository(store.DB, keys)
	if err := usage.Put(ctx, UsageSnapshot{AccountID: account.ID, Normalized: json.RawMessage(`{"weekly":{"used_percent":20}}`), Raw: json.RawMessage(`{"billing_secret":"raw-secret"}`), FetchedAt: now}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := usage.Latest(ctx, account.ID)
	if err != nil || !bytes.Contains(snapshot.Raw, []byte("raw-secret")) {
		t.Fatalf("usage = %+v, %v", snapshot, err)
	}
	responses := NewResponseRepository(store.DB, keys)
	node := ResponseSession{ResponseID: "resp_1", Model: "grok-4.5", PreferredAccountID: account.ID, Input: []byte("prompt-fixture"), Output: []byte("output-fixture"), Store: true, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := responses.Put(ctx, node); err != nil {
		t.Fatal(err)
	}
	loaded, err := responses.Get(ctx, node.ResponseID, now)
	if err != nil || !bytes.Equal(loaded.Input, node.Input) || !bytes.Equal(loaded.Output, node.Output) {
		t.Fatalf("response = %+v, %v", loaded, err)
	}
	if err := store.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"browser-state", "device-secret", "USER-CODE", "raw-secret", "prompt-fixture", "output-fixture"} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatalf("database contains %q", secret)
		}
	}
	if _, err := responses.Get(ctx, node.ResponseID, now.Add(2*time.Hour)); err != sql.ErrNoRows {
		t.Fatalf("expired response error = %v", err)
	}
	if count, err := responses.Cleanup(ctx, now.Add(2*time.Hour)); err != nil || count != 1 {
		t.Fatalf("response cleanup = %d, %v", count, err)
	}
	if count, err := usage.Cleanup(ctx, now.Add(time.Minute)); err != nil || count != 1 {
		t.Fatalf("usage cleanup = %d, %v", count, err)
	}
	if count, err := oauth.Cleanup(ctx, now.Add(2*time.Hour)); err != nil || count != 1 {
		t.Fatalf("oauth cleanup = %d, %v", count, err)
	}
}
