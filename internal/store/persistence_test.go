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
	"byos/internal/provider"
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
	created, err := repo.UpsertLogin(ctx, Account{Provider: provider.XAI, Label: "primary", Credentials: credentials, ExpiresAt: &expires})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(ctx, created.ID, "primary", false); err != nil {
		t.Fatal(err)
	}
	credentials.AccessToken = "rotated-access-token"
	relogged, err := repo.UpsertLogin(ctx, Account{Provider: provider.XAI, Label: "ignored", Credentials: credentials, ExpiresAt: &expires})
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
	account, err := accounts.UpsertLogin(ctx, Account{Provider: provider.XAI, Credentials: AccountCredentials{Issuer: "https://auth.x.ai", Subject: "cap-sub", AccessToken: "token", TokenEndpoint: "https://auth.x.ai/token"}})
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
	account, err := accounts.UpsertLogin(ctx, Account{Provider: provider.XAI, Credentials: AccountCredentials{Issuer: "https://auth.x.ai", Subject: "repo-sub", AccessToken: "token", TokenEndpoint: "https://auth.x.ai/token"}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	oauth := NewOAuthSessionRepository(store.DB, keys)
	session := OAuthSession{Provider: provider.XAI, FlowType: OAuthFlowDevice, State: "browser-state", DeviceCode: "device-secret", UserCode: "USER-CODE", VerificationURI: "https://auth.x.ai/device", TokenEndpoint: "https://auth.x.ai/token", PollInterval: 5 * time.Second, ExpiresAt: now.Add(time.Hour)}
	if err := oauth.Create(ctx, session); err != nil {
		t.Fatal(err)
	}
	got, err := oauth.GetPending(ctx, provider.XAI, OAuthFlowDevice, session.State, now)
	if err != nil || got.DeviceCode != "device-secret" {
		t.Fatalf("oauth = %+v, %v", got, err)
	}
	authorization := OAuthAuthorization{AccessToken: "oauth-access-token", AuthorizedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := oauth.Authorize(ctx, provider.XAI, OAuthFlowDevice, session.State, authorization, now); err != nil {
		t.Fatal(err)
	}
	if err := oauth.Complete(ctx, provider.XAI, OAuthFlowDevice, session.State, account.ID, now); err != nil {
		t.Fatal(err)
	}
	_, pendingErr := oauth.GetPending(ctx, provider.XAI, OAuthFlowDevice, session.State, now)
	if !errors.Is(pendingErr, sql.ErrNoRows) {
		t.Fatalf("terminal session resumed: %v", pendingErr)
	}
	// A terminal session must not be classifiable as a cancellable conflict:
	// GetPending returns a plain not-found for non-pending rows, while
	// mutation methods (Fail below) distinguish ErrOAuthTerminalConflict.
	if errors.Is(pendingErr, ErrOAuthTerminalConflict) {
		t.Fatalf("GetPending must not surface terminal conflict: %v", pendingErr)
	}
	if err := oauth.Fail(ctx, provider.XAI, OAuthFlowDevice, session.State, "", now); !errors.Is(err, ErrOAuthTerminalConflict) {
		t.Fatalf("terminal session mutated: %v", err)
	}
	usage := NewUsageRepository(store.DB, keys)
	if err := usage.Put(ctx, UsageSnapshot{AccountID: account.ID, Normalized: json.RawMessage(`{"monthly":{"limit":100,"used":25,"remaining":75,"reset_at":"2030-01-01T00:00:00Z"}}`), FetchedAt: now.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := usage.Put(ctx, UsageSnapshot{AccountID: account.ID, Normalized: json.RawMessage(`{"weekly":{"used_percent":20}}`), Raw: json.RawMessage(`{"billing_secret":"raw-secret"}`), FetchedAt: now}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := usage.Latest(ctx, account.ID)
	if err != nil || !bytes.Contains(snapshot.Raw, []byte("raw-secret")) {
		t.Fatalf("usage = %+v, %v", snapshot, err)
	}
	completeUsage, err := usage.LatestComplete(ctx, account.ID)
	if err != nil || !bytes.Contains(completeUsage.Normalized, []byte(`"used":25`)) || !completeUsage.FetchedAt.Equal(now.Add(-time.Minute)) {
		t.Fatalf("complete usage = %+v, %v", completeUsage, err)
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
	if count, err := usage.Cleanup(ctx, now.Add(time.Minute)); err != nil || count != 2 {
		t.Fatalf("usage cleanup = %d, %v", count, err)
	}
	if count, err := oauth.Cleanup(ctx, now.Add(2*time.Hour)); err != nil || count != 1 {
		t.Fatalf("oauth cleanup = %d, %v", count, err)
	}
}

func TestDevinOAuthTransactionDurablePayloadInventory(t *testing.T) {
	ctx := context.Background()
	database, keys := openRepositories(t)
	defer database.Close()
	now := time.Now().UTC().Truncate(time.Second)
	state := "inventory-raw-state"
	verifier := "inventory-pkce-verifier"
	redirectURI := "https://inventory.example.test/oauth/callback"
	token := "inventory-opaque-token"
	createConsumedDevinSession(t, database.DB, keys, state, verifier, redirectURI, now)
	created, err := NewDevinOAuthTransaction(database.DB, keys).Complete(ctx, state, devinAccount(token, now.Add(time.Hour)), now)
	if err != nil {
		t.Fatal(err)
	}
	var accountEnvelope, oauthEnvelope string
	if err := database.DB.QueryRowContext(ctx, `SELECT credentials_encrypted FROM accounts WHERE id=?`, created.ID).Scan(&accountEnvelope); err != nil {
		t.Fatal(err)
	}
	hash := stateHash(state)
	if err := database.DB.QueryRowContext(ctx, `SELECT payload_encrypted FROM oauth_sessions WHERE state_hash=?`, hash[:]).Scan(&oauthEnvelope); err != nil {
		t.Fatal(err)
	}
	accountPlain, err := appcrypto.Decrypt(keys.OAuth(), accountEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	oauthPlain, err := appcrypto.Decrypt(keys.OAuth(), oauthEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	var accountPayload, oauthPayload map[string]json.RawMessage
	if err := json.Unmarshal(accountPlain, &accountPayload); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(oauthPlain, &oauthPayload); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"code", "state", "user_jwt", "raw_state", "authorization_code"} {
		if _, ok := accountPayload[forbidden]; ok {
			t.Fatalf("account payload contains forbidden field %q", forbidden)
		}
		if _, ok := oauthPayload[forbidden]; ok {
			t.Fatalf("oauth payload contains forbidden field %q", forbidden)
		}
	}
	if len(oauthPayload) != 1 || string(oauthPayload["account_id"]) != `"`+created.ID+`"` {
		t.Fatalf("completed oauth payload = %s", oauthPlain)
	}
}
