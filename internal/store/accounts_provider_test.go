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

func TestAccountProvidersRoundTripAndDevinCredentialsStayEncrypted(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{19}, 32))
	if err != nil {
		t.Fatal(err)
	}
	first, err := Open(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	databasePath := first.Path()
	repo := NewAccountRepository(first.DB, keys)
	xai, err := repo.UpsertLogin(ctx, Account{
		Provider: provider.XAI,
		Label:    "xAI",
		Credentials: AccountCredentials{
			Issuer: "https://auth.x.ai", Subject: "provider-round-trip", AccessToken: "xai-access-token", TokenEndpoint: "https://auth.x.ai/token",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(45 * time.Minute).Truncate(time.Second)
	const opaqueToken = "devin-opaque-token-provider-persistence-sentinel"
	devin, err := repo.UpsertLogin(ctx, Account{
		Provider: provider.Devin,
		Label:    "Devin",
		Credentials: AccountCredentials{
			OpaqueToken: opaqueToken, OpaqueTokenExpiresAt: &expires,
		},
		ExpiresAt: &expires,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(ctx, devin.ID, "Devin renamed", false); err != nil {
		t.Fatal(err)
	}
	if err := first.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{databasePath, databasePath + "-wal", databasePath + "-shm"} {
		data, readErr := os.ReadFile(path)
		if errors.Is(readErr, os.ErrNotExist) {
			continue
		}
		if readErr != nil {
			t.Fatal(readErr)
		}
		if bytes.Contains(data, []byte(opaqueToken)) {
			t.Fatalf("%s contains plaintext Devin token", path)
		}
	}

	second, err := Open(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	reopened := NewAccountRepository(second.DB, keys)
	gotXAI, err := reopened.Get(ctx, xai.ID)
	if err != nil {
		t.Fatal(err)
	}
	gotDevin, err := reopened.Get(ctx, devin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotXAI.Provider != provider.XAI {
		t.Fatalf("xAI provider = %q", gotXAI.Provider)
	}
	if gotDevin.Provider != provider.Devin || gotDevin.Label != "Devin renamed" || gotDevin.Enabled {
		t.Fatalf("Devin projection = %+v", gotDevin)
	}
	if gotDevin.Credentials.OpaqueToken != opaqueToken || gotDevin.Credentials.OpaqueTokenExpiresAt == nil || !gotDevin.Credentials.OpaqueTokenExpiresAt.Equal(expires) {
		t.Fatalf("Devin credentials = %+v", gotDevin.Credentials)
	}
	if gotDevin.ExpiresAt == nil || !gotDevin.ExpiresAt.Equal(expires) {
		t.Fatalf("Devin expiry = %v", gotDevin.ExpiresAt)
	}
	listed, err := reopened.List(ctx)
	if err != nil || len(listed) != 2 {
		t.Fatalf("List() = %+v, %v", listed, err)
	}
	byFingerprint, err := reopened.GetByFingerprint(ctx, keys.IdentityFingerprint(provider.Devin.String(), opaqueToken))
	if err != nil || byFingerprint.ID != devin.ID || byFingerprint.Provider != provider.Devin {
		t.Fatalf("GetByFingerprint() = %+v, %v", byFingerprint, err)
	}
}

func TestAccountProviderValidationFingerprintCompatibilityAndBoundMutation(t *testing.T) {
	ctx := context.Background()
	database, keys := openRepositories(t)
	defer database.Close()
	repo := NewAccountRepository(database.DB, keys)

	if _, err := repo.UpsertLogin(ctx, Account{Credentials: AccountCredentials{Issuer: "issuer", Subject: "subject"}}); !errors.Is(err, provider.ErrInvalidKind) {
		t.Fatalf("empty provider error = %v", err)
	}
	if _, err := repo.UpsertLogin(ctx, Account{Provider: provider.Kind("other"), Credentials: AccountCredentials{Issuer: "issuer", Subject: "subject"}}); !errors.Is(err, provider.ErrInvalidKind) {
		t.Fatalf("unknown provider error = %v", err)
	}
	if _, err := repo.UpsertLogin(ctx, Account{Provider: provider.Devin}); err == nil {
		t.Fatal("empty Devin token was accepted")
	}

	const issuer = "devin"
	const subject = "stable-fingerprint"
	created, err := repo.UpsertLogin(ctx, Account{Provider: provider.XAI, Credentials: AccountCredentials{Issuer: issuer, Subject: subject, AccessToken: "first"}})
	if err != nil {
		t.Fatal(err)
	}
	wantFingerprint := keys.IdentityFingerprint(issuer, subject)
	var storedFingerprint []byte
	if err := database.DB.QueryRowContext(ctx, `SELECT identity_fingerprint FROM accounts WHERE id=?`, created.ID).Scan(&storedFingerprint); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(storedFingerprint, wantFingerprint[:]) {
		t.Fatalf("xAI fingerprint changed: %x != %x", storedFingerprint, wantFingerprint)
	}

	before, err := repo.Get(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkReloginRequired(ctx, created.ID, provider.Devin); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("wrong-provider mutation error = %v", err)
	}
	after, err := repo.Get(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Provider != provider.XAI || after.Status != before.Status || after.Enabled != before.Enabled || after.LastError != before.LastError || after.Credentials.AccessToken != before.Credentials.AccessToken {
		t.Fatalf("wrong-provider mutation changed row: before=%+v after=%+v", before, after)
	}
	if err := repo.MarkReloginRequired(ctx, created.ID, provider.XAI); err != nil {
		t.Fatal(err)
	}
	marked, err := repo.Get(ctx, created.ID)
	if err != nil || marked.Provider != provider.XAI || marked.Status != "relogin_required" || marked.Enabled {
		t.Fatalf("provider-bound mutation result = %+v, %v", marked, err)
	}

	// This Devin identity deliberately hashes to the same bytes as the xAI
	// issuer/subject above. A provider mismatch must reject the conflict rather
	// than transfer ownership or overwrite encrypted credentials.
	if _, err := repo.UpsertLogin(ctx, Account{Provider: provider.Devin, Credentials: AccountCredentials{OpaqueToken: subject}}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("cross-provider fingerprint collision error = %v", err)
	}
	unchanged, err := repo.Get(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Provider != provider.XAI || unchanged.Credentials.AccessToken != "first" || unchanged.Status != "relogin_required" {
		t.Fatalf("collision changed account = %+v", unchanged)
	}
}
