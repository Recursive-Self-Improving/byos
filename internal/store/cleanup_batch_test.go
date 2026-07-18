package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	appcrypto "byos/internal/crypto"
)

func TestCleanupRepositoriesUseFixedBatches(t *testing.T) {
	for _, name := range []string{"responses", "oauth", "admin", "usage", "cooldowns", "attempts"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			database, err := Open(ctx, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{5}, 32))
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			account, err := NewAccountRepository(database.DB, keys).UpsertLogin(ctx, Account{Credentials: AccountCredentials{Issuer: "issuer", Subject: name, AccessToken: "token", TokenEndpoint: "https://auth.x.ai/token"}})
			if err != nil {
				t.Fatal(err)
			}
			tx, err := database.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			for index := range cleanupBatchSize + 1 {
				switch name {
				case "responses":
					_, err = tx.ExecContext(ctx, `INSERT INTO response_sessions(response_id,model,input_encrypted,output_encrypted,store,created_at,expires_at) VALUES(?,?,?,?,1,?,?)`, fmt.Sprintf("r%d", index), "grok", "encrypted", "encrypted", now.Add(-2*time.Hour).Unix(), now.Add(-time.Hour).Unix())
				case "oauth":
					_, err = tx.ExecContext(ctx, `INSERT INTO oauth_sessions(state_hash,payload_encrypted,status,poll_interval_seconds,expires_at,created_at,updated_at) VALUES(?,?,'pending',5,?,?,?)`, []byte(fmt.Sprintf("state-%d", index)), "encrypted", now.Add(-time.Hour).Unix(), now.Add(-2*time.Hour).Unix(), now.Add(-2*time.Hour).Unix())
				case "admin":
					_, err = tx.ExecContext(ctx, `INSERT INTO admin_sessions(id_hash,csrf_secret_encrypted,created_at,expires_at) VALUES(?,?,?,?)`, []byte(fmt.Sprintf("admin-%d", index)), "encrypted", now.Add(-2*time.Hour).Unix(), now.Add(-time.Hour).Unix())
				case "usage":
					_, err = tx.ExecContext(ctx, `INSERT INTO usage_snapshots(account_id,normalized_json,fetched_at) VALUES(?,?,?)`, account.ID, `{}`, now.Add(-time.Hour).Unix())
				case "cooldowns":
					_, err = tx.ExecContext(ctx, `INSERT INTO account_model_states(account_id,model,cooldown_until,backoff_level) VALUES(?,?,?,1)`, account.ID, fmt.Sprintf("model-%d", index), now.Add(-time.Hour).Unix())
				case "attempts":
					hash := sha256.Sum256([]byte(fmt.Sprintf("attempt-%d", index)))
					_, err = tx.ExecContext(ctx, `INSERT INTO admin_auth_sources(source_hash,failure_count,last_failure_at,updated_at) VALUES(?,1,?,?)`, hash[:], now.Add(-2*time.Hour).Unix(), now.Add(-2*time.Hour).Unix())
				}
				if err != nil {
					_ = tx.Rollback()
					t.Fatal(err)
				}
			}
			if name == "attempts" {
				fresh := sha256.Sum256([]byte("fresh-attempt"))
				if _, err = tx.ExecContext(ctx, `INSERT INTO admin_auth_sources(source_hash,failure_count,last_failure_at,updated_at) VALUES(?,1,?,?)`, fresh[:], now.Unix(), now.Unix()); err != nil {
					_ = tx.Rollback()
					t.Fatal(err)
				}
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			var first, second int64
			switch name {
			case "responses":
				first, err = NewResponseRepository(database.DB, keys).Cleanup(ctx, now)
				if err == nil {
					second, err = NewResponseRepository(database.DB, keys).Cleanup(ctx, now)
				}
			case "oauth":
				first, err = NewOAuthSessionRepository(database.DB, keys).Cleanup(ctx, now)
				if err == nil {
					second, err = NewOAuthSessionRepository(database.DB, keys).Cleanup(ctx, now)
				}
			case "admin":
				first, err = NewAdminSessionRepository(database.DB, keys).Cleanup(ctx, now)
				if err == nil {
					second, err = NewAdminSessionRepository(database.DB, keys).Cleanup(ctx, now)
				}
			case "usage":
				cutoff := now.Add(-time.Minute)
				first, err = NewUsageRepository(database.DB, keys).Cleanup(ctx, cutoff)
				if err == nil {
					second, err = NewUsageRepository(database.DB, keys).Cleanup(ctx, cutoff)
				}
			case "cooldowns":
				first, err = NewCooldownRepository(database.DB).PromoteExpired(ctx, now)
				if err == nil {
					second, err = NewCooldownRepository(database.DB).PromoteExpired(ctx, now)
				}
			case "attempts":
				cutoff := now.Add(-time.Minute)
				first, err = NewAdminAuthThrottleRepository(database.DB).Cleanup(ctx, cutoff)
				if err == nil {
					second, err = NewAdminAuthThrottleRepository(database.DB).Cleanup(ctx, cutoff)
				}
			}
			if err != nil || first != cleanupBatchSize || second != 1 {
				t.Fatalf("first=%d second=%d err=%v", first, second, err)
			}
			if name == "attempts" {
				fresh := sha256.Sum256([]byte("fresh-attempt"))
				var count int
				if err := database.DB.QueryRowContext(ctx, `SELECT count(*) FROM admin_auth_sources WHERE source_hash=?`, fresh[:]).Scan(&count); err != nil || count != 1 {
					t.Fatalf("fresh attempt count=%d err=%v", count, err)
				}
			}
		})
	}
}
