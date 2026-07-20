package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
)

// backfillOAuthSessionIDs populates every legacy oauth_sessions row that lacks
// a session_id with a distinct CSPRNG-generated opaque handle, then creates the
// unique partial index that enforces (provider, flow_type, session_id)
// uniqueness. It is idempotent: rows that already have a session_id are left
// untouched, and the index is created only if it does not exist.
//
// This runs as a Go post-migration step because SQLite's randomblob() is not
// guaranteed to be a CSPRNG; the assignment requires true safe random
// management SessionIDs. Callback authorization remains separate and is still
// keyed by raw state hash + PKCE.
func backfillOAuthSessionIDs(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin oauth session id backfill: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `SELECT state_hash FROM oauth_sessions WHERE session_id IS NULL`)
	if err != nil {
		return fmt.Errorf("query legacy oauth sessions: %w", err)
	}
	type rowKey struct{ stateHash []byte }
	var pending []rowKey
	for rows.Next() {
		var key rowKey
		if err := rows.Scan(&key.stateHash); err != nil {
			rows.Close()
			return fmt.Errorf("scan legacy oauth session: %w", err)
		}
		pending = append(pending, key)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close legacy oauth session rows: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate legacy oauth sessions: %w", err)
	}

	for _, key := range pending {
		id, err := newSessionIDHex()
		if err != nil {
			return fmt.Errorf("generate legacy session id: %w", err)
		}
		result, err := tx.ExecContext(ctx, `UPDATE oauth_sessions SET session_id=? WHERE state_hash=? AND session_id IS NULL`, id, key.stateHash)
		if err != nil {
			return fmt.Errorf("backfill legacy session id: %w", err)
		}
		if err := requireAffected(result); err != nil {
			return fmt.Errorf("backfill legacy session id affected: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS oauth_sessions_provider_flow_session_id_idx ON oauth_sessions(provider, flow_type, session_id) WHERE session_id IS NOT NULL`); err != nil {
		return fmt.Errorf("create oauth session id index: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit oauth session id backfill: %w", err)
	}
	return nil
}

// newSessionIDHex generates a 24-byte CSPRNG session id encoded as unpadded
// base64url, matching the encoding used by provider.NewSessionID for new rows.
func newSessionIDHex() (string, error) {
	var buf [24]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}
