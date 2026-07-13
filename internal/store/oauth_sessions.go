package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	appcrypto "supergrok-api/internal/crypto"
)

type OAuthSession struct {
	State, DeviceCode, UserCode, VerificationURI, VerificationURIComplete, TokenEndpoint string
	PollInterval                                                                         time.Duration
	ExpiresAt                                                                            time.Time
	Status, SanitizedError                                                               string
	CreatedAt, UpdatedAt                                                                 time.Time
}
type OAuthSessionRepository struct {
	db  *sql.DB
	key [32]byte
}

func NewOAuthSessionRepository(db *sql.DB, keys appcrypto.Keys) *OAuthSessionRepository {
	return &OAuthSessionRepository{db: db, key: keys.OAuth()}
}
func stateHash(state string) [32]byte { return sha256.Sum256([]byte(state)) }
func (r *OAuthSessionRepository) Create(ctx context.Context, value OAuthSession) error {
	if value.Status == "" {
		value.Status = "pending"
	}
	now := time.Now().UTC()
	value.CreatedAt = now
	value.UpdatedAt = now
	payload, _ := json.Marshal(value)
	encrypted, err := appcrypto.Encrypt(r.key, payload)
	if err != nil {
		return err
	}
	hash := stateHash(value.State)
	_, err = r.db.ExecContext(ctx, `INSERT INTO oauth_sessions(state_hash,payload_encrypted,status,poll_interval_seconds,expires_at,created_at,updated_at,sanitized_error) VALUES(?,?,?,?,?,?,?,?)`, hash[:], encrypted, value.Status, int64(value.PollInterval/time.Second), value.ExpiresAt.Unix(), now.Unix(), now.Unix(), nullString(value.SanitizedError))
	return err
}
func (r *OAuthSessionRepository) GetPending(ctx context.Context, state string, now time.Time) (OAuthSession, error) {
	hash := stateHash(state)
	var encrypted, status string
	var expires int64
	if err := r.db.QueryRowContext(ctx, `SELECT payload_encrypted,status,expires_at FROM oauth_sessions WHERE state_hash=?`, hash[:]).Scan(&encrypted, &status, &expires); err != nil {
		return OAuthSession{}, err
	}
	if status != "pending" || expires <= now.Unix() {
		return OAuthSession{}, sql.ErrNoRows
	}
	plain, err := appcrypto.Decrypt(r.key, encrypted)
	if err != nil {
		return OAuthSession{}, err
	}
	var value OAuthSession
	if json.Unmarshal(plain, &value) != nil {
		return OAuthSession{}, errors.New("decode encrypted oauth session")
	}
	return value, nil
}

func (r *OAuthSessionRepository) ListPending(ctx context.Context, now time.Time) ([]OAuthSession, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT payload_encrypted FROM oauth_sessions WHERE status='pending' AND expires_at>? ORDER BY created_at`, now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sessions []OAuthSession
	for rows.Next() {
		var encrypted string
		if err := rows.Scan(&encrypted); err != nil {
			return nil, err
		}
		plain, err := appcrypto.Decrypt(r.key, encrypted)
		if err != nil {
			return nil, err
		}
		var session OAuthSession
		if err := json.Unmarshal(plain, &session); err != nil {
			return nil, errors.New("decode encrypted oauth session")
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}
func (r *OAuthSessionRepository) Transition(ctx context.Context, state, to, sanitized string) error {
	switch to {
	case "completed", "cancelled", "failed", "expired":
	default:
		return errors.New("invalid terminal oauth status")
	}
	hash := stateHash(state)
	result, err := r.db.ExecContext(ctx, `UPDATE oauth_sessions SET status=?,sanitized_error=?,updated_at=unixepoch() WHERE state_hash=? AND status='pending'`, to, nullString(sanitized), hash[:])
	if err != nil {
		return err
	}
	return requireAffected(result)
}
func (r *OAuthSessionRepository) Cleanup(ctx context.Context, before time.Time) (int64, error) {
	result, err := r.db.ExecContext(ctx, `DELETE FROM oauth_sessions WHERE expires_at<? OR (status<>'pending' AND updated_at<?)`, before.Unix(), before.Unix())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
