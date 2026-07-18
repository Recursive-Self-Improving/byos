package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	appcrypto "byoo/internal/crypto"
)

const oauthAuthorizationRetention = 24 * time.Hour

type OAuthAuthorization struct {
	AccessToken, RefreshToken, IDToken, TokenType string
	ExpiresIn                                     int
	AuthorizedAt, ExpiresAt                       time.Time
}

type OAuthSession struct {
	State, DeviceCode, UserCode, VerificationURI, VerificationURIComplete, TokenEndpoint string
	PollInterval                                                                         time.Duration
	ExpiresAt                                                                            time.Time
	Status, SanitizedError, AccountID                                                    string
	Authorization                                                                        *OAuthAuthorization
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
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encrypted, err := appcrypto.Encrypt(r.key, payload)
	if err != nil {
		return err
	}
	hash := stateHash(value.State)
	_, err = r.db.ExecContext(ctx, `INSERT INTO oauth_sessions(state_hash,payload_encrypted,status,poll_interval_seconds,expires_at,created_at,updated_at,sanitized_error) VALUES(?,?,?,?,?,?,?,?)`, hash[:], encrypted, value.Status, int64(value.PollInterval/time.Second), value.ExpiresAt.Unix(), now.Unix(), now.Unix(), nullString(value.SanitizedError))
	return err
}

func (r *OAuthSessionRepository) Get(ctx context.Context, state string) (OAuthSession, error) {
	hash := stateHash(state)
	return r.scan(r.db.QueryRowContext(ctx, `SELECT payload_encrypted,status,poll_interval_seconds,expires_at,created_at,updated_at,sanitized_error FROM oauth_sessions WHERE state_hash=?`, hash[:]))
}

func (r *OAuthSessionRepository) GetPending(ctx context.Context, state string, now time.Time) (OAuthSession, error) {
	value, err := r.Get(ctx, state)
	if err != nil {
		return OAuthSession{}, err
	}
	if value.Status != "pending" || !now.Before(value.ExpiresAt) {
		return OAuthSession{}, sql.ErrNoRows
	}
	return value, nil
}

func (r *OAuthSessionRepository) GetResumable(ctx context.Context, state string, now time.Time) (OAuthSession, error) {
	value, err := r.Get(ctx, state)
	if err != nil {
		return OAuthSession{}, err
	}
	if value.Status == "authorized" {
		return value, nil
	}
	if value.Status != "pending" || !now.Before(value.ExpiresAt) {
		return OAuthSession{}, sql.ErrNoRows
	}
	return value, nil
}

func (r *OAuthSessionRepository) ListPending(ctx context.Context, now time.Time) ([]OAuthSession, error) {
	return r.list(ctx, `SELECT payload_encrypted,status,poll_interval_seconds,expires_at,created_at,updated_at,sanitized_error FROM oauth_sessions WHERE status='pending' AND expires_at>? ORDER BY created_at`, now.Unix())
}

func (r *OAuthSessionRepository) ListResumable(ctx context.Context, now time.Time) ([]OAuthSession, error) {
	return r.list(ctx, `SELECT payload_encrypted,status,poll_interval_seconds,expires_at,created_at,updated_at,sanitized_error FROM oauth_sessions WHERE (status='pending' AND expires_at>?) OR status='authorized' ORDER BY created_at`, now.Unix())
}

func (r *OAuthSessionRepository) Authorize(ctx context.Context, state string, authorization OAuthAuthorization, now time.Time) error {
	if authorization.AccessToken == "" {
		return errors.New("oauth authorization access token is required")
	}
	return r.mutateResumable(ctx, state, now, func(value *OAuthSession) error {
		if value.Status != "pending" || !now.Before(value.ExpiresAt) {
			return sql.ErrNoRows
		}
		value.Status = "authorized"
		value.SanitizedError = ""
		value.Authorization = &authorization
		return nil
	})
}

func (r *OAuthSessionRepository) Complete(ctx context.Context, state, accountID string, now time.Time) error {
	if accountID == "" {
		return errors.New("completed oauth session account ID is required")
	}
	return r.mutateResumable(ctx, state, now, func(value *OAuthSession) error {
		if value.Status != "authorized" {
			return sql.ErrNoRows
		}
		value.Status = "completed"
		value.SanitizedError = ""
		value.AccountID = accountID
		value.Authorization = nil
		value.DeviceCode = ""
		value.TokenEndpoint = ""
		return nil
	})
}

func (r *OAuthSessionRepository) Transition(ctx context.Context, state, to, sanitized string) error {
	switch to {
	case "completed", "cancelled", "failed", "expired":
	default:
		return errors.New("invalid terminal oauth status")
	}
	return r.mutateResumable(ctx, state, time.Now().UTC(), func(value *OAuthSession) error {
		value.Status = to
		value.SanitizedError = sanitized
		value.Authorization = nil
		value.DeviceCode = ""
		value.TokenEndpoint = ""
		if to != "completed" {
			value.AccountID = ""
		}
		return nil
	})
}

func (r *OAuthSessionRepository) Cleanup(ctx context.Context, before time.Time) (int64, error) {
	authorizedBefore := before.Add(-oauthAuthorizationRetention)
	result, err := r.db.ExecContext(ctx, `DELETE FROM oauth_sessions WHERE rowid IN (SELECT rowid FROM oauth_sessions WHERE (status='pending' AND expires_at<?) OR (status='authorized' AND updated_at<?) OR (status NOT IN ('pending','authorized') AND updated_at<?) LIMIT ?)`, before.Unix(), authorizedBefore.Unix(), before.Unix(), cleanupBatchSize)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

type oauthSessionScanner interface {
	Scan(...any) error
}

func (r *OAuthSessionRepository) scan(row oauthSessionScanner) (OAuthSession, error) {
	var value OAuthSession
	var encrypted, status string
	var pollInterval, expiresAt, createdAt, updatedAt int64
	var sanitized sql.NullString
	if err := row.Scan(&encrypted, &status, &pollInterval, &expiresAt, &createdAt, &updatedAt, &sanitized); err != nil {
		return OAuthSession{}, err
	}
	plain, err := appcrypto.Decrypt(r.key, encrypted)
	if err != nil {
		return OAuthSession{}, err
	}
	if err := json.Unmarshal(plain, &value); err != nil {
		return OAuthSession{}, errors.New("decode encrypted oauth session")
	}
	value.Status = status
	value.PollInterval = time.Duration(pollInterval) * time.Second
	value.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	value.CreatedAt = time.Unix(createdAt, 0).UTC()
	value.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	value.SanitizedError = sanitized.String
	return value, nil
}

func (r *OAuthSessionRepository) list(ctx context.Context, query string, args ...any) ([]OAuthSession, error) {
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sessions []OAuthSession
	for rows.Next() {
		value, err := r.scan(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, value)
	}
	return sessions, rows.Err()
}

func (r *OAuthSessionRepository) mutateResumable(ctx context.Context, state string, now time.Time, mutate func(*OAuthSession) error) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	hash := stateHash(state)
	value, err := r.scan(tx.QueryRowContext(ctx, `SELECT payload_encrypted,status,poll_interval_seconds,expires_at,created_at,updated_at,sanitized_error FROM oauth_sessions WHERE state_hash=?`, hash[:]))
	if err != nil {
		return err
	}
	if value.Status != "pending" && value.Status != "authorized" {
		return sql.ErrNoRows
	}
	if err := mutate(&value); err != nil {
		return err
	}
	value.UpdatedAt = now.UTC()
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encrypted, err := appcrypto.Encrypt(r.key, payload)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE oauth_sessions SET payload_encrypted=?,status=?,updated_at=?,sanitized_error=? WHERE state_hash=? AND status IN ('pending','authorized')`, encrypted, value.Status, value.UpdatedAt.Unix(), nullString(value.SanitizedError), hash[:])
	if err != nil {
		return err
	}
	if err := requireAffected(result); err != nil {
		return err
	}
	return tx.Commit()
}
