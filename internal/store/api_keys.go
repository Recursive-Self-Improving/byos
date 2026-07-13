package store

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"time"
)

type APIKey struct {
	ID, Prefix, Label     string
	CreatedAt             time.Time
	LastUsedAt, RevokedAt *time.Time
}
type APIKeyRepository struct {
	db              *sql.DB
	lastUseInterval time.Duration
}

func NewAPIKeyRepository(db *sql.DB) *APIKeyRepository {
	return &APIKeyRepository{db: db, lastUseInterval: time.Hour}
}
func (r *APIKeyRepository) Create(ctx context.Context, id, prefix, label, plaintext string, now time.Time) (APIKey, error) {
	hash := sha256.Sum256([]byte(plaintext))
	created := time.Unix(now.Unix(), 0).UTC()
	_, err := r.db.ExecContext(ctx, `INSERT INTO api_keys(id,prefix,key_hash,label,created_at) VALUES(?,?,?,?,?)`, id, prefix, hash[:], label, created.Unix())
	if err != nil {
		return APIKey{}, err
	}
	return APIKey{ID: id, Prefix: prefix, Label: label, CreatedAt: created}, nil
}
func (r *APIKeyRepository) Authenticate(ctx context.Context, prefix, plaintext string, now time.Time) (APIKey, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return APIKey{}, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id,prefix,key_hash,label,created_at,last_used_at,revoked_at FROM api_keys WHERE prefix=?`, prefix)
	if err != nil {
		return APIKey{}, err
	}
	candidate := sha256.Sum256([]byte(plaintext))
	var matched APIKey
	found := false
	for rows.Next() {
		var value APIKey
		var stored []byte
		var created int64
		var used, revoked sql.NullInt64
		if err := rows.Scan(&value.ID, &value.Prefix, &stored, &value.Label, &created, &used, &revoked); err != nil {
			rows.Close()
			return APIKey{}, err
		}
		if len(stored) == len(candidate) && subtle.ConstantTimeCompare(stored, candidate[:]) == 1 && !revoked.Valid {
			value.CreatedAt = time.Unix(created, 0).UTC()
			value.LastUsedAt = timePtr(used)
			matched = value
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return APIKey{}, err
	}
	if err := rows.Close(); err != nil {
		return APIKey{}, err
	}
	if !found {
		return APIKey{}, sql.ErrNoRows
	}
	if matched.LastUsedAt == nil || matched.LastUsedAt.Before(now.Add(-r.lastUseInterval)) {
		used := time.Unix(now.Unix(), 0).UTC()
		result, err := tx.ExecContext(ctx, `UPDATE api_keys SET last_used_at=? WHERE id=? AND revoked_at IS NULL`, used.Unix(), matched.ID)
		if err != nil {
			return APIKey{}, err
		}
		if err := requireAffected(result); err != nil {
			return APIKey{}, err
		}
		matched.LastUsedAt = &used
	}
	if err := tx.Commit(); err != nil {
		return APIKey{}, err
	}
	return matched, nil
}
func (r *APIKeyRepository) List(ctx context.Context) ([]APIKey, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id,prefix,label,created_at,last_used_at,revoked_at FROM api_keys ORDER BY created_at,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []APIKey
	for rows.Next() {
		var value APIKey
		var created int64
		var used, revoked sql.NullInt64
		if err := rows.Scan(&value.ID, &value.Prefix, &value.Label, &created, &used, &revoked); err != nil {
			return nil, err
		}
		value.CreatedAt = time.Unix(created, 0).UTC()
		value.LastUsedAt = timePtr(used)
		value.RevokedAt = timePtr(revoked)
		result = append(result, value)
	}
	return result, rows.Err()
}
func (r *APIKeyRepository) Revoke(ctx context.Context, id string, now time.Time) error {
	result, err := r.db.ExecContext(ctx, `UPDATE api_keys SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, now.Unix(), id)
	if err != nil {
		return err
	}
	return requireAffected(result)
}
