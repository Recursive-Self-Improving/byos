package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	appcrypto "byos/internal/crypto"
)

type UsageSnapshot struct {
	ID         int64
	AccountID  string
	Normalized json.RawMessage
	Raw        json.RawMessage
	FetchedAt  time.Time
	Stale      bool
	Error      string
}
type UsageRepository struct {
	db  *sql.DB
	key [32]byte
}

func NewUsageRepository(db *sql.DB, keys appcrypto.Keys) *UsageRepository {
	return &UsageRepository{db: db, key: keys.Billing()}
}
func (r *UsageRepository) Put(ctx context.Context, v UsageSnapshot) error {
	var encrypted any
	if len(v.Raw) > 0 {
		value, err := appcrypto.Encrypt(r.key, v.Raw)
		if err != nil {
			return err
		}
		encrypted = value
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO usage_snapshots(account_id,normalized_json,raw_encrypted,fetched_at,stale,error) VALUES(?,?,?,?,?,?)`, v.AccountID, string(v.Normalized), encrypted, v.FetchedAt.Unix(), boolInt(v.Stale), nullString(v.Error))
	return err
}
func (r *UsageRepository) Latest(ctx context.Context, accountID string) (UsageSnapshot, error) {
	return r.latest(ctx, `SELECT id,account_id,normalized_json,raw_encrypted,fetched_at,stale,COALESCE(error,'') FROM usage_snapshots WHERE account_id=? ORDER BY fetched_at DESC,id DESC LIMIT 1`, accountID)
}

func (r *UsageRepository) LatestComplete(ctx context.Context, accountID string) (UsageSnapshot, error) {
	return r.latest(ctx, `SELECT id,account_id,normalized_json,raw_encrypted,fetched_at,stale,COALESCE(error,'') FROM usage_snapshots WHERE account_id=? AND json_type(normalized_json,'$.monthly')='object' ORDER BY fetched_at DESC,id DESC LIMIT 1`, accountID)
}

func (r *UsageRepository) latest(ctx context.Context, query, accountID string) (UsageSnapshot, error) {
	var v UsageSnapshot
	var normalized string
	var encrypted sql.NullString
	var fetched int64
	var stale int
	if err := r.db.QueryRowContext(ctx, query, accountID).Scan(&v.ID, &v.AccountID, &normalized, &encrypted, &fetched, &stale, &v.Error); err != nil {
		return UsageSnapshot{}, err
	}
	v.Normalized = json.RawMessage(normalized)
	v.FetchedAt = time.Unix(fetched, 0).UTC()
	v.Stale = stale != 0
	if encrypted.Valid {
		raw, err := appcrypto.Decrypt(r.key, encrypted.String)
		if err != nil {
			return UsageSnapshot{}, err
		}
		v.Raw = raw
	}
	return v, nil
}

func (r *UsageRepository) StaleFallback(ctx context.Context, accountID, refreshError string) (UsageSnapshot, error) {
	snapshot, err := r.Latest(ctx, accountID)
	if err != nil {
		return UsageSnapshot{}, err
	}
	snapshot.Stale = true
	snapshot.Error = refreshError
	return snapshot, nil
}
func (r *UsageRepository) Cleanup(ctx context.Context, before time.Time) (int64, error) {
	result, err := r.db.ExecContext(ctx, `DELETE FROM usage_snapshots WHERE rowid IN (SELECT rowid FROM usage_snapshots WHERE fetched_at<? LIMIT ?)`, before.Unix(), cleanupBatchSize)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
