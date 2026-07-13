package store

import (
	"context"
	"database/sql"
	"time"
)

type Cooldown struct {
	AccountID, Model, LastErrorClass string
	Until                            *time.Time
	BackoffLevel                     int
	LastErrorAt                      *time.Time
}
type CooldownRepository struct{ db *sql.DB }

func NewCooldownRepository(db *sql.DB) *CooldownRepository { return &CooldownRepository{db: db} }
func (r *CooldownRepository) Put(ctx context.Context, value Cooldown) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO account_model_states(account_id,model,cooldown_until,backoff_level,last_error_class,last_error_at) VALUES(?,?,?,?,?,?) ON CONFLICT(account_id,model) DO UPDATE SET cooldown_until=excluded.cooldown_until,backoff_level=excluded.backoff_level,last_error_class=excluded.last_error_class,last_error_at=excluded.last_error_at`, value.AccountID, value.Model, nullableUnix(value.Until), value.BackoffLevel, nullString(value.LastErrorClass), nullableUnix(value.LastErrorAt))
	return err
}
func (r *CooldownRepository) Get(ctx context.Context, accountID, model string, now time.Time) (Cooldown, error) {
	var v Cooldown
	var until, last sql.NullInt64
	if err := r.db.QueryRowContext(ctx, `SELECT account_id,model,cooldown_until,backoff_level,COALESCE(last_error_class,''),last_error_at FROM account_model_states WHERE account_id=? AND model=?`, accountID, model).Scan(&v.AccountID, &v.Model, &until, &v.BackoffLevel, &v.LastErrorClass, &last); err != nil {
		return Cooldown{}, err
	}
	v.Until = timePtr(until)
	v.LastErrorAt = timePtr(last)
	if v.Until != nil && !v.Until.After(now) {
		v.Until = nil
		v.BackoffLevel = 0
		if _, err := r.db.ExecContext(ctx, `UPDATE account_model_states SET cooldown_until=NULL,backoff_level=0 WHERE account_id=? AND model=?`, accountID, model); err != nil {
			return Cooldown{}, err
		}
	}
	return v, nil
}
