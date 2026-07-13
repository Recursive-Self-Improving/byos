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
	if _, err := r.db.ExecContext(ctx, `UPDATE account_model_states SET cooldown_until=NULL,backoff_level=0 WHERE account_id=? AND model=? AND cooldown_until IS NOT NULL AND cooldown_until<=?`, accountID, model, now.Unix()); err != nil {
		return Cooldown{}, err
	}
	var v Cooldown
	var until, last sql.NullInt64
	if err := r.db.QueryRowContext(ctx, `SELECT account_id,model,cooldown_until,backoff_level,COALESCE(last_error_class,''),last_error_at FROM account_model_states WHERE account_id=? AND model=?`, accountID, model).Scan(&v.AccountID, &v.Model, &until, &v.BackoffLevel, &v.LastErrorClass, &last); err != nil {
		return Cooldown{}, err
	}
	v.Until = timePtr(until)
	v.LastErrorAt = timePtr(last)
	return v, nil
}

func (r *CooldownRepository) Ready(ctx context.Context, accountID, model string) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO account_model_states(account_id,model,cooldown_until,backoff_level) VALUES(?,?,NULL,0) ON CONFLICT(account_id,model) DO UPDATE SET cooldown_until=NULL,backoff_level=0`, accountID, model)
	return err
}

func (r *CooldownRepository) AdvanceRateLimit(ctx context.Context, accountID, model, errorClass string, now time.Time) (Cooldown, error) {
	var value Cooldown
	var until, last sql.NullInt64
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO account_model_states(account_id,model,cooldown_until,backoff_level,last_error_class,last_error_at)
		VALUES(?,?,?,1,?,?)
		ON CONFLICT(account_id,model) DO UPDATE SET
			backoff_level=CASE WHEN account_model_states.cooldown_until IS NULL OR account_model_states.cooldown_until<=? THEN 1 ELSE MIN(account_model_states.backoff_level+1,6) END,
			cooldown_until=?+CASE WHEN account_model_states.cooldown_until IS NULL OR account_model_states.cooldown_until<=? THEN 60 WHEN account_model_states.backoff_level<=1 THEN 120 WHEN account_model_states.backoff_level=2 THEN 240 WHEN account_model_states.backoff_level=3 THEN 480 WHEN account_model_states.backoff_level=4 THEN 960 ELSE 1800 END,
			last_error_class=excluded.last_error_class,last_error_at=excluded.last_error_at
		RETURNING account_id,model,cooldown_until,backoff_level,COALESCE(last_error_class,''),last_error_at`,
		accountID, model, now.Add(time.Minute).Unix(), errorClass, now.Unix(), now.Unix(), now.Unix(), now.Unix(),
	).Scan(&value.AccountID, &value.Model, &until, &value.BackoffLevel, &value.LastErrorClass, &last)
	if err != nil {
		return Cooldown{}, err
	}
	value.Until = timePtr(until)
	value.LastErrorAt = timePtr(last)
	return value, nil
}
