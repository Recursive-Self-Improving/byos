package store

import (
	"context"
	"database/sql"
	"errors"
)

type LocalUsageCounters struct {
	Requests     int64
	Failures     int64
	InputTokens  int64
	OutputTokens int64
}

type LocalUsageRepository struct{ db *sql.DB }

func NewLocalUsageRepository(db *sql.DB) *LocalUsageRepository { return &LocalUsageRepository{db: db} }

func (r *LocalUsageRepository) Add(ctx context.Context, accountID string, delta LocalUsageCounters) error {
	if delta.Requests < 0 || delta.Failures < 0 || delta.InputTokens < 0 || delta.OutputTokens < 0 {
		return errors.New("local usage deltas cannot be negative")
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO local_usage_counters(account_id,requests,failures,input_tokens,output_tokens,updated_at)
		VALUES(?,?,?,?,?,unixepoch())
		ON CONFLICT(account_id) DO UPDATE SET
		requests=requests+excluded.requests,
		failures=failures+excluded.failures,
		input_tokens=input_tokens+excluded.input_tokens,
		output_tokens=output_tokens+excluded.output_tokens,
		updated_at=unixepoch()`, accountID, delta.Requests, delta.Failures, delta.InputTokens, delta.OutputTokens)
	return err
}

func (r *LocalUsageRepository) Get(ctx context.Context, accountID string) (LocalUsageCounters, error) {
	var counters LocalUsageCounters
	err := r.db.QueryRowContext(ctx, `SELECT requests,failures,input_tokens,output_tokens FROM local_usage_counters WHERE account_id=?`, accountID).Scan(&counters.Requests, &counters.Failures, &counters.InputTokens, &counters.OutputTokens)
	if errors.Is(err, sql.ErrNoRows) {
		return LocalUsageCounters{}, nil
	}
	return counters, err
}
