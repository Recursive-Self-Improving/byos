package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"byos/internal/auththrottle"
)

type AdminAuthThrottleRepository struct{ db *sql.DB }

func NewAdminAuthThrottleRepository(db *sql.DB) *AdminAuthThrottleRepository {
	return &AdminAuthThrottleRepository{db: db}
}

func (r *AdminAuthThrottleRepository) Check(ctx context.Context, source [32]byte, now time.Time, policy auththrottle.Policy) (auththrottle.Status, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return auththrottle.Status{}, fmt.Errorf("begin admin authentication throttle check: %w", err)
	}
	defer tx.Rollback()
	status := auththrottle.Status{}
	var count int
	var blocked, last sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT failure_count,blocked_until,last_failure_at FROM admin_auth_sources WHERE source_hash=?`, source[:]).Scan(&count, &blocked, &last)
	switch {
	case err == nil:
		activeUntil := unixTime(blocked)
		if activeUntil.After(now) {
			status.BlockedUntil = activeUntil
		} else if count == 5 {
			if _, err := tx.ExecContext(ctx, `DELETE FROM admin_auth_sources WHERE source_hash=?`, source[:]); err != nil {
				return auththrottle.Status{}, fmt.Errorf("clear expired admin authentication lock: %w", err)
			}
			status.Transitions = append(status.Transitions, auththrottle.Transition{Kind: auththrottle.TransitionSourceUnlocked, PriorFailureCount: count})
		} else if last.Valid && last.Int64 <= now.Add(-policy.FailureResetAfter).Unix() {
			if _, err := tx.ExecContext(ctx, `DELETE FROM admin_auth_sources WHERE source_hash=?`, source[:]); err != nil {
				return auththrottle.Status{}, fmt.Errorf("clear stale admin authentication failures: %w", err)
			}
		}
	case err != nil && err != sql.ErrNoRows:
		return auththrottle.Status{}, fmt.Errorf("read admin authentication source state: %w", err)
	}

	var windowStarted, globalBlocked sql.NullInt64
	var sourceLocks int
	err = tx.QueryRowContext(ctx, `SELECT window_started_at,source_locks,blocked_until FROM admin_auth_global WHERE id=1`).Scan(&windowStarted, &sourceLocks, &globalBlocked)
	switch {
	case err == nil:
		activeUntil := unixTime(globalBlocked)
		if activeUntil.After(now) {
			if activeUntil.After(status.BlockedUntil) {
				status.BlockedUntil = activeUntil
			}
		} else if globalBlocked.Valid {
			if _, err := tx.ExecContext(ctx, `UPDATE admin_auth_global SET window_started_at=?,source_locks=0,blocked_until=NULL,updated_at=? WHERE id=1`, now.Unix(), now.Unix()); err != nil {
				return auththrottle.Status{}, fmt.Errorf("release global admin authentication guard: %w", err)
			}
			status.Transitions = append(status.Transitions, auththrottle.Transition{Kind: auththrottle.TransitionGlobalReleased})
		} else if windowStarted.Valid && windowStarted.Int64 <= now.Add(-policy.GlobalWindow).Unix() {
			if _, err := tx.ExecContext(ctx, `UPDATE admin_auth_global SET window_started_at=?,source_locks=0,updated_at=? WHERE id=1`, now.Unix(), now.Unix()); err != nil {
				return auththrottle.Status{}, fmt.Errorf("reset global admin authentication window: %w", err)
			}
		}
	case err != nil && err != sql.ErrNoRows:
		return auththrottle.Status{}, fmt.Errorf("read global admin authentication state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return auththrottle.Status{}, fmt.Errorf("commit admin authentication throttle check: %w", err)
	}
	return status, nil
}

func (r *AdminAuthThrottleRepository) RecordFailure(ctx context.Context, source [32]byte, now time.Time, policy auththrottle.Policy) ([]auththrottle.Transition, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin admin authentication failure: %w", err)
	}
	defer tx.Rollback()
	count := 0
	var blocked, last sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT failure_count,blocked_until,last_failure_at FROM admin_auth_sources WHERE source_hash=?`, source[:]).Scan(&count, &blocked, &last)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("read admin authentication failure state: %w", err)
	}
	if err == sql.ErrNoRows || count == 5 || (last.Valid && last.Int64 <= now.Add(-policy.FailureResetAfter).Unix()) {
		count = 0
	}
	count++
	var blockedUntil *time.Time
	var transitions []auththrottle.Transition
	switch count {
	case 3:
		value := now.Add(policy.CooldownAfterThree)
		blockedUntil = &value
		transitions = append(transitions, auththrottle.Transition{Kind: auththrottle.TransitionSourceCooldown, FailureCount: count, BlockedUntil: value})
	case 4:
		value := now.Add(policy.CooldownAfterFour)
		blockedUntil = &value
		transitions = append(transitions, auththrottle.Transition{Kind: auththrottle.TransitionSourceCooldown, FailureCount: count, BlockedUntil: value})
	case 5:
		value := now.Add(policy.LockAfterFive)
		blockedUntil = &value
		transitions = append(transitions, auththrottle.Transition{Kind: auththrottle.TransitionSourceLocked, FailureCount: count, BlockedUntil: value})
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO admin_auth_sources(source_hash,failure_count,blocked_until,last_failure_at,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(source_hash) DO UPDATE SET failure_count=excluded.failure_count,blocked_until=excluded.blocked_until,last_failure_at=excluded.last_failure_at,updated_at=excluded.updated_at`, source[:], count, nullableTime(blockedUntil), now.Unix(), now.Unix())
	if err != nil {
		return nil, fmt.Errorf("record admin authentication failure: %w", err)
	}
	if count == 5 {
		global, err := r.recordSourceLock(ctx, tx, now, policy)
		if err != nil {
			return nil, err
		}
		if global != nil {
			transitions = append(transitions, *global)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit admin authentication failure: %w", err)
	}
	return transitions, nil
}

func (r *AdminAuthThrottleRepository) recordSourceLock(ctx context.Context, tx *sql.Tx, now time.Time, policy auththrottle.Policy) (*auththrottle.Transition, error) {
	var windowStarted, blocked sql.NullInt64
	locks := 0
	err := tx.QueryRowContext(ctx, `SELECT window_started_at,source_locks,blocked_until FROM admin_auth_global WHERE id=1`).Scan(&windowStarted, &locks, &blocked)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("read global admin authentication lock state: %w", err)
	}
	if err == sql.ErrNoRows || !windowStarted.Valid || windowStarted.Int64 <= now.Add(-policy.GlobalWindow).Unix() || (blocked.Valid && blocked.Int64 <= now.Unix()) {
		locks = 0
		windowStarted = sql.NullInt64{Int64: now.Unix(), Valid: true}
	}
	locks++
	var blockedUntil *time.Time
	var transition *auththrottle.Transition
	if locks >= policy.GlobalSourceLockLimit {
		value := now.Add(policy.GlobalBlockDuration)
		blockedUntil = &value
		transition = &auththrottle.Transition{Kind: auththrottle.TransitionGlobalArmed, BlockedUntil: value, GlobalSourceLocks: locks}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO admin_auth_global(id,window_started_at,source_locks,blocked_until,updated_at) VALUES(1,?,?,?,?) ON CONFLICT(id) DO UPDATE SET window_started_at=excluded.window_started_at,source_locks=excluded.source_locks,blocked_until=excluded.blocked_until,updated_at=excluded.updated_at`, windowStarted.Int64, locks, nullableTime(blockedUntil), now.Unix())
	if err != nil {
		return nil, fmt.Errorf("record global admin authentication lock: %w", err)
	}
	return transition, nil
}

func (r *AdminAuthThrottleRepository) ResetSource(ctx context.Context, source [32]byte) (auththrottle.Transition, bool, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `DELETE FROM admin_auth_sources WHERE source_hash=? RETURNING failure_count`, source[:]).Scan(&count)
	if err == sql.ErrNoRows {
		return auththrottle.Transition{}, false, nil
	}
	if err != nil {
		return auththrottle.Transition{}, false, fmt.Errorf("reset admin authentication source: %w", err)
	}
	return auththrottle.Transition{Kind: auththrottle.TransitionSourceReset, PriorFailureCount: count}, true, nil
}

func (r *AdminAuthThrottleRepository) Cleanup(ctx context.Context, before time.Time) (int64, error) {
	result, err := r.db.ExecContext(ctx, `DELETE FROM admin_auth_sources WHERE rowid IN (SELECT rowid FROM admin_auth_sources WHERE updated_at<=? LIMIT ?)`, before.Unix(), cleanupBatchSize)
	if err != nil {
		return 0, fmt.Errorf("clean admin authentication throttle state: %w", err)
	}
	return result.RowsAffected()
}

func unixTime(value sql.NullInt64) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return time.Unix(value.Int64, 0).UTC()
}

func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.Unix()
}
