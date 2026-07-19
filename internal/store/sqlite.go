package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	appcrypto "byos/internal/crypto"
	"byos/internal/provider"
	"byos/migrations"
)

const (
	cleanupBatchSize           = 500
	databaseFilename           = "byos.db"
	defaultCompensationTimeout = 2 * time.Second
)

type SQLite struct {
	DB   *sql.DB
	path string
}

// DevinOAuthTransaction atomically publishes an encrypted Devin account and
// completes the already-consumed callback session that produced it.
type transactionExec func(context.Context, string, ...any) (sql.Result, error)
type transactionExecHook func(transactionExec) transactionExec

type DevinOAuthTransaction struct {
	db       *sql.DB
	accounts *AccountRepository
	oauth    *OAuthSessionRepository

	accountExecHook     transactionExecHook
	sessionExecHook     transactionExecHook
	commitTx            func(*sql.Tx) error
	beforeCommit        func() error
	beforeFinalize      func() error
	compensationTimeout time.Duration
}

func NewDevinOAuthTransaction(db *sql.DB, keys appcrypto.Keys) *DevinOAuthTransaction {
	return &DevinOAuthTransaction{
		db:       db,
		accounts: NewAccountRepository(db, keys),
		oauth:    NewOAuthSessionRepository(db, keys),
	}
}

// Complete commits account upsert/dedup and consumed-session completion as one
// unit. On failure it compensates only by changing consumed to failed; it never
// restores pending or makes the callback retryable.
func (r *DevinOAuthTransaction) Complete(ctx context.Context, state string, account Account, now time.Time) (Account, error) {
	created, err := r.complete(ctx, state, account, now.UTC())
	if err == nil {
		return created, nil
	}
	if r.beforeFinalize != nil {
		if finalizeErr := r.beforeFinalize(); finalizeErr != nil {
			return Account{}, errors.Join(err, finalizeErr)
		}
	}
	timeout := r.compensationTimeout
	if timeout <= 0 {
		timeout = defaultCompensationTimeout
	}
	compensationCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if finalizeErr := r.oauth.Fail(compensationCtx, provider.Devin, OAuthFlowCallbackPKCE, state, "oauth completion failed", now.UTC()); finalizeErr != nil {
		return Account{}, errors.Join(err, finalizeErr)
	}
	return Account{}, err
}

func (r *DevinOAuthTransaction) complete(ctx context.Context, state string, account Account, now time.Time) (Account, error) {
	if account.Provider != provider.Devin {
		return Account{}, errors.New("devin oauth transaction requires devin account")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Account{}, err
	}
	defer tx.Rollback()
	accountDB := accountDBTX(tx)
	if r.accountExecHook != nil {
		accountDB = transactionDBTX{tx: tx, exec: r.accountExecHook(tx.ExecContext)}
	}
	created, err := r.accounts.upsertLogin(ctx, accountDB, account, now)
	if err != nil {
		return Account{}, err
	}
	sessionDB := oauthTransactionDBTX(tx)
	if r.sessionExecHook != nil {
		sessionDB = transactionDBTX{tx: tx, exec: r.sessionExecHook(tx.ExecContext)}
	}
	if err := r.oauth.completeConsumedDevin(ctx, sessionDB, state, created.ID, now); err != nil {
		return Account{}, err
	}
	if r.beforeCommit != nil {
		if err := r.beforeCommit(); err != nil {
			return Account{}, err
		}
	}
	if r.commitTx != nil {
		if err := r.commitTx(tx); err != nil {
			return Account{}, err
		}
	} else if err := tx.Commit(); err != nil {
		return Account{}, err
	}
	return created, nil
}

type transactionDBTX struct {
	tx   *sql.Tx
	exec func(context.Context, string, ...any) (sql.Result, error)
}

func (db transactionDBTX) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return db.exec(ctx, query, args...)
}

func (db transactionDBTX) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return db.tx.QueryRowContext(ctx, query, args...)
}

func Open(ctx context.Context, dataDir string) (*SQLite, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	if err := os.Chmod(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("secure data directory: %w", err)
	}
	path := filepath.Join(dataDir, databaseFilename)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	closeOnError := func(err error) (*SQLite, error) { _ = db.Close(); return nil, err }
	for _, statement := range []string{"PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000"} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return closeOnError(fmt.Errorf("configure sqlite: %w", err))
		}
	}
	if err := Migrate(ctx, db, migrations.FS); err != nil {
		return closeOnError(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return closeOnError(fmt.Errorf("secure database file: %w", err))
	}
	return &SQLite{DB: db, path: path}, nil
}

func (s *SQLite) Path() string { return s.path }
func (s *SQLite) Checkpoint(ctx context.Context) error {
	_, err := s.DB.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	return err
}
func (s *SQLite) Close() error { return s.DB.Close() }
