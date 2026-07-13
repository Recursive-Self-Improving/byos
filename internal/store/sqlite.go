package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"supergrok-api/migrations"
)

type SQLite struct {
	DB   *sql.DB
	path string
}

func Open(ctx context.Context, dataDir string) (*SQLite, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	if err := os.Chmod(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("secure data directory: %w", err)
	}
	path := filepath.Join(dataDir, "supergrok.db")
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
