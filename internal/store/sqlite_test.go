package store

import (
	"context"
	"database/sql"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"supergrok-api/migrations"
)

func TestOpenMigratesAndConfiguresSQLite(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	store, err := Open(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var journal string
	if err := store.DB.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
		t.Fatal(err)
	}
	if journal != "wal" {
		t.Fatalf("journal_mode = %q", journal)
	}
	var foreignKeys, busyTimeout int
	if err := store.DB.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		t.Fatal(err)
	}
	if err := store.DB.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		t.Fatal(err)
	}
	if foreignKeys != 1 || busyTimeout != 5000 {
		t.Fatalf("pragmas = foreign_keys:%d busy_timeout:%d", foreignKeys, busyTimeout)
	}
	for _, table := range []string{"schema_migrations", "accounts", "account_model_capabilities", "account_model_states", "oauth_sessions", "usage_snapshots", "api_keys", "response_sessions", "admin_sessions", "admin_auth_sources", "admin_auth_global"} {
		var count int
		if err := store.DB.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("table %s missing", table)
		}
	}
	info, err := os.Stat(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("database mode = %o", info.Mode().Perm())
	}
}

func TestMigrationsAreIdempotent(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	first, err := Open(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	var count int
	if err := second.DB.QueryRow("SELECT count(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Fatalf("migration count = %d", count)
	}
}

func TestMigrationFailureRollsBackFreshSchema(t *testing.T) {
	ctx := context.Background()
	db, err := openUnmigratedTestDB(t)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	broken := fstest.MapFS{"001_broken.sql": &fstest.MapFile{Data: []byte("CREATE TABLE partial(id INTEGER); INVALID SQL;")}}
	if err := Migrate(ctx, db, broken); err == nil {
		t.Fatal("broken migration succeeded")
	}
	for _, table := range []string{"partial", "schema_migrations"} {
		var count int
		if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("partial table %s remained", table)
		}
	}
}

func TestResponseChainMigrationPreservesPopulatedRows(t *testing.T) {
	ctx := context.Background()
	db, err := openUnmigratedTestDB(t)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	initial, err := fs.ReadFile(migrations.FS, "001_initial.sql")
	if err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, db, fstest.MapFS{"001_initial.sql": &fstest.MapFile{Data: initial}}); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ id, previous string }{{id: "parent"}, {id: "child", previous: "parent"}} {
		var previous any
		if row.previous != "" {
			previous = row.previous
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO response_sessions(response_id,previous_response_id,model,input_encrypted,output_encrypted,store,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)`, row.id, previous, "grok-4.5", "encrypted-input", "encrypted-output", 1, 1, 2); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(ctx, db, migrations.FS); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM response_sessions`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("migrated row count = %d, %v", count, err)
	}
	var previous string
	if err := db.QueryRowContext(ctx, `SELECT previous_response_id FROM response_sessions WHERE response_id='child'`).Scan(&previous); err != nil || previous != "parent" {
		t.Fatalf("child previous ID = %q, %v", previous, err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM response_sessions WHERE response_id='parent'`); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT previous_response_id FROM response_sessions WHERE response_id='child'`).Scan(&previous); err != nil || previous != "parent" {
		t.Fatalf("child linkage after parent delete = %q, %v", previous, err)
	}
}

func openUnmigratedTestDB(t *testing.T) (*sql.DB, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	return sql.Open("sqlite", path)
}
