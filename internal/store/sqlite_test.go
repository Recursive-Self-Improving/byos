package store

import (
	"context"
	"database/sql"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"testing/fstest"

	"byos/migrations"
)

func TestOpenMigratesAndConfiguresSQLite(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	store, err := Open(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if store.Path() != filepath.Join(dataDir, "byos.db") {
		t.Fatalf("database path = %q", store.Path())
	}
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
	if count != 5 {
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

func TestProviderIdentityMigrationFreshSchema(t *testing.T) {
	ctx := context.Background()
	db, err := openUnmigratedTestDB(t)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, db, migrations.FS); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 5 {
		t.Fatalf("migration count = %d", count)
	}
	for _, column := range []struct {
		table, name, defaultValue string
		notNull                   int
	}{
		{table: "accounts", name: "provider", defaultValue: "'xai'", notNull: 1},
		{table: "oauth_sessions", name: "provider", defaultValue: "'xai'", notNull: 1},
		{table: "oauth_sessions", name: "flow_type", defaultValue: "'device'", notNull: 1},
	} {
		var gotDefault sql.NullString
		var gotNotNull int
		if err := db.QueryRowContext(ctx, `SELECT "notnull", dflt_value FROM pragma_table_info(?) WHERE name = ?`, column.table, column.name).Scan(&gotNotNull, &gotDefault); err != nil {
			t.Fatalf("column %s.%s: %v", column.table, column.name, err)
		}
		if gotNotNull != column.notNull || !gotDefault.Valid || gotDefault.String != column.defaultValue {
			t.Fatalf("column %s.%s = notnull:%d default:%q", column.table, column.name, gotNotNull, gotDefault.String)
		}
	}
	for _, index := range []string{"accounts_provider_status_idx", "oauth_sessions_provider_flow_status_expiry_idx", "oauth_sessions_expiry_idx"} {
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = ?`, index).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("index %s missing", index)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO accounts(id, identity_fingerprint, status, credentials_encrypted, created_at, updated_at, provider) VALUES('bad', X'01', 'active', 'cipher', 1, 1, 'other')`); err == nil {
		t.Fatal("invalid account provider accepted")
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO oauth_sessions(state_hash, payload_encrypted, status, poll_interval_seconds, expires_at, created_at, updated_at, provider, flow_type) VALUES(X'03', 'cipher', 'pending', 5, 10, 1, 1, 'other', 'device')`); err == nil {
		t.Fatal("invalid OAuth provider accepted")
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO oauth_sessions(state_hash, payload_encrypted, status, poll_interval_seconds, expires_at, created_at, updated_at, provider, flow_type) VALUES(X'02', 'cipher', 'pending', 5, 10, 1, 1, 'xai', 'redirect')`); err == nil {
		t.Fatal("invalid OAuth flow accepted")
	}
}

func TestProviderIdentityMigrationPreservesPopulatedV4(t *testing.T) {
	ctx := context.Background()
	db, err := openUnmigratedTestDB(t)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, db, migrationFS(t, 4)); err != nil {
		t.Fatal(err)
	}
	populateV4ProviderFixture(t, ctx, db)
	before := snapshotV4ProviderFixture(t, ctx, db)

	if err := Migrate(ctx, db, migrations.FS); err != nil {
		t.Fatal(err)
	}
	after := snapshotV4ProviderFixture(t, ctx, db)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("v4 row bytes changed during migration\nbefore: %#v\nafter:  %#v", before, after)
	}
	var accountProvider, oauthProvider, flowType string
	if err := db.QueryRowContext(ctx, `SELECT provider FROM accounts WHERE id = 'acct-v4'`).Scan(&accountProvider); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT provider, flow_type FROM oauth_sessions WHERE state_hash = X'00112233'`).Scan(&oauthProvider, &flowType); err != nil {
		t.Fatal(err)
	}
	if accountProvider != "xai" || oauthProvider != "xai" || flowType != "device" {
		t.Fatalf("legacy identity = account:%q oauth:%q flow:%q", accountProvider, oauthProvider, flowType)
	}
	rows, err := db.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Fatal("foreign_key_check reported a violation")
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil || count != 5 {
		t.Fatalf("migration count = %d, %v", count, err)
	}
}

func TestProviderIdentityMigrationFailureRollsBackToV4(t *testing.T) {
	ctx := context.Background()
	db, err := openUnmigratedTestDB(t)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, db, migrationFS(t, 4)); err != nil {
		t.Fatal(err)
	}
	populateV4ProviderFixture(t, ctx, db)
	before := snapshotV4ProviderFixture(t, ctx, db)
	broken := fstest.MapFS{
		"005_provider_identity.sql": &fstest.MapFile{Data: []byte(`
ALTER TABLE accounts ADD COLUMN provider TEXT NOT NULL DEFAULT 'xai';
CREATE INDEX accounts_provider_status_idx ON accounts(provider, status);
ALTER TABLE oauth_sessions ADD COLUMN provider TEXT NOT NULL DEFAULT 'xai';
ALTER TABLE oauth_sessions ADD COLUMN flow_type TEXT NOT NULL DEFAULT 'device';
CREATE INDEX oauth_sessions_provider_flow_status_expiry_idx ON oauth_sessions(provider, flow_type, status, expires_at);
INSERT INTO table_that_does_not_exist VALUES (1);`)},
	}
	if err := Migrate(ctx, db, broken); err == nil {
		t.Fatal("failing 005 succeeded")
	}
	if after := snapshotV4ProviderFixture(t, ctx, db); !reflect.DeepEqual(after, before) {
		t.Fatalf("v4 rows changed after failed migration\nbefore: %#v\nafter:  %#v", before, after)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil || count != 4 {
		t.Fatalf("migration count = %d, %v", count, err)
	}
	for _, column := range []struct{ table, name string }{{"accounts", "provider"}, {"oauth_sessions", "provider"}, {"oauth_sessions", "flow_type"}} {
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info(?) WHERE name = ?`, column.table, column.name).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("partial column %s.%s remained", column.table, column.name)
		}
	}
	for _, index := range []string{"accounts_provider_status_idx", "oauth_sessions_provider_flow_status_expiry_idx"} {
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = ?`, index).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("partial index %s remained", index)
		}
	}
}

type providerMigrationSnapshot struct {
	account, capability, modelState, usage, localUsage, response, oauth []any
}

func migrationFS(t *testing.T, through int) fstest.MapFS {
	t.Helper()
	result := fstest.MapFS{}
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if len(entry.Name()) < 3 {
			continue
		}
		version, err := strconv.Atoi(entry.Name()[:3])
		if err != nil || version > through {
			continue
		}
		body, err := fs.ReadFile(migrations.FS, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = &fstest.MapFile{Data: body}
	}
	return result
}

func populateV4ProviderFixture(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	statements := []string{
		`INSERT INTO accounts(id, identity_fingerprint, label, enabled, status, credentials_encrypted, expires_at, last_refresh_at, last_error, created_at, updated_at) VALUES('acct-v4', X'00FF1080', 'legacy label', 0, 'relogin_required', 'enc-account-\x00-\xff', 1700000001, 1700000002, 'sanitized account error', 1700000003, 1700000004)`,
		`INSERT INTO account_model_capabilities(account_id, model, supported, supports_backend_search, display_name, context_window, max_output_tokens, reasoning_efforts, discovered_at, stale) VALUES('acct-v4', 'legacy/model', 1, 0, 'Legacy Model', 131072, 8192, '["low","high"]', 1700000010, 1)`,
		`INSERT INTO account_model_states(account_id, model, cooldown_until, backoff_level, last_error_class, last_error_at) VALUES('acct-v4', 'legacy/model', 1700000020, 3, 'rate_limit', 1700000021)`,
		`INSERT INTO usage_snapshots(id, account_id, normalized_json, raw_encrypted, fetched_at, stale, error) VALUES(41, 'acct-v4', '{"remaining":7}', 'enc-usage-\x00', 1700000030, 1, 'sanitized usage error')`,
		`INSERT INTO local_usage_counters(account_id, requests, failures, input_tokens, output_tokens, updated_at) VALUES('acct-v4', 11, 2, 333, 444, 1700000040)`,
		`INSERT INTO response_sessions(response_id, upstream_response_id, previous_response_id, model, preferred_account_id, input_encrypted, output_encrypted, store, created_at, expires_at) VALUES('resp-v4', 'upstream-v4', 'previous-v4', 'legacy/model', 'acct-v4', 'enc-input-\x00', 'enc-output-\xff', 1, 1700000050, 1700000060)`,
		`INSERT INTO oauth_sessions(state_hash, payload_encrypted, status, poll_interval_seconds, expires_at, created_at, updated_at, sanitized_error) VALUES(X'00112233', 'enc-oauth-\x00-\xff', 'authorized', 17, 1700000070, 1700000080, 1700000090, 'sanitized oauth error')`,
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
}

func snapshotV4ProviderFixture(t *testing.T, ctx context.Context, db *sql.DB) providerMigrationSnapshot {
	t.Helper()
	return providerMigrationSnapshot{
		account:    queryRowValues(t, ctx, db, `SELECT id, identity_fingerprint, label, enabled, status, credentials_encrypted, expires_at, last_refresh_at, last_error, created_at, updated_at FROM accounts WHERE id='acct-v4'`, 11),
		capability: queryRowValues(t, ctx, db, `SELECT account_id, model, supported, supports_backend_search, display_name, context_window, max_output_tokens, reasoning_efforts, discovered_at, stale FROM account_model_capabilities WHERE account_id='acct-v4'`, 10),
		modelState: queryRowValues(t, ctx, db, `SELECT account_id, model, cooldown_until, backoff_level, last_error_class, last_error_at FROM account_model_states WHERE account_id='acct-v4'`, 6),
		usage:      queryRowValues(t, ctx, db, `SELECT id, account_id, normalized_json, raw_encrypted, fetched_at, stale, error FROM usage_snapshots WHERE id=41`, 7),
		localUsage: queryRowValues(t, ctx, db, `SELECT account_id, requests, failures, input_tokens, output_tokens, updated_at FROM local_usage_counters WHERE account_id='acct-v4'`, 6),
		response:   queryRowValues(t, ctx, db, `SELECT response_id, upstream_response_id, previous_response_id, model, preferred_account_id, input_encrypted, output_encrypted, store, created_at, expires_at FROM response_sessions WHERE response_id='resp-v4'`, 10),
		oauth:      queryRowValues(t, ctx, db, `SELECT state_hash, payload_encrypted, status, poll_interval_seconds, expires_at, created_at, updated_at, sanitized_error FROM oauth_sessions WHERE state_hash=X'00112233'`, 8),
	}
}

func queryRowValues(t *testing.T, ctx context.Context, db *sql.DB, query string, count int) []any {
	t.Helper()
	values := make([]any, count)
	destinations := make([]any, count)
	for i := range values {
		destinations[i] = &values[i]
	}
	if err := db.QueryRowContext(ctx, query).Scan(destinations...); err != nil {
		t.Fatal(err)
	}
	return values
}

func openUnmigratedTestDB(t *testing.T) (*sql.DB, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	return sql.Open("sqlite", path)
}
