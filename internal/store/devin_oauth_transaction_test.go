package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	appcrypto "byos/internal/crypto"
	"byos/internal/provider"
)

func createConsumedDevinSession(t *testing.T, db *sql.DB, keys appcrypto.Keys, state, verifier, redirectURI string, now time.Time) {
	t.Helper()
	repo := NewOAuthSessionRepository(db, keys)
	err := repo.Create(context.Background(), OAuthSession{
		Provider:  provider.Devin,
		FlowType:  OAuthFlowCallbackPKCE,
		State:     state,
		Pending:   &OAuthPendingPayload{Verifier: verifier, RedirectURI: redirectURI, ExpiresAt: now.Add(time.Hour)},
		ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Consume(context.Background(), provider.Devin, OAuthFlowCallbackPKCE, state, now); err != nil {
		t.Fatal(err)
	}
}

func devinAccount(token string, expires time.Time) Account {
	return Account{
		Provider:    provider.Devin,
		Label:       "Devin",
		Credentials: AccountCredentials{OpaqueToken: token, OpaqueTokenExpiresAt: &expires},
		ExpiresAt:   &expires,
	}
}

func assertNoStorePlaintext(t *testing.T, path string, secrets ...string) {
	t.Helper()
	for _, artifact := range []string{path, path + "-wal", path + "-shm"} {
		data, err := os.ReadFile(artifact)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		for _, secret := range secrets {
			if bytes.Contains(data, []byte(secret)) {
				t.Fatalf("plaintext %q found in %s", secret, artifact)
			}
		}
	}
}

func assertNoStorePlaintextAcrossLifecycle(t *testing.T, database *SQLite, secrets ...string) *SQLite {
	t.Helper()
	ctx := context.Background()
	path := database.Path()
	assertNoStorePlaintext(t, path, secrets...)
	if err := database.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	assertNoStorePlaintext(t, path, secrets...)
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	assertNoStorePlaintext(t, path, secrets...)
	reopened, err := Open(ctx, filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	assertNoStorePlaintext(t, path, secrets...)
	return reopened
}

func TestDevinOAuthTransactionAtomicSuccessDedupAndPlaintextAbsence(t *testing.T) {
	ctx := context.Background()
	database, keys := openRepositories(t)
	now := time.Now().UTC().Truncate(time.Second)
	state := "unique-raw-state-atomic-success"
	verifier := "unique-pkce-verifier-atomic-success"
	redirectURI := "https://atomic-success.example.test/oauth/callback"
	token := "unique-opaque-token-atomic-success"
	code := "unique-callback-code-atomic-success-never-input"
	userJWT := "eyJhbGciOiJub25lIn0.atomic-success-user-jwt.never-input"
	createConsumedDevinSession(t, database.DB, keys, state, verifier, redirectURI, now)

	tx := NewDevinOAuthTransaction(database.DB, keys)
	created, err := tx.Complete(ctx, state, devinAccount(token, now.Add(time.Hour)), now)
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.Provider != provider.Devin || created.Credentials.OpaqueToken != token {
		t.Fatalf("created account = %+v", created)
	}
	session, err := NewOAuthSessionRepository(database.DB, keys).Get(ctx, provider.Devin, OAuthFlowCallbackPKCE, state)
	if err != nil || session.Status != "completed" || session.AccountID != created.ID || session.Pending != nil {
		t.Fatalf("completed session = %+v, %v", session, err)
	}

	state2 := "unique-raw-state-atomic-dedup"
	verifier2 := "unique-pkce-verifier-atomic-dedup"
	redirectURI2 := "https://atomic-dedup.example.test/oauth/callback"
	createConsumedDevinSession(t, database.DB, keys, state2, verifier2, redirectURI2, now)
	dedup, err := tx.Complete(ctx, state2, devinAccount(token, now.Add(2*time.Hour)), now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if dedup.ID != created.ID {
		t.Fatalf("dedup ID = %q, want %q", dedup.ID, created.ID)
	}
	var count int
	if err := database.DB.QueryRowContext(ctx, `SELECT count(*) FROM accounts WHERE provider=?`, provider.Devin).Scan(&count); err != nil || count != 1 {
		t.Fatalf("account count = %d, %v", count, err)
	}

	database = assertNoStorePlaintextAcrossLifecycle(t, database, state, verifier, redirectURI, state2, verifier2, redirectURI2, token, code, userJWT)
	defer database.Close()
}

func TestDevinOAuthTransactionFailuresRollbackAndFailConsumed(t *testing.T) {
	injected := errors.New("injected transaction failure")
	failAfterExec := func(next transactionExec) transactionExec {
		return func(ctx context.Context, query string, args ...any) (sql.Result, error) {
			if _, err := next(ctx, query, args...); err != nil {
				return nil, err
			}
			return nil, injected
		}
	}
	cases := []struct {
		name   string
		inject func(*DevinOAuthTransaction)
	}{
		{name: "account-exec", inject: func(tx *DevinOAuthTransaction) { tx.accountExecHook = failAfterExec }},
		{name: "session-exec", inject: func(tx *DevinOAuthTransaction) { tx.sessionExecHook = failAfterExec }},
		{name: "commit", inject: func(tx *DevinOAuthTransaction) {
			tx.commitTx = func(sqlTx *sql.Tx) error {
				if err := sqlTx.Rollback(); err != nil {
					return err
				}
				return injected
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database, keys := openRepositories(t)
			now := time.Now().UTC().Truncate(time.Second)
			state := "unique-raw-state-failure-" + tc.name
			verifier := "unique-pkce-verifier-failure-" + tc.name
			redirectURI := "https://failure-" + tc.name + ".example.test/oauth/callback"
			token := "unique-opaque-token-failure-" + tc.name
			code := "unique-callback-code-failure-" + tc.name + "-never-input"
			userJWT := "eyJhbGciOiJub25lIn0.failure-" + tc.name + "-user-jwt.never-input"
			createConsumedDevinSession(t, database.DB, keys, state, verifier, redirectURI, now)
			tx := NewDevinOAuthTransaction(database.DB, keys)
			tc.inject(tx)
			if _, err := tx.Complete(ctx, state, devinAccount(token, now.Add(time.Hour)), now); !errors.Is(err, injected) {
				t.Fatalf("complete error = %v", err)
			}
			var count int
			if err := database.DB.QueryRowContext(ctx, `SELECT count(*) FROM accounts WHERE provider=?`, provider.Devin).Scan(&count); err != nil || count != 0 {
				t.Fatalf("account count = %d, %v", count, err)
			}
			session, err := NewOAuthSessionRepository(database.DB, keys).Get(ctx, provider.Devin, OAuthFlowCallbackPKCE, state)
			if err != nil || session.Status != "failed" || session.AccountID != "" || session.Pending != nil {
				t.Fatalf("failed session = %+v, %v", session, err)
			}
			database = assertNoStorePlaintextAcrossLifecycle(t, database, state, verifier, redirectURI, token, code, userJWT)
			defer database.Close()
			if err := database.DB.QueryRowContext(ctx, `SELECT count(*) FROM accounts WHERE provider=?`, provider.Devin).Scan(&count); err != nil || count != 0 {
				t.Fatalf("reopened account count = %d, %v", count, err)
			}
		})
	}
}

func TestDevinOAuthTransactionRollbackPreservesPreexistingDedupAccount(t *testing.T) {
	ctx := context.Background()
	database, keys := openRepositories(t)
	defer database.Close()
	now := time.Now().UTC().Truncate(time.Second)
	token := "unique-opaque-token-preexisting-dedup-failure"
	accounts := NewAccountRepository(database.DB, keys)
	original, err := accounts.UpsertLogin(ctx, devinAccount(token, now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	var beforeCipher string
	var beforeUpdated int64
	if err := database.DB.QueryRowContext(ctx, `SELECT credentials_encrypted,updated_at FROM accounts WHERE id=?`, original.ID).Scan(&beforeCipher, &beforeUpdated); err != nil {
		t.Fatal(err)
	}
	state := "unique-raw-state-preexisting-dedup-failure"
	verifier := "unique-pkce-verifier-preexisting-dedup-failure"
	redirectURI := "https://preexisting-dedup-failure.example.test/oauth/callback"
	code := "unique-callback-code-preexisting-dedup-failure-never-input"
	userJWT := "eyJhbGciOiJub25lIn0.preexisting-dedup-failure-user-jwt.never-input"
	createConsumedDevinSession(t, database.DB, keys, state, verifier, redirectURI, now)
	tx := NewDevinOAuthTransaction(database.DB, keys)
	tx.sessionExecHook = func(next transactionExec) transactionExec {
		return func(ctx context.Context, query string, args ...any) (sql.Result, error) {
			if _, err := next(ctx, query, args...); err != nil {
				return nil, err
			}
			return nil, errors.New("session write failure")
		}
	}
	if _, err := tx.Complete(ctx, state, devinAccount(token, now.Add(24*time.Hour)), now.Add(time.Minute)); err == nil {
		t.Fatal("transaction unexpectedly succeeded")
	}
	var afterCipher string
	var afterUpdated int64
	if err := database.DB.QueryRowContext(ctx, `SELECT credentials_encrypted,updated_at FROM accounts WHERE id=?`, original.ID).Scan(&afterCipher, &afterUpdated); err != nil {
		t.Fatal(err)
	}
	if afterCipher != beforeCipher || afterUpdated != beforeUpdated {
		t.Fatal("preexisting deduplicated account changed despite rollback")
	}
	got, err := accounts.Get(ctx, original.ID)
	if err != nil || got.Credentials.OpaqueToken != token || !got.ExpiresAt.Equal(*original.ExpiresAt) {
		t.Fatalf("preserved account = %+v, %v", got, err)
	}
	database = assertNoStorePlaintextAcrossLifecycle(t, database, state, verifier, redirectURI, token, code, userJWT)
	defer database.Close()
}

func TestDevinOAuthTransactionInterruptedFinalizationRecoversAfterRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	database, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	state := "unique-raw-state-interrupted-restart"
	verifier := "unique-pkce-verifier-interrupted-restart"
	redirectURI := "https://interrupted-restart.example.test/oauth/callback"
	token := "unique-opaque-token-interrupted-restart"
	code := "unique-callback-code-interrupted-restart-never-input"
	userJWT := "eyJhbGciOiJub25lIn0.interrupted-restart-user-jwt.never-input"
	createConsumedDevinSession(t, database.DB, keys, state, verifier, redirectURI, now)
	tx := NewDevinOAuthTransaction(database.DB, keys)
	tx.commitTx = func(sqlTx *sql.Tx) error {
		if err := sqlTx.Rollback(); err != nil {
			return err
		}
		return errors.New("commit interrupted")
	}
	tx.beforeFinalize = func() error { return errors.New("finalization interrupted") }
	if _, err := tx.Complete(ctx, state, devinAccount(token, now.Add(time.Hour)), now); err == nil {
		t.Fatal("transaction unexpectedly succeeded")
	}
	reopened := assertNoStorePlaintextAcrossLifecycle(t, database, state, verifier, redirectURI, token, code, userJWT)
	defer reopened.Close()
	oauth := NewOAuthSessionRepository(reopened.DB, keys)
	session, err := oauth.Get(ctx, provider.Devin, OAuthFlowCallbackPKCE, state)
	if err != nil || session.Status != "consumed" {
		t.Fatalf("restart session = %+v, %v", session, err)
	}
	if err := oauth.FailConsumedByHash(ctx, provider.Devin, OAuthFlowCallbackPKCE, session.StateHash, "oauth completion interrupted", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	session, err = oauth.Get(ctx, provider.Devin, OAuthFlowCallbackPKCE, state)
	if err != nil || session.Status != "failed" || session.Pending != nil || session.AccountID != "" {
		t.Fatalf("recovered session = %+v, %v", session, err)
	}
	var count int
	if err := reopened.DB.QueryRowContext(ctx, `SELECT count(*) FROM accounts WHERE provider=?`, provider.Devin).Scan(&count); err != nil || count != 0 {
		t.Fatalf("restarted account count = %d, %v", count, err)
	}
	reopened = assertNoStorePlaintextAcrossLifecycle(t, reopened, state, verifier, redirectURI, token, code, userJWT)
	defer reopened.Close()
}

func TestDevinOAuthTransactionPrecommitInvisibleToSecondConnection(t *testing.T) {
	ctx := context.Background()
	database, keys := openRepositories(t)
	defer database.Close()
	now := time.Now().UTC().Truncate(time.Second)
	state := "unique-raw-state-precommit-invisibility"
	verifier := "unique-pkce-verifier-precommit-invisibility"
	redirectURI := "https://precommit-invisibility.example.test/oauth/callback"
	token := "unique-opaque-token-precommit-invisibility"
	code := "unique-callback-code-precommit-invisibility-never-input"
	userJWT := "eyJhbGciOiJub25lIn0.precommit-invisibility-user-jwt.never-input"
	createConsumedDevinSession(t, database.DB, keys, state, verifier, redirectURI, now)
	second, err := sql.Open("sqlite", database.Path())
	if err != nil {
		t.Fatal(err)
	}
	paused := make(chan struct{})
	release := make(chan struct{})
	tx := NewDevinOAuthTransaction(database.DB, keys)
	tx.beforeCommit = func() error {
		close(paused)
		<-release
		return nil
	}
	done := make(chan error, 1)
	go func() {
		_, err := tx.Complete(ctx, state, devinAccount(token, now.Add(time.Hour)), now)
		done <- err
	}()
	<-paused
	var accounts int
	if err := second.QueryRowContext(ctx, `SELECT count(*) FROM accounts WHERE provider=?`, provider.Devin).Scan(&accounts); err != nil || accounts != 0 {
		t.Fatalf("precommit account count = %d, %v", accounts, err)
	}
	hash := stateHash(state)
	var status string
	if err := second.QueryRowContext(ctx, `SELECT status FROM oauth_sessions WHERE state_hash=?`, hash[:]).Scan(&status); err != nil || status != "consumed" {
		t.Fatalf("precommit session status = %q, %v", status, err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := second.QueryRowContext(ctx, `SELECT count(*) FROM accounts WHERE provider=?`, provider.Devin).Scan(&accounts); err != nil || accounts != 1 {
		t.Fatalf("postcommit account count = %d, %v", accounts, err)
	}
	if err := second.QueryRowContext(ctx, `SELECT status FROM oauth_sessions WHERE state_hash=?`, hash[:]).Scan(&status); err != nil || status != "completed" {
		t.Fatalf("postcommit session status = %q, %v", status, err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	database = assertNoStorePlaintextAcrossLifecycle(t, database, state, verifier, redirectURI, token, code, userJWT)
	defer database.Close()
}

func TestDevinOAuthTransactionCompensationDetachedFromCallerCancellation(t *testing.T) {
	database, keys := openRepositories(t)
	defer database.Close()
	now := time.Now().UTC().Truncate(time.Second)
	state := "unique-raw-state-detached-compensation"
	verifier := "unique-pkce-verifier-detached-compensation"
	redirectURI := "https://detached-compensation.example.test/oauth/callback"
	token := "unique-opaque-token-detached-compensation"
	code := "unique-callback-code-detached-compensation-never-input"
	userJWT := "eyJhbGciOiJub25lIn0.detached-compensation-user-jwt.never-input"
	createConsumedDevinSession(t, database.DB, keys, state, verifier, redirectURI, now)
	ctx, cancel := context.WithCancel(context.Background())
	injected := errors.New("commit preparation failed")
	tx := NewDevinOAuthTransaction(database.DB, keys)
	tx.beforeCommit = func() error {
		cancel()
		return injected
	}
	tx.compensationTimeout = time.Second
	if _, err := tx.Complete(ctx, state, devinAccount(token, now.Add(time.Hour)), now); !errors.Is(err, injected) {
		t.Fatalf("complete error = %v", err)
	}
	session, err := NewOAuthSessionRepository(database.DB, keys).Get(context.Background(), provider.Devin, OAuthFlowCallbackPKCE, state)
	if err != nil || session.Status != "failed" || session.AccountID != "" {
		t.Fatalf("compensated session = %+v, %v", session, err)
	}
	database = assertNoStorePlaintextAcrossLifecycle(t, database, state, verifier, redirectURI, token, code, userJWT)
	defer database.Close()
}
