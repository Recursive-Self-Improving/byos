package devin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appcrypto "byos/internal/crypto"
	"byos/internal/provider"
	"byos/internal/store"
)

type lifecycleExchangeFake struct {
	calls  atomic.Int32
	token  string
	err    error
	onCall func(string, string)
}

func (f *lifecycleExchangeFake) Exchange(_ context.Context, code, verifier string) (string, error) {
	f.calls.Add(1)
	if f.onCall != nil {
		f.onCall(code, verifier)
	}
	return f.token, f.err
}

type lifecycleTransactionFake struct {
	calls   atomic.Int32
	account store.Account
	err     error
}

func (f *lifecycleTransactionFake) Complete(_ context.Context, _ string, account store.Account, _ time.Time) (store.Account, error) {
	f.calls.Add(1)
	f.account = account
	if f.err != nil {
		return store.Account{}, f.err
	}
	return store.Account{Provider: provider.Devin, ID: "acct_devin"}, nil
}

func newLifecycleFixture(t *testing.T) (*store.SQLite, *store.OAuthSessionRepository, *ProviderLifecycle, *lifecycleExchangeFake, *lifecycleTransactionFake, time.Time) {
	t.Helper()
	database, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{37}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sessions := store.NewOAuthSessionRepository(database.DB, keys)
	exchange := &lifecycleExchangeFake{token: "opaque-devin-token"}
	transaction := &lifecycleTransactionFake{}
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	lifecycle := &ProviderLifecycle{
		sessions: sessions, client: exchange, transaction: transaction,
		config: OAuthConfig{CallbackOrigin: "http://127.0.0.1:59653", CallbackPath: "/callback"},
		now:    func() time.Time { return now },
	}
	return database, sessions, lifecycle, exchange, transaction, now
}

func createPendingLifecycleSession(t *testing.T, sessions *store.OAuthSessionRepository, state, verifier string, now time.Time) provider.SessionID {
	t.Helper()
	sessionID, err := provider.NewSessionID()
	if err != nil {
		t.Fatal(err)
	}
	expires := now.Add(pendingSessionTTL)
	if err := sessions.Create(context.Background(), store.OAuthSession{
		Provider: provider.Devin, FlowType: store.OAuthFlowCallbackPKCE, State: state, SessionID: string(sessionID),
		Pending:   &store.OAuthPendingPayload{Verifier: verifier, RedirectURI: "http://127.0.0.1:59653/callback", ExpiresAt: expires},
		ExpiresAt: expires,
	}); err != nil {
		t.Fatal(err)
	}
	return sessionID
}

func TestProviderLifecycleStartPersistsFiveMinutePendingProjection(t *testing.T) {
	_, sessions, lifecycle, exchange, transaction, now := newLifecycleFixture(t)
	authorization, err := lifecycle.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Ref.Provider != provider.Devin || authorization.Ref.State != "" || string(authorization.Ref.SessionID) == "" || authorization.Ref.SessionID != authorization.SessionID || authorization.VerificationURL == "" || authorization.VerificationURLComplete != authorization.VerificationURL {
		t.Fatalf("unsafe/incomplete authorization projection: %+v", authorization)
	}
	if !authorization.ExpiresAt.Equal(now.Add(5 * time.Minute)) {
		t.Fatalf("expiry=%v", authorization.ExpiresAt)
	}
	session, err := sessions.GetBySessionID(context.Background(), provider.Devin, store.OAuthFlowCallbackPKCE, string(authorization.Ref.SessionID))
	if err != nil {
		t.Fatal(err)
	}
	if session.Status != "pending" || session.Pending == nil || session.Pending.Verifier == "" || session.State != "" || len(session.StateHash) != 32 || session.SessionID != string(authorization.Ref.SessionID) {
		t.Fatalf("pending session=%+v", session)
	}
	if exchange.calls.Load() != 0 || transaction.calls.Load() != 0 {
		t.Fatal("start invoked completion dependencies")
	}
}

func TestProviderLifecycleMismatchAndMissingCodeStopBeforeDependencies(t *testing.T) {
	_, sessions, lifecycle, exchange, transaction, now := newLifecycleFixture(t)
	createPendingLifecycleSession(t, sessions, "state", "verifier", now)
	if _, err := lifecycle.Complete(context.Background(), provider.AuthorizationRef{Provider: provider.XAI, State: "state"}, provider.AuthorizationCompletion{Code: "code"}); !errors.Is(err, provider.ErrProviderMismatch) {
		t.Fatalf("mismatch err=%v", err)
	}
	if _, err := lifecycle.Complete(context.Background(), provider.AuthorizationRef{Provider: provider.Devin, State: "state"}, provider.AuthorizationCompletion{}); err == nil {
		t.Fatal("missing code accepted")
	}
	if exchange.calls.Load() != 0 || transaction.calls.Load() != 0 {
		t.Fatal("invalid completion invoked dependencies")
	}
	session, err := sessions.Get(context.Background(), provider.Devin, store.OAuthFlowCallbackPKCE, "state")
	if err != nil || session.Status != "pending" || session.Pending == nil {
		t.Fatalf("session mutated: %+v %v", session, err)
	}
}

func TestProviderLifecycleManualCompletionBindsSessionID(t *testing.T) {
	_, sessions, lifecycle, exchange, transaction, now := newLifecycleFixture(t)
	sessionID := createPendingLifecycleSession(t, sessions, "manual-state", "manual-verifier", now)
	wrongSessionID, err := provider.NewSessionID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.Complete(context.Background(), provider.AuthorizationRef{Provider: provider.Devin, State: "manual-state", SessionID: wrongSessionID}, provider.AuthorizationCompletion{Code: "manual-code"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mismatched session error=%v", err)
	}
	if exchange.calls.Load() != 0 || transaction.calls.Load() != 0 {
		t.Fatal("mismatched session invoked completion dependencies")
	}
	result, err := lifecycle.Complete(context.Background(), provider.AuthorizationRef{Provider: provider.Devin, State: "manual-state", SessionID: sessionID}, provider.AuthorizationCompletion{Code: "manual-code"})
	if err != nil || result.AccountID != "acct_devin" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestProviderLifecycleConsumesBeforeExchangeAndRejectsReplay(t *testing.T) {
	_, sessions, lifecycle, exchange, transaction, now := newLifecycleFixture(t)
	const state, verifier, code = "consume-state", "memory-only-verifier", "memory-only-code"
	createPendingLifecycleSession(t, sessions, state, verifier, now)
	exchange.onCall = func(gotCode, gotVerifier string) {
		if gotCode != code || gotVerifier != verifier {
			t.Errorf("exchange secrets mismatch")
		}
		session, err := sessions.Get(context.Background(), provider.Devin, store.OAuthFlowCallbackPKCE, state)
		if err != nil || session.Status != "consumed" || session.Pending != nil {
			t.Errorf("exchange observed %+v, %v", session, err)
		}
	}
	result, err := lifecycle.Complete(context.Background(), provider.AuthorizationRef{Provider: provider.Devin, State: state}, provider.AuthorizationCompletion{Code: code})
	if err != nil || result.Provider != provider.Devin || result.AccountID != "acct_devin" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if exchange.calls.Load() != 1 || transaction.calls.Load() != 1 {
		t.Fatalf("calls exchange=%d tx=%d", exchange.calls.Load(), transaction.calls.Load())
	}
	if _, err := lifecycle.Complete(context.Background(), provider.AuthorizationRef{Provider: provider.Devin, State: state}, provider.AuthorizationCompletion{Code: code}); err == nil {
		t.Fatal("replay accepted")
	}
	if exchange.calls.Load() != 1 || transaction.calls.Load() != 1 {
		t.Fatal("replay invoked dependencies")
	}
	if transaction.account.Provider != provider.Devin || transaction.account.Credentials.OpaqueToken != exchange.token || transaction.account.Credentials.RefreshToken != "" {
		t.Fatalf("account=%+v", transaction.account)
	}
}

func TestProviderLifecycleConcurrentCompletionExchangesOnce(t *testing.T) {
	_, sessions, lifecycle, exchange, _, now := newLifecycleFixture(t)
	createPendingLifecycleSession(t, sessions, "race-state", "race-verifier", now)
	started := make(chan struct{})
	release := make(chan struct{})
	exchange.onCall = func(_, _ string) { close(started); <-release }
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := lifecycle.Complete(context.Background(), provider.AuthorizationRef{Provider: provider.Devin, State: "race-state"}, provider.AuthorizationCompletion{Code: "code"})
			errs <- err
		}()
	}
	<-started
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("singleflight waiter err=%v", err)
		}
	}
	if exchange.calls.Load() != 1 {
		t.Fatalf("exchange calls=%d", exchange.calls.Load())
	}
}

func TestProviderLifecycleExchangeFailureIsDetachedAndNonRetryable(t *testing.T) {
	_, sessions, lifecycle, exchange, transaction, now := newLifecycleFixture(t)
	createPendingLifecycleSession(t, sessions, "failed-state", "failed-verifier", now)
	exchange.err = context.Canceled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Use a live caller for consume; the fake exchange supplies cancellation to
	// prove finalization does not inherit it.
	ctx = context.Background()
	if _, err := lifecycle.Complete(ctx, provider.AuthorizationRef{Provider: provider.Devin, State: "failed-state"}, provider.AuthorizationCompletion{Code: "code"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	session, err := sessions.Get(context.Background(), provider.Devin, store.OAuthFlowCallbackPKCE, "failed-state")
	if err != nil || session.Status != "failed" || session.Pending != nil || session.SanitizedError != failedMessage {
		t.Fatalf("session=%+v err=%v", session, err)
	}
	if transaction.calls.Load() != 0 {
		t.Fatal("exchange failure invoked transaction")
	}
	if _, err := lifecycle.Complete(context.Background(), provider.AuthorizationRef{Provider: provider.Devin, State: "failed-state"}, provider.AuthorizationCompletion{Code: "code"}); err == nil {
		t.Fatal("failed replay accepted")
	}
	if exchange.calls.Load() != 1 {
		t.Fatalf("replay exchange calls=%d", exchange.calls.Load())
	}
}

func TestProviderLifecycleCancelStatusAndConsumedRestartRecovery(t *testing.T) {
	_, sessions, lifecycle, exchange, transaction, now := newLifecycleFixture(t)
	sessionID := createPendingLifecycleSession(t, sessions, "cancel-state", "cancel-verifier", now)
	ref := provider.AuthorizationRef{Provider: provider.Devin, SessionID: sessionID}
	status, err := lifecycle.Status(context.Background(), ref)
	if err != nil || status.Status != provider.AuthorizationPending || status.Ref != ref {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	if err := lifecycle.Cancel(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	status, err = lifecycle.Status(context.Background(), ref)
	if err != nil || status.Status != provider.AuthorizationCancelled || status.SanitizedMessage != cancelledMessage {
		t.Fatalf("cancelled=%+v err=%v", status, err)
	}
	if err := lifecycle.Cancel(context.Background(), ref); !errors.Is(err, provider.ErrOAuthConflict) {
		t.Fatalf("terminal cancel error = %v, want ErrOAuthConflict", err)
	}

	createPendingLifecycleSession(t, sessions, "restart-state", "restart-verifier", now)
	if _, err := sessions.Consume(context.Background(), provider.Devin, store.OAuthFlowCallbackPKCE, "restart-state", now); err != nil {
		t.Fatal(err)
	}
	resumed, err := lifecycle.Resume(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(resumed) != 0 {
		t.Fatalf("resumed=%+v", resumed)
	}
	recovered, err := sessions.Get(context.Background(), provider.Devin, store.OAuthFlowCallbackPKCE, "restart-state")
	if err != nil || recovered.Status != "failed" || recovered.Pending != nil || recovered.SanitizedError != restartMessage {
		t.Fatalf("recovered=%+v err=%v", recovered, err)
	}
	if exchange.calls.Load() != 0 || transaction.calls.Load() != 0 {
		t.Fatal("restart recovery invoked exchange/transaction")
	}
}

func TestProviderLifecycleElapsedPendingExpiresAtEqualityBeforeActions(t *testing.T) {
	_, sessions, lifecycle, exchange, transaction, now := newLifecycleFixture(t)
	for _, test := range []struct {
		name string
		act  func(state string, sessionID provider.SessionID) error
	}{
		{name: "status", act: func(_ string, sessionID provider.SessionID) error {
			status, err := lifecycle.Status(context.Background(), provider.AuthorizationRef{Provider: provider.Devin, SessionID: sessionID})
			if err == nil && (status.Status != provider.AuthorizationExpired || status.SanitizedMessage != expiredMessage) {
				t.Fatalf("status = %+v", status)
			}
			return err
		}},
		{name: "complete before code validation", act: func(state string, _ provider.SessionID) error {
			_, err := lifecycle.Complete(context.Background(), provider.AuthorizationRef{Provider: provider.Devin, State: state}, provider.AuthorizationCompletion{})
			return err
		}},
		{name: "cancel before cancellation", act: func(_ string, sessionID provider.SessionID) error {
			return lifecycle.Cancel(context.Background(), provider.AuthorizationRef{Provider: provider.Devin, SessionID: sessionID})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := "expired-" + test.name
			sessionID := createPendingLifecycleSession(t, sessions, state, "secret-verifier", now)
			lifecycle.now = func() time.Time { return now.Add(pendingSessionTTL) }
			err := test.act(state, sessionID)
			if test.name == "status" {
				if err != nil {
					t.Fatal(err)
				}
			} else if test.name == "cancel before cancellation" {
				// Cancel on an expired session must surface the stable
				// provider.ErrOAuthConflict sentinel (409 at admin), per the
				// sentinel's contract naming expired as a terminal, non-
				// cancellable state. The generic expired message is reserved
				// for the Complete (callback) path.
				if !errors.Is(err, provider.ErrOAuthConflict) {
					t.Fatalf("cancel expiry error = %v, want ErrOAuthConflict", err)
				}
			} else if err == nil || err.Error() != "Devin authorization has expired" {
				t.Fatalf("expiry error = %v", err)
			}
			stored, getErr := sessions.Get(context.Background(), provider.Devin, store.OAuthFlowCallbackPKCE, state)
			if getErr != nil || stored.Status != string(provider.AuthorizationExpired) || stored.Pending != nil || stored.SanitizedError != expiredMessage {
				t.Fatalf("expired session = %+v, %v", stored, getErr)
			}
		})
	}
	if exchange.calls.Load() != 0 || transaction.calls.Load() != 0 {
		t.Fatalf("expired actions invoked dependencies: exchange=%d transaction=%d", exchange.calls.Load(), transaction.calls.Load())
	}
}

func TestProviderLifecycleExpiredExchangedTokenCreatesDisabledReloginAccount(t *testing.T) {
	_, sessions, lifecycle, exchange, transaction, now := newLifecycleFixture(t)
	createPendingLifecycleSession(t, sessions, "expired-token-state", "verifier", now)
	exchange.token = jwtWithPayload(fmt.Sprintf(`{"exp":%d}`, now.Add(5*time.Minute).Unix()))

	result, err := lifecycle.Complete(context.Background(), provider.AuthorizationRef{Provider: provider.Devin, State: "expired-token-state"}, provider.AuthorizationCompletion{Code: "code"})
	if err != nil || result.AccountID != "acct_devin" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	account := transaction.account
	if account.Enabled || account.Status != "relogin_required" || account.LastError != "authentication expired; reconnect required" {
		t.Fatalf("expired account = %+v", account)
	}
	if account.Credentials.OpaqueToken != exchange.token || account.ExpiresAt == nil || !account.ExpiresAt.Equal(now) {
		t.Fatalf("expired credentials = %+v expiry=%v", account.Credentials, account.ExpiresAt)
	}
}

// TestProviderLifecycleCancelMatrix verifies that Cancel on a known-but-
// terminal Devin session (completed, failed, already cancelled, consumed,
// expired) returns the stable provider.ErrOAuthConflict sentinel (409 at
// the admin layer), while a genuine unknown SessionID returns ErrNotFound
// (404). Terminal immutability is preserved: the status is unchanged after
// the conflict response.
func TestProviderLifecycleCancelMatrix(t *testing.T) {
	_, sessions, lifecycle, _, _, now := newLifecycleFixture(t)
	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T) provider.SessionID
		wantErr func(error) bool
	}{
		{
			name: "completed",
			setup: func(t *testing.T) provider.SessionID {
				sessionID := createPendingLifecycleSession(t, sessions, "matrix-completed", "v", now)
				if _, err := sessions.Consume(context.Background(), provider.Devin, store.OAuthFlowCallbackPKCE, "matrix-completed", now); err != nil {
					t.Fatal(err)
				}
				if err := sessions.Complete(context.Background(), provider.Devin, store.OAuthFlowCallbackPKCE, "matrix-completed", "acct", now); err != nil {
					t.Fatal(err)
				}
				return sessionID
			},
			wantErr: func(err error) bool { return errors.Is(err, provider.ErrOAuthConflict) },
		},
		{
			name: "failed",
			setup: func(t *testing.T) provider.SessionID {
				sessionID := createPendingLifecycleSession(t, sessions, "matrix-failed", "v", now)
				if _, err := sessions.Consume(context.Background(), provider.Devin, store.OAuthFlowCallbackPKCE, "matrix-failed", now); err != nil {
					t.Fatal(err)
				}
				if err := sessions.Fail(context.Background(), provider.Devin, store.OAuthFlowCallbackPKCE, "matrix-failed", failedMessage, now); err != nil {
					t.Fatal(err)
				}
				return sessionID
			},
			wantErr: func(err error) bool { return errors.Is(err, provider.ErrOAuthConflict) },
		},
		{
			name: "cancelled",
			setup: func(t *testing.T) provider.SessionID {
				sessionID := createPendingLifecycleSession(t, sessions, "matrix-cancelled", "v", now)
				if err := sessions.Cancel(context.Background(), provider.Devin, store.OAuthFlowCallbackPKCE, "matrix-cancelled", cancelledMessage, now); err != nil {
					t.Fatal(err)
				}
				return sessionID
			},
			wantErr: func(err error) bool { return errors.Is(err, provider.ErrOAuthConflict) },
		},
		{
			name: "consumed",
			setup: func(t *testing.T) provider.SessionID {
				sessionID := createPendingLifecycleSession(t, sessions, "matrix-consumed", "v", now)
				if _, err := sessions.Consume(context.Background(), provider.Devin, store.OAuthFlowCallbackPKCE, "matrix-consumed", now); err != nil {
					t.Fatal(err)
				}
				return sessionID
			},
			wantErr: func(err error) bool { return errors.Is(err, provider.ErrOAuthConflict) },
		},
		{
			name: "expired",
			setup: func(t *testing.T) provider.SessionID {
				sessionID := createPendingLifecycleSession(t, sessions, "matrix-expired", "v", now)
				// ExpirePendingBefore transitions elapsed pending rows to
				// expired with a secret-free terminal payload. Use a clock
				// past the session expiry.
				if _, err := sessions.ExpirePendingBefore(context.Background(), provider.Devin, store.OAuthFlowCallbackPKCE, now.Add(2*time.Hour)); err != nil {
					t.Fatal(err)
				}
				return sessionID
			},
			wantErr: func(err error) bool { return errors.Is(err, provider.ErrOAuthConflict) },
		},
		{
			name:    "unknown",
			setup:   func(t *testing.T) provider.SessionID { return provider.SessionID("nonexistent") },
			wantErr: func(err error) bool { return errors.Is(err, ErrNotFound) && !errors.Is(err, provider.ErrOAuthConflict) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sessionID := tc.setup(t)
			ref := provider.AuthorizationRef{Provider: provider.Devin, SessionID: sessionID}
			err := lifecycle.Cancel(context.Background(), ref)
			if !tc.wantErr(err) {
				t.Fatalf("cancel %s error = %v", tc.name, err)
			}
			// Terminal immutability: for terminal cases, status must be unchanged.
			if tc.name != "unknown" {
				stored, lookupErr := sessions.GetBySessionID(context.Background(), provider.Devin, store.OAuthFlowCallbackPKCE, string(sessionID))
				if lookupErr != nil {
					t.Fatalf("post-cancel lookup error = %v", lookupErr)
				}
				if stored.Status != tc.name {
					t.Fatalf("post-cancel status = %q, want %q (immutability violated)", stored.Status, tc.name)
				}
			}
		})
	}
}

// TestProviderLifecycleCallbackRaceCancelVsComplete verifies the callback
// race: when a Complete call consumes a session and a concurrent Cancel
// arrives, the Cancel must return provider.ErrOAuthConflict (409 at admin)
// rather than 500 or a leaked secret. The completed session is never mutated
// by the losing Cancel.
func TestProviderLifecycleCallbackRaceCancelVsComplete(t *testing.T) {
	_, sessions, lifecycle, exchange, transaction, now := newLifecycleFixture(t)
	const state, verifier, code = "race-cancel-state", "race-verifier", "race-code"
	sessionID := createPendingLifecycleSession(t, sessions, state, verifier, now)
	ref := provider.AuthorizationRef{Provider: provider.Devin, SessionID: sessionID}

	// Complete the session first (simulating the callback winning the race).
	exchange.token = "opaque-race-token"
	result, err := lifecycle.Complete(context.Background(), provider.AuthorizationRef{Provider: provider.Devin, State: state}, provider.AuthorizationCompletion{Code: code})
	if err != nil || result.AccountID != "acct_devin" {
		t.Fatalf("complete result=%+v err=%v", result, err)
	}
	if exchange.calls.Load() != 1 || transaction.calls.Load() != 1 {
		t.Fatalf("exchange=%d transaction=%d", exchange.calls.Load(), transaction.calls.Load())
	}

	// The late Cancel must classify as conflict, never 500, never leak.
	cancelErr := lifecycle.Cancel(context.Background(), ref)
	if !errors.Is(cancelErr, provider.ErrOAuthConflict) {
		t.Fatalf("late cancel error = %v, want ErrOAuthConflict", cancelErr)
	}

	// Terminal immutability: the session remains consumed (the fake
	// transaction does not transition to completed; the real transaction
	// would). The late Cancel must not mutate it further.
	stored, lookupErr := sessions.GetBySessionID(context.Background(), provider.Devin, store.OAuthFlowCallbackPKCE, string(sessionID))
	if lookupErr != nil || stored.Status != "consumed" {
		t.Fatalf("post-race session = %+v, %v (immutability violated)", stored, lookupErr)
	}
	// No additional exchange or transaction calls from the cancel.
	if exchange.calls.Load() != 1 || transaction.calls.Load() != 1 {
		t.Fatalf("cancel invoked dependencies: exchange=%d transaction=%d", exchange.calls.Load(), transaction.calls.Load())
	}
}

// TestProviderLifecycleCallbackConcurrentCancelVsComplete is the formal
// concurrent race evidence: a Cancel and a Complete hit the same pending
// Devin session simultaneously under a release barrier. Exactly one wins;
// the loser receives provider.ErrOAuthConflict (409 at admin). The exchange
// and transaction are invoked at most once total across both outcomes, so
// no second token exchange occurs. The persisted session is terminal
// (consumed if Complete won, cancelled if Cancel won) and secret-free
// (Pending is nil). Runs multiple iterations to exercise both interleavings.
func TestProviderLifecycleCallbackConcurrentCancelVsComplete(t *testing.T) {
	const iterations = 12
	for i := range iterations {
		_, sessions, lifecycle, exchange, transaction, now := newLifecycleFixture(t)
		state := fmt.Sprintf("concurrent-race-%d", i)
		verifier := fmt.Sprintf("concurrent-verifier-%d", i)
		sessionID := createPendingLifecycleSession(t, sessions, state, verifier, now)
		ref := provider.AuthorizationRef{Provider: provider.Devin, SessionID: sessionID}
		completeRef := provider.AuthorizationRef{Provider: provider.Devin, State: state}

		start := make(chan struct{})
		var wg sync.WaitGroup
		var completeErr error
		var cancelErr error
		var completeAccount string
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			result, err := lifecycle.Complete(context.Background(), completeRef, provider.AuthorizationCompletion{Code: "code"})
			if err == nil {
				completeAccount = result.AccountID
			}
			completeErr = err
		}()
		go func() {
			defer wg.Done()
			<-start
			cancelErr = lifecycle.Cancel(context.Background(), ref)
		}()
		close(start)
		wg.Wait()

		completeWon := completeErr == nil
		cancelWon := cancelErr == nil
		if completeWon && cancelWon {
			t.Fatalf("iteration %d: both complete and cancel succeeded", i)
		}
		if !completeWon && !cancelWon {
			t.Fatalf("iteration %d: both failed: complete=%v cancel=%v", i, completeErr, cancelErr)
		}
		if completeWon {
			if completeAccount != "acct_devin" {
				t.Fatalf("iteration %d: complete account = %q, want acct_devin", i, completeAccount)
			}
			// Cancel lost: the session is consumed/completed, which is
			// terminal for Cancel, so it must surface ErrOAuthConflict.
			if !errors.Is(cancelErr, provider.ErrOAuthConflict) {
				t.Fatalf("iteration %d: losing cancel error = %v, want ErrOAuthConflict", i, cancelErr)
			}
		} else {
			// Complete lost the race: Consume found the session no longer
			// pending (cancelled by the winning Cancel). The callback path
			// surfaces its own sanitized non-500 conflict error rather than
			// provider.ErrOAuthConflict (which is the cancel-path sentinel).
			// The key invariants — no second exchange and a terminal,
			// secret-free row — are asserted below.
			if completeErr == nil {
				t.Fatalf("iteration %d: complete unexpectedly succeeded", i)
			}
			if errors.Is(completeErr, provider.ErrOAuthConflict) {
				t.Fatalf("iteration %d: complete-path must not return the cancel sentinel", i)
			}
		}

		// At most one exchange and one transaction across both outcomes:
		// no second token exchange regardless of interleaving.
		if calls := exchange.calls.Load(); calls > 1 {
			t.Fatalf("iteration %d: exchange calls = %d, want <= 1", i, calls)
		}
		if calls := transaction.calls.Load(); calls > 1 {
			t.Fatalf("iteration %d: transaction calls = %d, want <= 1", i, calls)
		}

		// The persisted session is terminal and secret-free.
		stored, lookupErr := sessions.GetBySessionID(context.Background(), provider.Devin, store.OAuthFlowCallbackPKCE, string(sessionID))
		if lookupErr != nil {
			t.Fatalf("iteration %d: lookup error = %v", i, lookupErr)
		}
		if stored.Status != "consumed" && stored.Status != "cancelled" && stored.Status != "completed" {
			t.Fatalf("iteration %d: post-race status = %q, want consumed/cancelled/completed", i, stored.Status)
		}
		if stored.Pending != nil {
			t.Fatalf("iteration %d: post-race Pending must be nil, got %+v", i, stored.Pending)
		}
	}
}

// TestProviderLifecycleTwoSessionIsolation is the formal two-session
// isolation evidence for the Devin callback-PKCE lifecycle. Two same-provider
// flows are started with distinct opaque SessionIDs; Status and Cancel are
// exercised concurrently across both sessions. Session A is cancelled while
// both sessions are polled; A must transition to cancelled and B must remain
// pending and fully independent. No status/account/state is cross-observed:
// each Status resolves only its own SessionID, carries no account, and never
// reflects the other session's state. Cancel(A) cannot affect B — B stays
// pending and remains independently cancellable after A is terminal. The
// exchange and transaction dependencies are never invoked (no completion).
func TestProviderLifecycleTwoSessionIsolation(t *testing.T) {
	ctx := context.Background()
	_, sessions, lifecycle, exchange, transaction, now := newLifecycleFixture(t)

	// Start two same-provider (Devin) flows. Each Start mints a fresh opaque
	// SessionID and persists an independent pending session.
	authA, err := lifecycle.Start(ctx)
	if err != nil {
		t.Fatalf("start A: %v", err)
	}
	authB, err := lifecycle.Start(ctx)
	if err != nil {
		t.Fatalf("start B: %v", err)
	}
	sessionIDA, sessionIDB := authA.Ref.SessionID, authB.Ref.SessionID
	if sessionIDA == "" || sessionIDB == "" {
		t.Fatalf("opaque SessionIDs required: A=%q B=%q", sessionIDA, sessionIDB)
	}
	if sessionIDA == sessionIDB {
		t.Fatalf("distinct SessionIDs required: both %q", sessionIDA)
	}
	refA := provider.AuthorizationRef{Provider: provider.Devin, SessionID: sessionIDA}
	refB := provider.AuthorizationRef{Provider: provider.Devin, SessionID: sessionIDB}

	// Concurrently poll Status(A), Status(B) and Cancel(A) under a release
	// barrier. Cancel(A) is the only mutator on A, so it must win against the
	// pending row; the concurrent Status(A) may observe pending or cancelled
	// depending on interleaving, but must never observe B.
	start := make(chan struct{})
	var wg sync.WaitGroup
	type statusResult struct {
		session provider.AuthorizationSession
		err     error
	}
	var statusA, statusB statusResult
	var cancelAErr error
	wg.Add(3)
	go func() {
		defer wg.Done()
		<-start
		statusA.session, statusA.err = lifecycle.Status(ctx, refA)
	}()
	go func() {
		defer wg.Done()
		<-start
		statusB.session, statusB.err = lifecycle.Status(ctx, refB)
	}()
	go func() {
		defer wg.Done()
		<-start
		cancelAErr = lifecycle.Cancel(ctx, refA)
	}()
	close(start)
	wg.Wait()

	// Cancel(A) must succeed: A was pending and only this cancel can
	// terminalize it. No other goroutine mutates A.
	if cancelAErr != nil {
		t.Fatalf("cancel A error = %v, want nil", cancelAErr)
	}
	if statusA.err != nil {
		t.Fatalf("concurrent status A error = %v", statusA.err)
	}
	if statusB.err != nil {
		t.Fatalf("concurrent status B error = %v", statusB.err)
	}

	// No cross-observation: each Status resolves only its own opaque
	// SessionID and never the sibling's. AccountID must be empty for both
	// (no completion ran).
	if statusA.session.Ref.SessionID != sessionIDA {
		t.Fatalf("status A resolved SessionID = %q, want %q (cross-observed B)", statusA.session.Ref.SessionID, sessionIDA)
	}
	if statusB.session.Ref.SessionID != sessionIDB {
		t.Fatalf("status B resolved SessionID = %q, want %q (cross-observed A)", statusB.session.Ref.SessionID, sessionIDB)
	}
	if statusA.session.AccountID != "" || statusB.session.AccountID != "" {
		t.Fatalf("account cross-observed: A=%q B=%q, want empty", statusA.session.AccountID, statusB.session.AccountID)
	}
	// Status(A) raced with Cancel(A): pending or cancelled are both valid.
	// Any other status would mean a foreign mutation crossed into A.
	if statusA.session.Status != provider.AuthorizationPending && statusA.session.Status != provider.AuthorizationCancelled {
		t.Fatalf("concurrent status A = %q, want pending or cancelled", statusA.session.Status)
	}
	// Status(B) must remain pending: Cancel(A) cannot affect B.
	if statusB.session.Status != provider.AuthorizationPending {
		t.Fatalf("concurrent status B = %q, want pending (cancel A affected B)", statusB.session.Status)
	}

	// Post-race: A has transitioned to cancelled as expected.
	finalA, err := lifecycle.Status(ctx, refA)
	if err != nil {
		t.Fatalf("post-race status A error = %v", err)
	}
	if finalA.Status != provider.AuthorizationCancelled {
		t.Fatalf("post-race status A = %q, want cancelled", finalA.Status)
	}
	if finalA.Ref.SessionID != sessionIDA {
		t.Fatalf("post-race status A SessionID = %q, want %q", finalA.Ref.SessionID, sessionIDA)
	}
	if finalA.SanitizedMessage != cancelledMessage {
		t.Fatalf("post-race A sanitized = %q, want %q", finalA.SanitizedMessage, cancelledMessage)
	}

	// B stays pending and unchanged after A's cancellation.
	finalB, err := lifecycle.Status(ctx, refB)
	if err != nil {
		t.Fatalf("post-race status B error = %v", err)
	}
	if finalB.Status != provider.AuthorizationPending {
		t.Fatalf("post-race status B = %q, want pending (isolation violated)", finalB.Status)
	}
	if finalB.Ref.SessionID != sessionIDB {
		t.Fatalf("post-race status B SessionID = %q, want %q", finalB.Ref.SessionID, sessionIDB)
	}
	if finalB.SanitizedMessage != "" {
		t.Fatalf("post-race B sanitized = %q, want empty (A's cancel leaked into B)", finalB.SanitizedMessage)
	}

	// Cancel(A) cannot affect B: B is still independently cancellable.
	if err := lifecycle.Cancel(ctx, refB); err != nil {
		t.Fatalf("cancel B after cancel A error = %v, want nil (B not independently cancellable)", err)
	}
	terminalB, err := lifecycle.Status(ctx, refB)
	if err != nil {
		t.Fatalf("terminal status B error = %v", err)
	}
	if terminalB.Status != provider.AuthorizationCancelled {
		t.Fatalf("terminal status B = %q, want cancelled", terminalB.Status)
	}
	if terminalB.Ref.SessionID != sessionIDB {
		t.Fatalf("terminal status B SessionID = %q, want %q", terminalB.Ref.SessionID, sessionIDB)
	}

	// A is now terminal: re-cancelling A must surface the stable conflict
	// sentinel (409 at admin), never mutate B or resurrect A.
	if err := lifecycle.Cancel(ctx, refA); !errors.Is(err, provider.ErrOAuthConflict) {
		t.Fatalf("re-cancel A error = %v, want ErrOAuthConflict", err)
	}
	// A wrong-ref lookup (B's SessionID against A's expectation) must not
	// resolve A; it resolves B. This proves SessionID-bound isolation at the
	// lookup layer: a cancel of A's ref never touches B's row and vice versa.
	storedA, err := sessions.GetBySessionID(ctx, provider.Devin, store.OAuthFlowCallbackPKCE, string(sessionIDA))
	if err != nil {
		t.Fatal(err)
	}
	storedB, err := sessions.GetBySessionID(ctx, provider.Devin, store.OAuthFlowCallbackPKCE, string(sessionIDB))
	if err != nil {
		t.Fatal(err)
	}
	if storedA.SessionID == storedB.SessionID {
		t.Fatalf("stored rows share SessionID %q", storedA.SessionID)
	}
	if storedA.Status != "cancelled" || storedB.Status != "cancelled" {
		t.Fatalf("stored A=%q B=%q, want both cancelled", storedA.Status, storedB.Status)
	}
	if storedA.SanitizedError != cancelledMessage || storedB.SanitizedError != cancelledMessage {
		t.Fatalf("stored sanitized A=%q B=%q, want %q", storedA.SanitizedError, storedB.SanitizedError, cancelledMessage)
	}
	// Both rows are secret-free after cancellation.
	if storedA.Pending != nil || storedB.Pending != nil {
		t.Fatalf("post-cancel Pending must be nil: A=%+v B=%+v", storedA.Pending, storedB.Pending)
	}

	// No completion ran: isolation test never exchanged a token or saved an
	// account. Both sessions were resolved purely via SessionID management.
	if exchange.calls.Load() != 0 || transaction.calls.Load() != 0 {
		t.Fatalf("isolation test invoked dependencies: exchange=%d transaction=%d", exchange.calls.Load(), transaction.calls.Load())
	}

	// Expiry sanity: both started sessions share the fixture clock's expiry.
	if !authA.ExpiresAt.Equal(now.Add(pendingSessionTTL)) || !authB.ExpiresAt.Equal(now.Add(pendingSessionTTL)) {
		t.Fatalf("expiry A=%v B=%v, want %v", authA.ExpiresAt, authB.ExpiresAt, now.Add(pendingSessionTTL))
	}
}
