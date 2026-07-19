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
		config: OAuthConfig{CallbackOrigin: "https://byos.example.test", CallbackPath: "/oauth/devin/callback"},
		now:    func() time.Time { return now },
	}
	return database, sessions, lifecycle, exchange, transaction, now
}

func createPendingLifecycleSession(t *testing.T, sessions *store.OAuthSessionRepository, state, verifier string, now time.Time) {
	t.Helper()
	expires := now.Add(pendingSessionTTL)
	if err := sessions.Create(context.Background(), store.OAuthSession{
		Provider: provider.Devin, FlowType: store.OAuthFlowCallbackPKCE, State: state,
		Pending:   &store.OAuthPendingPayload{Verifier: verifier, RedirectURI: "https://byos.example.test/oauth/devin/callback", ExpiresAt: expires},
		ExpiresAt: expires,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestProviderLifecycleStartPersistsFiveMinutePendingProjection(t *testing.T) {
	_, sessions, lifecycle, exchange, transaction, now := newLifecycleFixture(t)
	authorization, err := lifecycle.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Ref.Provider != provider.Devin || authorization.Ref.State == "" || authorization.VerificationURL == "" || authorization.VerificationURLComplete != authorization.VerificationURL {
		t.Fatalf("unsafe/incomplete authorization projection: %+v", authorization)
	}
	if !authorization.ExpiresAt.Equal(now.Add(5 * time.Minute)) {
		t.Fatalf("expiry=%v", authorization.ExpiresAt)
	}
	session, err := sessions.Get(context.Background(), provider.Devin, store.OAuthFlowCallbackPKCE, authorization.Ref.State)
	if err != nil {
		t.Fatal(err)
	}
	if session.Status != "pending" || session.Pending == nil || session.Pending.Verifier == "" || session.State != "" || len(session.StateHash) != 32 {
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
	createPendingLifecycleSession(t, sessions, "cancel-state", "cancel-verifier", now)
	ref := provider.AuthorizationRef{Provider: provider.Devin, State: "cancel-state"}
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
	if err := lifecycle.Cancel(context.Background(), ref); err == nil {
		t.Fatal("terminal cancel repeated")
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
		act  func(provider.AuthorizationRef) error
	}{
		{name: "status", act: func(ref provider.AuthorizationRef) error {
			status, err := lifecycle.Status(context.Background(), ref)
			if err == nil && (status.Status != provider.AuthorizationExpired || status.SanitizedMessage != expiredMessage) {
				t.Fatalf("status = %+v", status)
			}
			return err
		}},
		{name: "complete before code validation", act: func(ref provider.AuthorizationRef) error {
			_, err := lifecycle.Complete(context.Background(), ref, provider.AuthorizationCompletion{})
			return err
		}},
		{name: "cancel before cancellation", act: func(ref provider.AuthorizationRef) error {
			return lifecycle.Cancel(context.Background(), ref)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := "expired-" + test.name
			createPendingLifecycleSession(t, sessions, state, "secret-verifier", now)
			lifecycle.now = func() time.Time { return now.Add(pendingSessionTTL) }
			err := test.act(provider.AuthorizationRef{Provider: provider.Devin, State: state})
			if test.name == "status" {
				if err != nil {
					t.Fatal(err)
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
