package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appcrypto "byos/internal/crypto"
	"byos/internal/provider"
)

// newConflictMatrixStore opens a fresh isolated SQLite store + key set for a
// conflict-matrix test. Each subtest gets its own temp dir so terminal rows
// seeded by one case never leak into another.
func newConflictMatrixStore(t *testing.T) (*SQLite, appcrypto.Keys, *OAuthSessionRepository, time.Time) {
	t.Helper()
	ctx := context.Background()
	database, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{91}, 32))
	if err != nil {
		t.Fatal(err)
	}
	repo := NewOAuthSessionRepository(database.DB, keys)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	return database, keys, repo, now
}

// seedPendingSession creates a pending OAuthSession for the given provider
// and flow with a known SessionID and returns that SessionID. The raw state
// is unique per call so rows never collide.
func seedPendingSession(t *testing.T, repo *OAuthSessionRepository, kind provider.Kind, flow OAuthFlowType, state, verifier string, now time.Time) string {
	t.Helper()
	session := OAuthSession{
		Provider:  kind,
		FlowType:  flow,
		State:     state,
		SessionID: "sess-" + state,
		ExpiresAt: now.Add(time.Hour),
	}
	if flow == OAuthFlowCallbackPKCE {
		session.Pending = &OAuthPendingPayload{
			Verifier:    verifier,
			RedirectURI: "https://byos.example.test/oauth/callback",
			ExpiresAt:   now.Add(time.Hour),
		}
	} else {
		session.DeviceCode = "device-" + state
		session.UserCode = "USER-" + state
		session.TokenEndpoint = "https://auth.example.test/token"
		session.PollInterval = 5 * time.Second
	}
	if err := repo.Create(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	return session.SessionID
}

// transitionToStatus moves a seeded pending session into the requested
// terminal status using the store's own mutation methods, so the matrix
// exercises the same state machine the production lifecycle does. The
// "expired" status is reached via ExpirePendingBefore with a clock past the
// session expiry; "consumed" via Consume; "completed" via Complete (after
// Authorize for device, after Consume for callback); "failed" via Fail;
// "cancelled" via Cancel.
func transitionToStatus(t *testing.T, repo *OAuthSessionRepository, kind provider.Kind, flow OAuthFlowType, state, sessionID, target string, now time.Time) {
	t.Helper()
	ctx := context.Background()
	switch target {
	case "pending":
		// Already pending from seed; nothing to do.
	case "authorized":
		if flow != OAuthFlowDevice {
			t.Fatalf("authorized only valid for device flow, got %s", flow)
		}
		if err := repo.Authorize(ctx, kind, flow, state, OAuthAuthorization{AccessToken: "access-" + state, AuthorizedAt: now, ExpiresAt: now.Add(time.Hour)}, now); err != nil {
			t.Fatal(err)
		}
	case "consumed":
		if flow != OAuthFlowCallbackPKCE {
			t.Fatalf("consumed only valid for callback flow, got %s", flow)
		}
		if _, err := repo.Consume(ctx, kind, flow, state, now); err != nil {
			t.Fatal(err)
		}
	case "completed":
		if flow == OAuthFlowDevice {
			if err := repo.Authorize(ctx, kind, flow, state, OAuthAuthorization{AccessToken: "access-" + state, AuthorizedAt: now, ExpiresAt: now.Add(time.Hour)}, now); err != nil {
				t.Fatal(err)
			}
			if err := repo.Complete(ctx, kind, flow, state, "acct-"+state, now); err != nil {
				t.Fatal(err)
			}
		} else {
			if _, err := repo.Consume(ctx, kind, flow, state, now); err != nil {
				t.Fatal(err)
			}
			if err := repo.Complete(ctx, kind, flow, state, "acct-"+state, now); err != nil {
				t.Fatal(err)
			}
		}
	case "failed":
		if flow == OAuthFlowCallbackPKCE {
			if _, err := repo.Consume(ctx, kind, flow, state, now); err != nil {
				t.Fatal(err)
			}
		}
		if err := repo.Fail(ctx, kind, flow, state, "upstream denied", now); err != nil {
			t.Fatal(err)
		}
	case "expired":
		// ExpirePendingBefore expires elapsed pending rows in place. Use a
		// clock past the session expiry so the pending row transitions to
		// expired with a secret-free terminal payload.
		if _, err := repo.ExpirePendingBefore(ctx, kind, flow, now.Add(2*time.Hour)); err != nil {
			t.Fatal(err)
		}
	case "cancelled":
		if err := repo.Cancel(ctx, kind, flow, state, "user cancelled", now); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown target status %q", target)
	}
}

// TestOAuthCancelBySessionIDConflictMatrix exercises CancelBySessionID across
// both providers and both flows for every reachable status. A pending or
// authorized session cancels successfully; a known-but-terminal session
// (consumed, completed, failed, expired, already cancelled) returns
// ErrOAuthTerminalConflict, which must also satisfy errors.Is(sql.ErrNoRows)
// for backward-compatible 404 callers while being distinguishable first for
// 409 classification. A genuinely unknown or wrong-provider/wrong-flow
// SessionID returns a plain sql.ErrNoRows (404) and never ErrOAuthTerminalConflict.
// Terminal immutability is asserted: the stored status is unchanged after a
// rejected cancel.
func TestOAuthCancelBySessionIDConflictMatrix(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		kind   provider.Kind
		flow   OAuthFlowType
		status string
		// wantErr is nil for the success path, otherwise the exact sentinel
		// the cancel must return.
		wantErr error
		// wantSuccess is true for the pending/authorized success path.
		wantSuccess bool
	}{
		// xAI device flow: pending and authorized are cancellable.
		{"xai-device-pending", provider.XAI, OAuthFlowDevice, "pending", nil, true},
		{"xai-device-authorized", provider.XAI, OAuthFlowDevice, "authorized", nil, true},
		{"xai-device-completed", provider.XAI, OAuthFlowDevice, "completed", ErrOAuthTerminalConflict, false},
		{"xai-device-failed", provider.XAI, OAuthFlowDevice, "failed", ErrOAuthTerminalConflict, false},
		{"xai-device-expired", provider.XAI, OAuthFlowDevice, "expired", ErrOAuthTerminalConflict, false},
		{"xai-device-cancelled", provider.XAI, OAuthFlowDevice, "cancelled", ErrOAuthTerminalConflict, false},
		// Devin callback-PKCE flow: pending is cancellable; consumed is terminal.
		{"devin-callback-pending", provider.Devin, OAuthFlowCallbackPKCE, "pending", nil, true},
		{"devin-callback-consumed", provider.Devin, OAuthFlowCallbackPKCE, "consumed", ErrOAuthTerminalConflict, false},
		{"devin-callback-completed", provider.Devin, OAuthFlowCallbackPKCE, "completed", ErrOAuthTerminalConflict, false},
		{"devin-callback-failed", provider.Devin, OAuthFlowCallbackPKCE, "failed", ErrOAuthTerminalConflict, false},
		{"devin-callback-expired", provider.Devin, OAuthFlowCallbackPKCE, "expired", ErrOAuthTerminalConflict, false},
		{"devin-callback-cancelled", provider.Devin, OAuthFlowCallbackPKCE, "cancelled", ErrOAuthTerminalConflict, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, repo, now := newConflictMatrixStore(t)
			state := tc.name + "-state"
			verifier := tc.name + "-verifier"
			sessionID := seedPendingSession(t, repo, tc.kind, tc.flow, state, verifier, now)
			transitionToStatus(t, repo, tc.kind, tc.flow, state, sessionID, tc.status, now)

			err := repo.CancelBySessionID(ctx, tc.kind, tc.flow, sessionID, "cancel-attempt", now.Add(time.Minute))
			if tc.wantSuccess {
				if err != nil {
					t.Fatalf("cancel %s error = %v, want nil", tc.name, err)
				}
				stored, lookupErr := repo.GetBySessionID(ctx, tc.kind, tc.flow, sessionID)
				if lookupErr != nil || stored.Status != "cancelled" {
					t.Fatalf("post-cancel status = %q, want cancelled (%v)", stored.Status, lookupErr)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("cancel %s error = %v, want %v", tc.name, err, tc.wantErr)
			}
			// ErrOAuthTerminalConflict must wrap sql.ErrNoRows so legacy
			// errors.Is(err, sql.ErrNoRows) callers still treat the session
			// as non-mutable, while new callers classify 409 first.
			if !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("terminal conflict %v must satisfy errors.Is(sql.ErrNoRows) for compatibility", err)
			}
			// Terminal immutability: status is unchanged after the rejected cancel.
			stored, lookupErr := repo.GetBySessionID(ctx, tc.kind, tc.flow, sessionID)
			if lookupErr != nil {
				t.Fatalf("post-cancel lookup error = %v", lookupErr)
			}
			if stored.Status != tc.status {
				t.Fatalf("post-cancel status = %q, want %q (immutability violated)", stored.Status, tc.status)
			}
		})
	}

	// Unknown SessionID: plain sql.ErrNoRows (404), never ErrOAuthTerminalConflict.
	t.Run("unknown-session-id", func(t *testing.T) {
		_, _, repo, now := newConflictMatrixStore(t)
		for _, tc := range []struct {
			name string
			kind provider.Kind
			flow OAuthFlowType
		}{
			{"xai-device", provider.XAI, OAuthFlowDevice},
			{"devin-callback", provider.Devin, OAuthFlowCallbackPKCE},
		} {
			t.Run(tc.name, func(t *testing.T) {
				err := repo.CancelBySessionID(ctx, tc.kind, tc.flow, "nonexistent-session-id", "cancel", now)
				if !errors.Is(err, sql.ErrNoRows) {
					t.Fatalf("unknown cancel error = %v, want sql.ErrNoRows", err)
				}
				if errors.Is(err, ErrOAuthTerminalConflict) {
					t.Fatalf("unknown SessionID must not be classified as terminal conflict: %v", err)
				}
			})
		}
	})

	// Wrong-provider/wrong-flow SessionID: even if a session exists for one
	// provider+flow, the other provider or flow must not resolve it. The
	// cancel returns a plain sql.ErrNoRows (404), never a terminal conflict,
	// because the lookup is provider+flow-bound and finds no row.
	t.Run("wrong-provider-and-flow", func(t *testing.T) {
		_, _, repo, now := newConflictMatrixStore(t)
		state := "cross-flow-state"
		sessionID := seedPendingSession(t, repo, provider.Devin, OAuthFlowCallbackPKCE, state, "verifier", now)
		for _, wrong := range []struct {
			name string
			kind provider.Kind
			flow OAuthFlowType
		}{
			{"xai-looks-at-devin", provider.XAI, OAuthFlowCallbackPKCE},
			{"devin-device-flow", provider.Devin, OAuthFlowDevice},
			{"xai-device-flow", provider.XAI, OAuthFlowDevice},
		} {
			t.Run(wrong.name, func(t *testing.T) {
				err := repo.CancelBySessionID(ctx, wrong.kind, wrong.flow, sessionID, "cancel", now)
				if !errors.Is(err, sql.ErrNoRows) {
					t.Fatalf("wrong-provider/flow cancel error = %v, want sql.ErrNoRows", err)
				}
				if errors.Is(err, ErrOAuthTerminalConflict) {
					t.Fatalf("wrong-provider/flow must not classify as terminal conflict: %v", err)
				}
				// The original session is untouched.
				stored, lookupErr := repo.GetBySessionID(ctx, provider.Devin, OAuthFlowCallbackPKCE, sessionID)
				if lookupErr != nil || stored.Status != "pending" {
					t.Fatalf("original session mutated by wrong-provider cancel: %+v %v", stored, lookupErr)
				}
			})
		}
	})
}

// TestOAuthExpireBySessionIDConflictMatrix mirrors the cancel matrix for
// ExpireBySessionID: pending/authorized expire successfully; terminal rows
// return ErrOAuthTerminalConflict (still errors.Is sql.ErrNoRows); unknown
// returns plain sql.ErrNoRows. Terminal immutability is asserted.
func TestOAuthExpireBySessionIDConflictMatrix(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name        string
		kind        provider.Kind
		flow        OAuthFlowType
		status      string
		wantSuccess bool
	}{
		{"xai-device-pending", provider.XAI, OAuthFlowDevice, "pending", true},
		{"xai-device-authorized", provider.XAI, OAuthFlowDevice, "authorized", true},
		{"xai-device-completed", provider.XAI, OAuthFlowDevice, "completed", false},
		{"xai-device-failed", provider.XAI, OAuthFlowDevice, "failed", false},
		{"xai-device-expired", provider.XAI, OAuthFlowDevice, "expired", false},
		{"xai-device-cancelled", provider.XAI, OAuthFlowDevice, "cancelled", false},
		{"devin-callback-pending", provider.Devin, OAuthFlowCallbackPKCE, "pending", true},
		{"devin-callback-consumed", provider.Devin, OAuthFlowCallbackPKCE, "consumed", false},
		{"devin-callback-completed", provider.Devin, OAuthFlowCallbackPKCE, "completed", false},
		{"devin-callback-failed", provider.Devin, OAuthFlowCallbackPKCE, "failed", false},
		{"devin-callback-expired", provider.Devin, OAuthFlowCallbackPKCE, "expired", false},
		{"devin-callback-cancelled", provider.Devin, OAuthFlowCallbackPKCE, "cancelled", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, repo, now := newConflictMatrixStore(t)
			state := tc.name + "-state"
			verifier := tc.name + "-verifier"
			sessionID := seedPendingSession(t, repo, tc.kind, tc.flow, state, verifier, now)
			transitionToStatus(t, repo, tc.kind, tc.flow, state, sessionID, tc.status, now)

			err := repo.ExpireBySessionID(ctx, tc.kind, tc.flow, sessionID, "expire-attempt", now.Add(time.Minute))
			if tc.wantSuccess {
				if err != nil {
					t.Fatalf("expire %s error = %v, want nil", tc.name, err)
				}
				stored, lookupErr := repo.GetBySessionID(ctx, tc.kind, tc.flow, sessionID)
				if lookupErr != nil || stored.Status != "expired" {
					t.Fatalf("post-expire status = %q, want expired (%v)", stored.Status, lookupErr)
				}
				return
			}
			if !errors.Is(err, ErrOAuthTerminalConflict) {
				t.Fatalf("expire %s error = %v, want ErrOAuthTerminalConflict", tc.name, err)
			}
			if !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("terminal conflict %v must satisfy errors.Is(sql.ErrNoRows)", err)
			}
			stored, lookupErr := repo.GetBySessionID(ctx, tc.kind, tc.flow, sessionID)
			if lookupErr != nil {
				t.Fatalf("post-expire lookup error = %v", lookupErr)
			}
			if stored.Status != tc.status {
				t.Fatalf("post-expire status = %q, want %q (immutability violated)", stored.Status, tc.status)
			}
		})
	}

	t.Run("unknown-session-id", func(t *testing.T) {
		_, _, repo, now := newConflictMatrixStore(t)
		err := repo.ExpireBySessionID(ctx, provider.Devin, OAuthFlowCallbackPKCE, "nonexistent", "expire", now)
		if !errors.Is(err, sql.ErrNoRows) || errors.Is(err, ErrOAuthTerminalConflict) {
			t.Fatalf("unknown expire error = %v, want plain sql.ErrNoRows", err)
		}
	})
}

// TestDevinCallbackConsumeConcurrentRace is the formal store-level race
// evidence for the Devin callback-PKCE consume path. Multiple goroutines
// race to Consume the same pending session under a release barrier. Exactly
// one winner receives the verifier+redirect URI; every loser receives
// ErrOAuthTerminalConflict (the row is now consumed and thus terminal for
// Consume's allowed source set). No second exchange is possible because
// Consume is the only path that returns the verifier and it is atomic. The
// persisted row is secret-free after the race (Pending is nil), and no
// verifier appears in the database file.
func TestDevinCallbackConsumeConcurrentRace(t *testing.T) {
	ctx := context.Background()
	database, _, repo, now := newConflictMatrixStore(t)
	const state = "consume-race-state"
	const verifier = "consume-race-verifier-secret"
	const redirect = "https://byos.example.test/oauth/callback/race"
	session := OAuthSession{
		Provider:  provider.Devin,
		FlowType:  OAuthFlowCallbackPKCE,
		State:     state,
		SessionID: "sess-consume-race",
		Pending:   &OAuthPendingPayload{Verifier: verifier, RedirectURI: redirect, ExpiresAt: now.Add(time.Hour)},
		ExpiresAt: now.Add(time.Hour),
	}
	if err := repo.Create(ctx, session); err != nil {
		t.Fatal(err)
	}

	const attempts = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	type outcome struct {
		payload OAuthPendingPayload
		err     error
	}
	outcomes := make(chan outcome, attempts)
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			payload, err := repo.Consume(ctx, provider.Devin, OAuthFlowCallbackPKCE, state, now)
			outcomes <- outcome{payload: payload, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(outcomes)

	var winners int
	var winnerPayload OAuthPendingPayload
	var loserConflicts int
	for o := range outcomes {
		if o.err == nil {
			winners++
			winnerPayload = o.payload
			continue
		}
		if !errors.Is(o.err, ErrOAuthTerminalConflict) {
			t.Fatalf("loser error = %v, want ErrOAuthTerminalConflict", o.err)
		}
		if !errors.Is(o.err, sql.ErrNoRows) {
			t.Fatalf("loser conflict %v must satisfy errors.Is(sql.ErrNoRows)", o.err)
		}
		loserConflicts++
	}
	if winners != 1 {
		t.Fatalf("winners = %d, want exactly 1", winners)
	}
	if loserConflicts != attempts-1 {
		t.Fatalf("loser conflicts = %d, want %d", loserConflicts, attempts-1)
	}
	if winnerPayload.Verifier != verifier || winnerPayload.RedirectURI != redirect {
		t.Fatalf("winner payload = %+v, want verifier=%q redirect=%q", winnerPayload, verifier, redirect)
	}

	// No second exchange: a follow-up Consume after the race must conflict.
	if _, err := repo.Consume(ctx, provider.Devin, OAuthFlowCallbackPKCE, state, now); !errors.Is(err, ErrOAuthTerminalConflict) {
		t.Fatalf("post-race consume error = %v, want ErrOAuthTerminalConflict", err)
	}

	// The persisted row is consumed and secret-free.
	stored, err := repo.Get(ctx, provider.Devin, OAuthFlowCallbackPKCE, state)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "consumed" || stored.Pending != nil {
		t.Fatalf("post-race session = %+v, want status=consumed Pending=nil", stored)
	}

	// No verifier leak in the database file, WAL, or SHM.
	assertOAuthFilesExclude(t, database.Path(), verifier, redirect)
}

// TestDevinCallbackConsumeVsCancelConcurrentRace races a Consume (the
// callback winner) against a Cancel (a concurrent admin cancel) on the same
// pending Devin session. Exactly one of the two wins; the loser receives
// ErrOAuthTerminalConflict. If Consume wins the row is consumed and
// secret-free; if Cancel wins the row is cancelled and secret-free and the
// late Consume conflicts. In neither outcome does the verifier leak or get
// exchanged twice. The test runs multiple iterations to exercise both
// interleavings.
func TestDevinCallbackConsumeVsCancelConcurrentRace(t *testing.T) {
	ctx := context.Background()
	const iterations = 20
	for i := range iterations {
		database, _, repo, now := newConflictMatrixStore(t)
		state := fmt.Sprintf("consume-cancel-race-%d", i)
		verifier := fmt.Sprintf("verifier-secret-%d", i)
		session := OAuthSession{
			Provider:  provider.Devin,
			FlowType:  OAuthFlowCallbackPKCE,
			State:     state,
			SessionID: "sess-" + state,
			Pending:   &OAuthPendingPayload{Verifier: verifier, RedirectURI: "https://byos.example.test/cb", ExpiresAt: now.Add(time.Hour)},
			ExpiresAt: now.Add(time.Hour),
		}
		if err := repo.Create(ctx, session); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		type result struct {
			consumed   OAuthPendingPayload
			consumeErr error
			cancelErr  error
		}
		res := make(chan result, 1)
		var consumeErr error
		var cancelErr error
		var consumed OAuthPendingPayload
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			consumed, consumeErr = repo.Consume(ctx, provider.Devin, OAuthFlowCallbackPKCE, state, now)
		}()
		go func() {
			defer wg.Done()
			<-start
			cancelErr = repo.Cancel(ctx, provider.Devin, OAuthFlowCallbackPKCE, state, "concurrent cancel", now)
		}()
		close(start)
		wg.Wait()
		res <- result{consumed, consumeErr, cancelErr}

		// Exactly one of consume/cancel must succeed.
		consumeWon := consumeErr == nil
		cancelWon := cancelErr == nil
		if consumeWon && cancelWon {
			t.Fatalf("iteration %d: both consume and cancel succeeded", i)
		}
		if !consumeWon && !cancelWon {
			t.Fatalf("iteration %d: both consume and cancel failed: consume=%v cancel=%v", i, consumeErr, cancelErr)
		}
		if consumeWon {
			if consumed.Verifier != verifier {
				t.Fatalf("iteration %d: winner verifier = %q, want %q", i, consumed.Verifier, verifier)
			}
			if !errors.Is(cancelErr, ErrOAuthTerminalConflict) {
				t.Fatalf("iteration %d: losing cancel error = %v, want ErrOAuthTerminalConflict", i, cancelErr)
			}
		} else {
			if !errors.Is(consumeErr, ErrOAuthTerminalConflict) {
				t.Fatalf("iteration %d: losing consume error = %v, want ErrOAuthTerminalConflict", i, consumeErr)
			}
		}

		// The row is terminal and secret-free regardless of winner.
		stored, err := repo.Get(ctx, provider.Devin, OAuthFlowCallbackPKCE, state)
		if err != nil {
			t.Fatalf("iteration %d: lookup error = %v", i, err)
		}
		if stored.Status != "consumed" && stored.Status != "cancelled" {
			t.Fatalf("iteration %d: post-race status = %q, want consumed or cancelled", i, stored.Status)
		}
		if stored.Pending != nil {
			t.Fatalf("iteration %d: post-race Pending must be nil, got %+v", i, stored.Pending)
		}
		// No second exchange: a follow-up Consume must conflict.
		if _, err := repo.Consume(ctx, provider.Devin, OAuthFlowCallbackPKCE, state, now); !errors.Is(err, ErrOAuthTerminalConflict) {
			t.Fatalf("iteration %d: post-race consume error = %v, want ErrOAuthTerminalConflict", i, err)
		}
		// No verifier leak in the database files.
		assertOAuthFilesExclude(t, database.Path(), verifier)
	}
}

// TestDevinCallbackConsumeRaceNoSecretLeak is a focused single-secret
// evidence: under high concurrency, the verifier is returned to exactly one
// caller and never appears in the persisted database file, WAL, or SHM.
func TestDevinCallbackConsumeRaceNoSecretLeak(t *testing.T) {
	ctx := context.Background()
	database, _, repo, now := newConflictMatrixStore(t)
	const state = "no-leak-race-state"
	const verifier = "no-leak-verifier-secret"
	session := OAuthSession{
		Provider:  provider.Devin,
		FlowType:  OAuthFlowCallbackPKCE,
		State:     state,
		SessionID: "sess-no-leak",
		Pending:   &OAuthPendingPayload{Verifier: verifier, RedirectURI: "https://byos.example.test/cb", ExpiresAt: now.Add(time.Hour)},
		ExpiresAt: now.Add(time.Hour),
	}
	if err := repo.Create(ctx, session); err != nil {
		t.Fatal(err)
	}
	const attempts = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	var winners atomic.Int32
	results := make(chan OAuthPendingPayload, attempts)
	errs := make(chan error, attempts)
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			payload, err := repo.Consume(ctx, provider.Devin, OAuthFlowCallbackPKCE, state, now)
			if err != nil {
				errs <- err
				return
			}
			winners.Add(1)
			results <- payload
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	if winners.Load() != 1 {
		t.Fatalf("winners = %d, want 1", winners.Load())
	}
	for err := range errs {
		if !errors.Is(err, ErrOAuthTerminalConflict) {
			t.Fatalf("loser error = %v, want ErrOAuthTerminalConflict", err)
		}
	}
	for payload := range results {
		if payload.Verifier != verifier {
			t.Fatalf("winner verifier = %q, want %q", payload.Verifier, verifier)
		}
	}
	assertOAuthFilesExclude(t, database.Path(), verifier)
}
