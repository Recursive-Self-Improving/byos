package routing

import (
	"bytes"
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	appcrypto "supergrok-api/internal/crypto"
	"supergrok-api/internal/store"
)

func TestCooldownProgressionIsolationRecoveryAndRestart(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	database, err := store.Open(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := appcrypto.DeriveKeys(bytes.Repeat([]byte{15}, 32))
	accounts := store.NewAccountRepository(database.DB, keys)
	account, err := accounts.UpsertLogin(ctx, store.Account{Credentials: store.AccountCredentials{Issuer: "https://auth.x.ai", Subject: "cooldown", AccessToken: "token", TokenEndpoint: "https://auth.x.ai/token"}})
	if err != nil {
		t.Fatal(err)
	}
	states := store.NewCooldownRepository(database.DB)
	manager := NewCooldownManager(states, accounts)
	now := time.Now().UTC().Truncate(time.Second)
	manager.now = func() time.Time { return now }
	generic := ClassifiedError{Class: ClassRateLimit}
	if err := manager.Apply(ctx, account.ID, "model-a", generic); err != nil {
		t.Fatal(err)
	}
	first, err := states.Get(ctx, account.ID, "model-a", now)
	if err != nil || first.BackoffLevel != 1 || first.Until.Sub(now) != time.Minute {
		t.Fatalf("first=%+v %v", first, err)
	}
	for level, minutes := range []time.Duration{2, 4, 8, 16, 30, 30} {
		if err := manager.Apply(ctx, account.ID, "model-a", generic); err != nil {
			t.Fatal(err)
		}
		state, err := states.Get(ctx, account.ID, "model-a", now)
		wantLevel := min(level+2, 6)
		if err != nil || state.BackoffLevel != wantLevel || state.Until.Sub(now) != minutes*time.Minute {
			t.Fatalf("backoff level %d = %+v, %v", wantLevel, state, err)
		}
	}
	latest, _ := states.Get(ctx, account.ID, "model-a", now)
	now = latest.Until.Add(time.Second)
	if err := manager.Apply(ctx, account.ID, "model-a", generic); err != nil {
		t.Fatal(err)
	}
	second, _ := states.Get(ctx, account.ID, "model-a", now)
	if second.BackoffLevel != 1 {
		t.Fatalf("expired backoff not reset: %+v", second)
	}
	explicit := ClassifiedError{Class: ClassRateLimit, Cooldown: 10 * time.Minute, ExplicitRetryAfter: true}
	if err := manager.Apply(ctx, account.ID, "model-b", explicit); err != nil {
		t.Fatal(err)
	}
	modelB, _ := states.Get(ctx, account.ID, "model-b", now)
	if modelB.Until.Sub(now) != 10*time.Minute {
		t.Fatalf("model-b=%+v", modelB)
	}
	accountWide := ClassifiedError{Class: ClassTransient, Cooldown: time.Minute, AccountWide: true}
	if err := manager.Apply(ctx, account.ID, "model-a", accountWide); err != nil {
		t.Fatal(err)
	}
	global, err := states.Get(ctx, account.ID, "*", now)
	if err != nil || global.Until == nil {
		t.Fatalf("global cooldown = %+v, %v", global, err)
	}
	zeroRetry := ClassifiedError{Class: ClassRateLimit, ExplicitRetryAfter: true}
	if err := manager.Apply(ctx, account.ID, "zero", zeroRetry); err != nil {
		t.Fatal(err)
	}
	if _, err := states.Get(ctx, account.ID, "zero", now); err != sql.ErrNoRows {
		t.Fatalf("Retry-After zero persisted cooldown: %v", err)
	}
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := manager.Apply(ctx, account.ID, "concurrent", generic); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	concurrent, err := states.Get(ctx, account.ID, "concurrent", now)
	if err != nil || concurrent.BackoffLevel != 6 || concurrent.Until.Sub(now) != 30*time.Minute {
		t.Fatalf("concurrent cooldown = %+v, %v", concurrent, err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	database, err = store.Open(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	states = store.NewCooldownRepository(database.DB)
	restored, err := states.Get(ctx, account.ID, "model-b", now)
	if err != nil || restored.Until == nil {
		t.Fatalf("restored=%+v %v", restored, err)
	}
	manager = NewCooldownManager(states, store.NewAccountRepository(database.DB, keys))
	manager.now = func() time.Time { return now }
	if err := manager.Success(ctx, account.ID, "model-b"); err != nil {
		t.Fatal(err)
	}
	ready, err := states.Get(ctx, account.ID, "model-b", now)
	if err != nil || ready.Until != nil || ready.BackoffLevel != 0 {
		t.Fatalf("ready=%+v %v", ready, err)
	}
	if ready.LastErrorClass != modelB.LastErrorClass || ready.LastErrorAt == nil || !ready.LastErrorAt.Equal(*modelB.LastErrorAt) {
		t.Fatalf("success erased error audit: before=%+v after=%+v", modelB, ready)
	}
	if err := manager.Apply(ctx, account.ID, "model-a", InvalidGrant("")); err != nil {
		t.Fatal(err)
	}
	disabled, err := manager.accounts.Get(ctx, account.ID)
	if err != nil || disabled.Enabled {
		t.Fatalf("disabled=%+v %v", disabled, err)
	}
}
