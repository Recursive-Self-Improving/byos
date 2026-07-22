package routing

import (
	"bytes"
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	appcrypto "byos/internal/crypto"
	"byos/internal/provider"
	"byos/internal/store"
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
	account, err := accounts.UpsertLogin(ctx, store.Account{Provider: provider.XAI, Credentials: store.AccountCredentials{Issuer: "https://auth.x.ai", Subject: "cooldown", AccessToken: "token", TokenEndpoint: "https://auth.x.ai/token"}})
	if err != nil {
		t.Fatal(err)
	}
	states := store.NewCooldownRepository(database.DB)
	manager := NewCooldownManager(states, accounts)
	generic := provider.ErrorClassification{Class: provider.ClassRateLimit, CooldownScope: provider.CooldownModel}
	if err := manager.Apply(ctx, account.ID, "model-a", generic); err != nil {
		t.Fatal(err)
	}
	first, err := states.Get(ctx, account.ID, "model-a", time.Now().UTC())
	if err != nil || first.BackoffLevel != 1 || first.Until == nil || first.LastErrorAt == nil || first.Until.Sub(*first.LastErrorAt) != time.Minute {
		t.Fatalf("first=%+v %v", first, err)
	}
	firstUntil := *first.Until
	for range 6 {
		if err := manager.Apply(ctx, account.ID, "model-a", generic); err != nil {
			t.Fatal(err)
		}
		state, err := states.Get(ctx, account.ID, "model-a", time.Now().UTC())
		if err != nil || state.BackoffLevel != 1 || state.Until == nil || !state.Until.Equal(firstUntil) {
			t.Fatalf("active cooldown escalated: first=%+v current=%+v err=%v", first, state, err)
		}
	}
	// Once the active window expires, preserve its backoff level so a new
	// provider 429 advances the ladder. Concurrent failures inside the window
	// must never advance it.
	latest, _ := states.Get(ctx, account.ID, "model-a", time.Now().UTC())
	if _, err := database.DB.ExecContext(ctx, `UPDATE account_model_states SET cooldown_until=? WHERE account_id=? AND model=?`, latest.LastErrorAt.Unix()-1, account.ID, "model-a"); err != nil {
		t.Fatalf("force expiry: %v", err)
	}
	expired, err := states.Get(ctx, account.ID, "model-a", time.Now().UTC())
	if err != nil || expired.Until != nil || expired.BackoffLevel != 1 {
		t.Fatalf("expired cooldown=%+v err=%v", expired, err)
	}
	if err := manager.Apply(ctx, account.ID, "model-a", generic); err != nil {
		t.Fatal(err)
	}
	second, err := states.Get(ctx, account.ID, "model-a", time.Now().UTC())
	if err != nil || second.BackoffLevel != 2 || second.Until == nil || second.LastErrorAt == nil || second.Until.Sub(*second.LastErrorAt) != 2*time.Minute {
		t.Fatalf("second=%+v err=%v", second, err)
	}
	explicit := provider.ErrorClassification{Class: provider.ClassRateLimit, CooldownScope: provider.CooldownModel, Cooldown: 10 * time.Minute, ExplicitRetryAfter: true}
	if err := manager.Apply(ctx, account.ID, "model-b", explicit); err != nil {
		t.Fatal(err)
	}
	modelB, _ := states.Get(ctx, account.ID, "model-b", time.Now().UTC())
	if modelB.Until == nil || modelB.LastErrorAt == nil || modelB.Until.Sub(*modelB.LastErrorAt) != 10*time.Minute {
		t.Fatalf("model-b=%+v", modelB)
	}
	accountWide := provider.ErrorClassification{Class: provider.ClassTransient, CooldownScope: provider.CooldownAccount, Cooldown: time.Minute}
	if err := manager.Apply(ctx, account.ID, "model-a", accountWide); err != nil {
		t.Fatal(err)
	}
	global, err := states.Get(ctx, account.ID, "*", time.Now().UTC())
	if err != nil || global.Until == nil {
		t.Fatalf("global cooldown = %+v, %v", global, err)
	}
	zeroRetry := provider.ErrorClassification{Class: provider.ClassRateLimit, CooldownScope: provider.CooldownModel, ExplicitRetryAfter: true}
	if err := manager.Apply(ctx, account.ID, "zero", zeroRetry); err != nil {
		t.Fatal(err)
	}
	if _, err := states.Get(ctx, account.ID, "zero", time.Now().UTC()); err != sql.ErrNoRows {
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
	concurrent, err := states.Get(ctx, account.ID, "concurrent", time.Now().UTC())
	if err != nil || concurrent.BackoffLevel != 1 || concurrent.Until == nil || concurrent.LastErrorAt == nil || concurrent.Until.Sub(time.Now().UTC()) <= 0 || concurrent.Until.Sub(time.Now().UTC()) > time.Minute {
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
	restored, err := states.Get(ctx, account.ID, "model-b", time.Now().UTC())
	if err != nil || restored.Until == nil {
		t.Fatalf("restored=%+v %v", restored, err)
	}
	manager = NewCooldownManager(states, store.NewAccountRepository(database.DB, keys))
	if err := manager.Success(ctx, account.ID, "model-b"); err != nil {
		t.Fatal(err)
	}
	ready, err := states.Get(ctx, account.ID, "model-b", time.Now().UTC())
	if err != nil || ready.Until != nil || ready.BackoffLevel != 0 {
		t.Fatalf("ready=%+v %v", ready, err)
	}
	if ready.LastErrorClass != modelB.LastErrorClass || ready.LastErrorAt == nil || !ready.LastErrorAt.Equal(*modelB.LastErrorAt) {
		t.Fatalf("success erased error audit: before=%+v after=%+v", modelB, ready)
	}
	if err := manager.Apply(ctx, account.ID, "model-a", provider.ErrorClassification{Class: provider.ClassInvalidGrant, DisableAccount: true, ReloginRequired: true, CooldownScope: provider.CooldownAccount}); err != nil {
		t.Fatal(err)
	}
	disabled, err := manager.accounts.Get(ctx, account.ID)
	if err != nil || disabled.Enabled {
		t.Fatalf("disabled=%+v %v", disabled, err)
	}
}
func TestCooldownApplyReloginRequired(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	database, err := store.Open(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, _ := appcrypto.DeriveKeys(bytes.Repeat([]byte{15}, 32))
	accounts := store.NewAccountRepository(database.DB, keys)
	account, err := accounts.UpsertLogin(ctx, store.Account{Provider: provider.XAI, Credentials: store.AccountCredentials{Issuer: "https://auth.x.ai", Subject: "relogin", AccessToken: "token", TokenEndpoint: "https://auth.x.ai/token"}})
	if err != nil {
		t.Fatal(err)
	}
	states := store.NewCooldownRepository(database.DB)
	manager := NewCooldownManager(states, accounts)
	classification := provider.ErrorClassification{Class: provider.ClassInvalidGrant, ReloginRequired: true, DisableAccount: true, CooldownScope: provider.CooldownAccount, Cooldown: time.Minute}
	if err := manager.Apply(ctx, account.ID, "model-a", classification); err != nil {
		t.Fatalf("Apply relogin: %v", err)
	}
	marked, err := accounts.Get(ctx, account.ID)
	if err != nil {
		t.Fatalf("get marked account: %v", err)
	}
	if marked.Enabled {
		t.Fatalf("relogin did not disable account: %+v", marked)
	}
	if marked.Status != "relogin_required" {
		t.Fatalf("status=%q want relogin_required", marked.Status)
	}
	if marked.LastError != "authentication expired; reconnect required" {
		t.Fatalf("last_error=%q want sanitized relogin message", marked.LastError)
	}
	if _, err := states.Get(ctx, account.ID, "model-a", time.Now().UTC()); err != sql.ErrNoRows {
		t.Fatalf("relogin persisted cooldown row: %v", err)
	}
	if _, err := states.Get(ctx, account.ID, "*", time.Now().UTC()); err != sql.ErrNoRows {
		t.Fatalf("relogin persisted account-wide cooldown row: %v", err)
	}
}
