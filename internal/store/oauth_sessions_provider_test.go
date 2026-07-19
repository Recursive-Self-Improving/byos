package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	appcrypto "byos/internal/crypto"
	"byos/internal/provider"
)

func TestOAuthProviderFlowIsolationAndRestartDispatch(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	db, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	repo := NewOAuthSessionRepository(db.DB, keys)
	deviceState := "raw-device-state-not-durable"
	callbackState := "raw-callback-state-not-durable"
	if err := repo.Create(ctx, OAuthSession{Provider: provider.XAI, FlowType: OAuthFlowDevice, State: deviceState, DeviceCode: "device-secret", UserCode: "DEVICE-CODE", TokenEndpoint: "https://auth.x.ai/token", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, OAuthSession{Provider: provider.Devin, FlowType: OAuthFlowCallbackPKCE, State: callbackState, Pending: &OAuthPendingPayload{Verifier: "restart-verifier-secret", RedirectURI: "https://localhost/callback/restart-secret", ExpiresAt: now.Add(time.Hour)}, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []struct {
		kind provider.Kind
		flow OAuthFlowType
	}{{provider.Devin, OAuthFlowDevice}, {provider.XAI, OAuthFlowCallbackPKCE}, {provider.Devin, OAuthFlowCallbackPKCE}} {
		if _, err := repo.Get(ctx, wrong.kind, wrong.flow, deviceState); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("wrong key Get(%s,%s) = %v", wrong.kind, wrong.flow, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo = NewOAuthSessionRepository(db.DB, keys)
	devices, err := repo.ListResumable(ctx, provider.XAI, OAuthFlowDevice, now)
	if err != nil || len(devices) != 1 || devices[0].Provider != provider.XAI || devices[0].FlowType != OAuthFlowDevice || devices[0].State != deviceState {
		t.Fatalf("device restart dispatch = %+v, %v", devices, err)
	}
	callbacks, err := repo.ListResumable(ctx, provider.Devin, OAuthFlowCallbackPKCE, now)
	if err != nil || len(callbacks) != 1 || callbacks[0].Provider != provider.Devin || callbacks[0].FlowType != OAuthFlowCallbackPKCE || callbacks[0].Pending == nil || callbacks[0].State != "" {
		t.Fatalf("callback restart dispatch = %+v, %v", callbacks, err)
	}
	if values, err := repo.ListResumable(ctx, provider.Devin, OAuthFlowDevice, now); err != nil || len(values) != 0 {
		t.Fatalf("cross-provider resumable rows = %+v, %v", values, err)
	}
}

func TestOAuthCallbackConsumeIsAtomicSecretDisposingAndRecoverable(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{72}, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	db, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	repo := NewOAuthSessionRepository(db.DB, keys)
	state := "callback-consume-raw-state"
	verifier := "pkce-verifier-returned-once"
	redirect := "https://localhost/callback/pending-only"
	if err := repo.Create(ctx, OAuthSession{Provider: provider.Devin, FlowType: OAuthFlowCallbackPKCE, State: state, Pending: &OAuthPendingPayload{Verifier: verifier, RedirectURI: redirect, ExpiresAt: now.Add(time.Hour)}, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	beforeEnvelope, beforeStatus, beforeUpdated := oauthStoredRow(t, db.DB, state)
	if _, err := repo.Consume(ctx, provider.XAI, OAuthFlowCallbackPKCE, state, now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("wrong-provider consume = %v", err)
	}
	if _, err := repo.Consume(ctx, provider.Devin, OAuthFlowDevice, state, now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("wrong-flow consume = %v", err)
	}
	afterEnvelope, afterStatus, afterUpdated := oauthStoredRow(t, db.DB, state)
	if beforeEnvelope != afterEnvelope || beforeStatus != afterStatus || beforeUpdated != afterUpdated {
		t.Fatal("wrong-key consume mutated row")
	}

	const attempts = 12
	start := make(chan struct{})
	results := make(chan OAuthPendingPayload, attempts)
	errs := make(chan error, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			value, err := repo.Consume(ctx, provider.Devin, OAuthFlowCallbackPKCE, state, now)
			if err != nil {
				errs <- err
				return
			}
			results <- value
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	if len(results) != 1 {
		t.Fatalf("successful consumes = %d, want 1", len(results))
	}
	consumedPayload := <-results
	if consumedPayload.Verifier != verifier || consumedPayload.RedirectURI != redirect {
		t.Fatalf("consume payload = %+v", consumedPayload)
	}
	consumed, err := repo.Get(ctx, provider.Devin, OAuthFlowCallbackPKCE, state)
	if err != nil {
		t.Fatal(err)
	}
	if consumed.Status != "consumed" || consumed.Pending != nil {
		t.Fatalf("persisted consumed session = %+v", consumed)
	}
	if _, err := repo.Consume(ctx, provider.Devin, OAuthFlowCallbackPKCE, state, now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("consume replay = %v", err)
	}
	if err := repo.Cancel(ctx, provider.Devin, OAuthFlowCallbackPKCE, state, "cancel", now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("consumed cancellation = %v", err)
	}
	if err := repo.Expire(ctx, provider.Devin, OAuthFlowCallbackPKCE, state, "expired", now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("consumed expiry = %v", err)
	}
	_, stored, _ := oauthStoredRow(t, db.DB, state)
	if stored != "consumed" {
		t.Fatalf("status after rejected consumed mutations = %q", stored)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo = NewOAuthSessionRepository(db.DB, keys)
	values, err := repo.ListResumable(ctx, provider.Devin, OAuthFlowCallbackPKCE, now)
	if err != nil || len(values) != 1 || values[0].Status != "consumed" || values[0].State != "" || len(values[0].StateHash) != 32 {
		t.Fatalf("consumed restart recovery dispatch = %+v, %v", values, err)
	}
	if err := repo.FailConsumedByHash(ctx, provider.Devin, OAuthFlowCallbackPKCE, values[0].StateHash, "interrupted exchange", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	failed, err := repo.Get(ctx, provider.Devin, OAuthFlowCallbackPKCE, state)
	if err != nil || failed.Status != "failed" || failed.Pending != nil {
		t.Fatalf("restart finalization = %+v, %v", failed, err)
	}
	for _, mutate := range []func() error{
		func() error {
			_, err := repo.Consume(ctx, provider.Devin, OAuthFlowCallbackPKCE, state, now)
			return err
		},
		func() error { return repo.Fail(ctx, provider.Devin, OAuthFlowCallbackPKCE, state, "again", now) },
		func() error { return repo.Complete(ctx, provider.Devin, OAuthFlowCallbackPKCE, state, "acct", now) },
		func() error { return repo.Cancel(ctx, provider.Devin, OAuthFlowCallbackPKCE, state, "again", now) },
		func() error { return repo.Expire(ctx, provider.Devin, OAuthFlowCallbackPKCE, state, "again", now) },
	} {
		if err := mutate(); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("terminal mutation = %v", err)
		}
	}
}

func TestOAuthPayloadPlaintextAbsenceAcrossDatabaseWALAndSHM(t *testing.T) {
	ctx := context.Background()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{73}, 32))
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewOAuthSessionRepository(db.DB, keys)
	now := time.Now().UTC().Truncate(time.Second)
	state := "RAW-STATE-SENTINEL-7f37b193"
	verifier := "DURABLE-VERIFIER-SENTINEL-c9182e41"
	redirect := "https://localhost/DURABLE-REDIRECT-SENTINEL-a83d11be"
	callbackCode := "NEVER-WRITTEN-CALLBACK-CODE-489ee3c0"
	userJWT := "NEVER.WRITTEN.USER-JWT-1b73f2f9"
	if err := repo.Create(ctx, OAuthSession{Provider: provider.Devin, FlowType: OAuthFlowCallbackPKCE, State: state, Pending: &OAuthPendingPayload{Verifier: verifier, RedirectURI: redirect, ExpiresAt: now.Add(time.Hour)}, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	assertOAuthFilesExclude(t, db.Path(), state, verifier, redirect, callbackCode, userJWT)

	returned, err := repo.Consume(ctx, provider.Devin, OAuthFlowCallbackPKCE, state, now)
	if err != nil || returned.Verifier != verifier || returned.RedirectURI != redirect {
		t.Fatalf("consume = %+v, %v", returned, err)
	}
	envelope, status, _ := oauthStoredRow(t, db.DB, state)
	if status != "consumed" {
		t.Fatalf("stored status = %q", status)
	}
	plain, err := appcrypto.Decrypt(keys.OAuth(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(plain, []byte(verifier)) || bytes.Contains(plain, []byte(redirect)) {
		t.Fatalf("consumed envelope retains pending secret: %s", plain)
	}
	assertOAuthFilesExclude(t, db.Path(), state, verifier, redirect, callbackCode, userJWT)
	if err := db.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	assertOAuthFilesExclude(t, db.Path(), state, verifier, redirect, callbackCode, userJWT)

	wrongKeys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{74}, 32))
	if err != nil {
		t.Fatal(err)
	}
	wrongRepo := NewOAuthSessionRepository(db.DB, wrongKeys)
	if value, err := wrongRepo.Get(ctx, provider.Devin, OAuthFlowCallbackPKCE, state); err == nil || value.Provider.Valid() || value.Status != "" || value.Pending != nil {
		t.Fatalf("wrong-key read returned partial session %+v, %v", value, err)
	}
}

func TestOAuthLegacyDevicePayloadSurvivesMigrationAndReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{75}, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	type legacyOAuthSessionFixture struct {
		State                   string
		DeviceCode              string
		UserCode                string
		VerificationURI         string
		VerificationURIComplete string
		TokenEndpoint           string
		AccountID               string
		PollInterval            time.Duration
		ExpiresAt               time.Time
		Status                  string
		SanitizedError          string
		Authorization           *OAuthAuthorization
		CreatedAt               time.Time
		UpdatedAt               time.Time
	}
	legacy := []legacyOAuthSessionFixture{
		{State: "legacy-pending-state", DeviceCode: "legacy-device", UserCode: "LEGACY-CODE", VerificationURI: "https://x.ai/device", VerificationURIComplete: "https://x.ai/device?code=LEGACY-CODE", TokenEndpoint: "https://auth.x.ai/token", AccountID: "pending-account"},
		{State: "legacy-authorized-state", DeviceCode: "authorized-device", UserCode: "AUTHORIZED-CODE", VerificationURI: "https://x.ai/device", VerificationURIComplete: "https://x.ai/device?code=AUTHORIZED-CODE", TokenEndpoint: "https://auth.x.ai/token", AccountID: "authorized-account", Authorization: &OAuthAuthorization{AccessToken: "access-secret", RefreshToken: "refresh-secret", IDToken: "id-secret", TokenType: "Bearer", ExpiresIn: 3600, AuthorizedAt: now, ExpiresAt: now.Add(time.Hour)}},
	}
	path := filepath.Join(dir, databaseFilename)
	rawDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, rawDB, migrationFS(t, 4)); err != nil {
		t.Fatal(err)
	}
	envelopes := make([]string, len(legacy))
	for i, value := range legacy {
		plain, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		envelopes[i], err = appcrypto.Encrypt(keys.OAuth(), plain)
		if err != nil {
			t.Fatal(err)
		}
		status := "pending"
		if i == 1 {
			status = "authorized"
		}
		hash := stateHash(value.State)
		if _, err := rawDB.ExecContext(ctx, `INSERT INTO oauth_sessions(state_hash,payload_encrypted,status,poll_interval_seconds,expires_at,created_at,updated_at,sanitized_error) VALUES(?,?,?,?,?,?,?,NULL)`, hash[:], envelopes[i], status, 17, now.Add(time.Hour).Unix(), now.Unix(), now.Unix()); err != nil {
			t.Fatal(err)
		}
	}
	if err := rawDB.Close(); err != nil {
		t.Fatal(err)
	}
	migrated, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	for i, value := range legacy {
		hash := stateHash(value.State)
		var envelope string
		if err := migrated.DB.QueryRowContext(ctx, `SELECT payload_encrypted FROM oauth_sessions WHERE state_hash=?`, hash[:]).Scan(&envelope); err != nil || envelope != envelopes[i] {
			t.Fatalf("migration rewrote legacy ciphertext %d: %v", i, err)
		}
	}
	if err := migrated.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	repo := NewOAuthSessionRepository(reopened.DB, keys)
	for i, want := range legacy {
		got, err := repo.GetResumable(ctx, provider.XAI, OAuthFlowDevice, want.State, now)
		if err != nil {
			t.Fatal(err)
		}
		wantStatus := "pending"
		if i == 1 {
			wantStatus = "authorized"
		}
		if got.Status != wantStatus || got.State != want.State || got.DeviceCode != want.DeviceCode || got.UserCode != want.UserCode || got.VerificationURI != want.VerificationURI || got.VerificationURIComplete != want.VerificationURIComplete || got.TokenEndpoint != want.TokenEndpoint || got.AccountID != want.AccountID || got.PollInterval != 17*time.Second {
			t.Fatalf("legacy session %d = %+v", i, got)
		}
		if i == 1 && (got.Authorization == nil || *got.Authorization != *want.Authorization) {
			t.Fatalf("legacy authorization = %+v", got.Authorization)
		}
	}
	malformedJSON, err := appcrypto.Encrypt(keys.OAuth(), []byte(`{"State":`))
	if err != nil {
		t.Fatal(err)
	}
	tampered := envelopes[0]
	tamperAt := len(tampered) / 2
	replacement := byte('A')
	if tampered[tamperAt] == replacement {
		replacement = 'B'
	}
	tampered = tampered[:tamperAt] + string(replacement) + tampered[tamperAt+1:]
	for _, failure := range []struct {
		state, envelope string
	}{
		{state: "authenticated-malformed-json", envelope: malformedJSON},
		{state: "malformed-envelope", envelope: "not-an-encrypted-envelope"},
		{state: "tampered-ciphertext", envelope: tampered},
	} {
		hash := stateHash(failure.state)
		if _, err := reopened.DB.ExecContext(ctx, `INSERT INTO oauth_sessions(state_hash,provider,flow_type,payload_encrypted,status,poll_interval_seconds,expires_at,created_at,updated_at,sanitized_error) VALUES(?,?,?,?,?,?,?,?,?,NULL)`, hash[:], provider.XAI, OAuthFlowDevice, failure.envelope, "pending", 5, now.Add(time.Hour).Unix(), now.Unix(), now.Unix()); err != nil {
			t.Fatal(err)
		}
		got, err := repo.Get(ctx, provider.XAI, OAuthFlowDevice, failure.state)
		if err == nil || !reflect.DeepEqual(got, OAuthSession{}) {
			t.Fatalf("invalid legacy payload returned %+v, %v", got, err)
		}
	}
	wrongKeys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{76}, 32))
	if err != nil {
		t.Fatal(err)
	}
	wrongRepo := NewOAuthSessionRepository(reopened.DB, wrongKeys)
	got, err := wrongRepo.Get(ctx, provider.XAI, OAuthFlowDevice, legacy[0].State)
	if err == nil || !reflect.DeepEqual(got, OAuthSession{}) {
		t.Fatalf("wrong-key legacy payload returned %+v, %v", got, err)
	}
}

func TestOAuthEncryptedPayloadCanonicalPrecedenceAndLegacyScope(t *testing.T) {
	for _, test := range []struct {
		name  string
		input string
		want  string
	}{
		{name: "canonical scalar empty shadows legacy", input: `{"state":"","State":"legacy"}`, want: ""},
		{name: "canonical scalar null shadows legacy", input: `{"state":null,"State":"legacy"}`, want: ""},
		{name: "legacy scalar empty", input: `{"State":""}`, want: ""},
		{name: "legacy scalar null", input: `{"State":null}`, want: ""},
		{name: "legacy scalar value", input: `{"State":"legacy"}`, want: "legacy"},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload, err := decodeOAuthEncryptedPayload([]byte(test.input), true)
			if err != nil {
				t.Fatal(err)
			}
			if payload.State != test.want {
				t.Fatalf("state = %q, want %q", payload.State, test.want)
			}
		})
	}

	for _, test := range []struct {
		name    string
		input   string
		wantNil bool
		want    string
	}{
		{name: "canonical pointer null shadows legacy", input: `{"authorization":null,"Authorization":{"access_token":"legacy"}}`, wantNil: true},
		{name: "canonical pointer empty shadows legacy", input: `{"authorization":{},"Authorization":{"access_token":"legacy"}}`, want: ""},
		{name: "legacy pointer null", input: `{"Authorization":null}`, wantNil: true},
		{name: "legacy pointer value", input: `{"Authorization":{"access_token":"legacy"}}`, want: "legacy"},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload, err := decodeOAuthEncryptedPayload([]byte(test.input), true)
			if err != nil {
				t.Fatal(err)
			}
			if test.wantNil {
				if payload.Authorization != nil {
					t.Fatalf("authorization = %+v, want nil", payload.Authorization)
				}
				return
			}
			if payload.Authorization == nil || payload.Authorization.AccessToken != test.want {
				t.Fatalf("authorization = %+v, want access token %q", payload.Authorization, test.want)
			}
		})
	}

	legacyAuthorization, err := decodeOAuthEncryptedPayload([]byte(`{"Authorization":{"AccessToken":"legacy-access","RefreshToken":"legacy-refresh","IDToken":"legacy-id","TokenType":"Bearer","ExpiresIn":3600,"AuthorizedAt":"2025-01-02T03:04:05Z","ExpiresAt":"2025-01-02T04:04:05Z"}}`), true)
	if err != nil {
		t.Fatal(err)
	}
	legacyAuthorizedAt := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	if legacyAuthorization.Authorization == nil || *legacyAuthorization.Authorization != (OAuthAuthorization{AccessToken: "legacy-access", RefreshToken: "legacy-refresh", IDToken: "legacy-id", TokenType: "Bearer", ExpiresIn: 3600, AuthorizedAt: legacyAuthorizedAt, ExpiresAt: legacyAuthorizedAt.Add(time.Hour)}) {
		t.Fatalf("legacy nested authorization = %+v", legacyAuthorization.Authorization)
	}

	canonicalAuthorization, err := decodeOAuthEncryptedPayload([]byte(`{"authorization":{"access_token":"canonical","AccessToken":"legacy","refresh_token":"canonical-refresh","RefreshToken":{}},"Authorization":{"AccessToken":{}}}`), true)
	if err != nil {
		t.Fatal(err)
	}
	if canonicalAuthorization.Authorization == nil || canonicalAuthorization.Authorization.AccessToken != "canonical" || canonicalAuthorization.Authorization.RefreshToken != "canonical-refresh" {
		t.Fatalf("canonical nested authorization precedence = %+v", canonicalAuthorization.Authorization)
	}

	nestedNonExact, err := decodeOAuthEncryptedPayload([]byte(`{"authorization":{"AccessToken":"wrong","accesstoken":"wrong","Access_Token":"wrong"},"AUTHORIZATION":{"AccessToken":"wrong"}}`), true)
	if err != nil {
		t.Fatal(err)
	}
	if nestedNonExact.Authorization == nil || nestedNonExact.Authorization.AccessToken != "" {
		t.Fatalf("non-exact nested authorization keys were accepted = %+v", nestedNonExact.Authorization)
	}

	if _, err := decodeOAuthEncryptedPayload([]byte(`{"Authorization":{"access_token":"canonical","AccessToken":{}}}`), true); err != nil {
		t.Fatalf("shadowed malformed nested legacy alias was decoded: %v", err)
	}
	if _, err := decodeOAuthEncryptedPayload([]byte(`{"Authorization":{"AccessToken":{}}}`), true); err == nil {
		t.Fatal("malformed unshadowed nested legacy alias was accepted")
	}

	for _, test := range []struct {
		name  string
		input string
	}{
		{name: "malformed scalar alias shadowed", input: `{"state":"canonical","State":{}}`},
		{name: "malformed pointer alias shadowed", input: `{"authorization":null,"Authorization":"malformed"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeOAuthEncryptedPayload([]byte(test.input), true); err != nil {
				t.Fatalf("shadowed legacy alias was decoded: %v", err)
			}
		})
	}

	for _, input := range []string{`{"State":{}}`, `{"Authorization":"malformed"}`} {
		if _, err := decodeOAuthEncryptedPayload([]byte(input), true); err == nil {
			t.Fatalf("malformed unshadowed legacy alias was accepted: %s", input)
		}
	}

	device, err := decodeOAuthEncryptedPayload([]byte(`{"State":"raw-device-state","DeviceCode":"device-secret","UserCode":"USER","VerificationURI":"https://example/device","VerificationURIComplete":"https://example/device?code=USER","TokenEndpoint":"https://example/token","AccountID":"account"}`), true)
	if err != nil {
		t.Fatal(err)
	}
	if device.State != "raw-device-state" || device.DeviceCode != "device-secret" || device.UserCode != "USER" || device.VerificationURI != "https://example/device" || device.VerificationURIComplete != "https://example/device?code=USER" || device.TokenEndpoint != "https://example/token" || device.AccountID != "account" {
		t.Fatalf("legacy xAI device payload not restored = %+v", device)
	}

	nonExact, err := decodeOAuthEncryptedPayload([]byte(`{"STATE":"wrong","deviceCode":"wrong","Usercode":"wrong","VerificationUri":"wrong","verificationURIComplete":"wrong","tokenEndpoint":"wrong","authorization":{"access_token":"canonical"},"AUTHORIZATION":{"access_token":"wrong"},"accountID":"wrong","Pending":{"Verifier":"legacy-verifier"}}`), true)
	if err != nil {
		t.Fatal(err)
	}
	if nonExact.State != "" || nonExact.DeviceCode != "" || nonExact.UserCode != "" || nonExact.VerificationURI != "" || nonExact.VerificationURIComplete != "" || nonExact.TokenEndpoint != "" || nonExact.AccountID != "" || nonExact.Pending != nil || nonExact.Authorization == nil || nonExact.Authorization.AccessToken != "canonical" {
		t.Fatalf("non-exact legacy aliases were accepted = %+v", nonExact)
	}

	canonicalPending, err := decodeOAuthEncryptedPayload([]byte(`{"pending":{"verifier":"canonical-verifier"},"Pending":{"Verifier":"legacy-verifier"}}`), true)
	if err != nil {
		t.Fatal(err)
	}
	if canonicalPending.Pending == nil || canonicalPending.Pending.Verifier != "canonical-verifier" {
		t.Fatalf("canonical pending payload = %+v", canonicalPending.Pending)
	}

	callback, err := decodeOAuthEncryptedPayload([]byte(`{"state":"canonical-raw-callback-state","device_code":"canonical-device-secret","State":"legacy-raw-callback-state","DeviceCode":"legacy-device-secret","Pending":{"Verifier":"legacy-verifier-secret"},"pending":{"verifier":"canonical-verifier"}}`), false)
	if err != nil {
		t.Fatal(err)
	}
	if callback.State != "" || callback.DeviceCode != "" || callback.Pending == nil || callback.Pending.Verifier != "canonical-verifier" {
		t.Fatalf("callback payload scope = %+v", callback)
	}
}

func TestOAuthPendingPayloadCanonicalWireAndExactDecode(t *testing.T) {
	ctx := context.Background()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{79}, 32))
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewOAuthSessionRepository(db.DB, keys)
	now := time.Date(2026, 7, 19, 12, 34, 56, 789000000, time.UTC)
	state := "pending-canonical-wire"
	want := OAuthPendingPayload{Verifier: "canonical-verifier", RedirectURI: "https://localhost/callback", ExpiresAt: now.Add(time.Hour)}
	if err := repo.Create(ctx, OAuthSession{Provider: provider.Devin, FlowType: OAuthFlowCallbackPKCE, State: state, Pending: &want, ExpiresAt: want.ExpiresAt}); err != nil {
		t.Fatal(err)
	}
	envelope, _, _ := oauthStoredRow(t, db.DB, state)
	plain, err := appcrypto.Decrypt(keys.OAuth(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(plain, &outer); err != nil {
		t.Fatal(err)
	}
	var pending map[string]json.RawMessage
	if err := json.Unmarshal(outer["pending"], &pending); err != nil {
		t.Fatal(err)
	}
	if got := reflect.ValueOf(pending).MapKeys(); len(got) != 3 {
		t.Fatalf("pending wire keys = %v; plaintext = %s", got, plain)
	}
	for _, key := range []string{"verifier", "redirect_uri", "expires_at"} {
		if _, ok := pending[key]; !ok {
			t.Fatalf("pending wire missing %q: %s", key, plain)
		}
	}

	decoded, err := decodeOAuthEncryptedPayload([]byte(`{"pending":{"verifier":"v","redirect_uri":"https://example/callback","expires_at":"2026-07-19T13:34:56.789Z"}}`), false)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Pending == nil || decoded.Pending.Verifier != "v" || decoded.Pending.RedirectURI != "https://example/callback" || !decoded.Pending.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("decoded canonical pending = %+v", decoded.Pending)
	}

	nonExact, err := decodeOAuthEncryptedPayload([]byte(`{"pending":{"Verifier":"wrong","RedirectURI":"wrong","ExpiresAt":"malformed","redirectUri":"wrong","EXPIRES_AT":{}}}`), false)
	if err != nil {
		t.Fatalf("non-exact pending aliases were decoded: %v", err)
	}
	if nonExact.Pending == nil || *nonExact.Pending != (OAuthPendingPayload{}) {
		t.Fatalf("non-exact pending aliases were accepted: %+v", nonExact.Pending)
	}

	nulls, err := decodeOAuthEncryptedPayload([]byte(`{"pending":{"verifier":null,"redirect_uri":null,"expires_at":null}}`), false)
	if err != nil {
		t.Fatal(err)
	}
	if nulls.Pending == nil || *nulls.Pending != (OAuthPendingPayload{}) {
		t.Fatalf("canonical null semantics = %+v", nulls.Pending)
	}
	nullPending, err := decodeOAuthEncryptedPayload([]byte(`{"pending":null}`), false)
	if err != nil || nullPending.Pending != nil {
		t.Fatalf("null pending = %+v, %v", nullPending.Pending, err)
	}

	for _, input := range []string{
		`{"pending":{"verifier":{}}}`,
		`{"pending":{"redirect_uri":42}}`,
		`{"pending":{"expires_at":"not-a-time"}}`,
		`{"pending":[]}`,
	} {
		if _, err := decodeOAuthEncryptedPayload([]byte(input), false); err == nil {
			t.Fatalf("malformed canonical pending value accepted: %s", input)
		}
	}
}

func oauthStoredRow(t *testing.T, db *sql.DB, state string) (envelope, status string, updated int64) {
	t.Helper()
	hash := stateHash(state)
	if err := db.QueryRow(`SELECT payload_encrypted,status,updated_at FROM oauth_sessions WHERE state_hash=?`, hash[:]).Scan(&envelope, &status, &updated); err != nil {
		t.Fatal(err)
	}
	return envelope, status, updated
}

func assertOAuthFilesExclude(t *testing.T, databasePath string, secrets ...string) {
	t.Helper()
	for _, path := range []string{databasePath, databasePath + "-wal", databasePath + "-shm"} {
		contents, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range secrets {
			if bytes.Contains(contents, []byte(secret)) {
				t.Fatalf("%s contains forbidden OAuth secret %q", path, secret)
			}
		}
	}
}
