package accounts

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appcrypto "byos/internal/crypto"
	oauthxai "byos/internal/oauth/xai"
	"byos/internal/store"
)

type blockingIdentityVerifier struct {
	calls   atomic.Int32
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (v *blockingIdentityVerifier) Verify(context.Context, string) (oauthxai.Identity, error) {
	v.calls.Add(1)
	v.once.Do(func() { close(v.started) })
	<-v.release
	return oauthxai.Identity{Issuer: "https://auth.x.ai", Subject: "private-subject", Email: "private@example.com", Claims: map[string]any{"sub": "private-subject", "email": "private@example.com"}}, nil
}

func TestCompleteLoginSingleflightsAndPersistsAccountID(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{23}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accountRepository := store.NewAccountRepository(database.DB, keys)
	sessionRepository := store.NewOAuthSessionRepository(database.DB, keys)
	now := time.Now().UTC().Truncate(time.Second)
	state := "deduplicated-completion"
	if err := sessionRepository.Create(ctx, store.OAuthSession{State: state, DeviceCode: "device", UserCode: "CODE", TokenEndpoint: "https://auth.x.ai/token", PollInterval: 5 * time.Second, ExpiresAt: now.Add(10 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := sessionRepository.Authorize(ctx, state, store.OAuthAuthorization{AccessToken: "access", RefreshToken: "refresh", IDToken: "identity", TokenType: "Bearer", ExpiresIn: 3600, AuthorizedAt: now, ExpiresAt: now.Add(time.Hour)}, now); err != nil {
		t.Fatal(err)
	}
	oauthService := oauthxai.NewService(nil, nil, sessionRepository, oauthxai.Options{})
	identity := &blockingIdentityVerifier{started: make(chan struct{}), release: make(chan struct{})}
	service := NewService(accountRepository, oauthService, identity, nil, nil, nil)

	results := make(chan store.Account, 2)
	errors := make(chan error, 2)
	go func() {
		account, err := service.CompleteLogin(ctx, state)
		results <- account
		errors <- err
	}()
	<-identity.started
	go func() {
		account, err := service.CompleteLogin(ctx, state)
		results <- account
		errors <- err
	}()
	close(identity.release)

	first := <-results
	second := <-results
	if err := <-errors; err != nil {
		t.Fatal(err)
	}
	if err := <-errors; err != nil {
		t.Fatal(err)
	}
	if first.ID == "" || second.ID != first.ID || identity.calls.Load() != 1 {
		t.Fatalf("accounts = %+v / %+v, identity calls = %d", first, second, identity.calls.Load())
	}
	terminal, err := oauthService.Session(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	if terminal.Status != "completed" || terminal.AccountID != first.ID || terminal.Authorization != nil {
		t.Fatalf("terminal session = %+v", terminal)
	}

	repeated, err := service.CompleteLogin(ctx, state)
	if err != nil || repeated.ID != first.ID || identity.calls.Load() != 1 {
		t.Fatalf("repeated completion = %+v, %v, identity calls = %d", repeated, err, identity.calls.Load())
	}
	stored, err := service.Get(ctx, first.ID)
	if err != nil || stored.Credentials.Subject != "private-subject" {
		t.Fatalf("stored account = %+v, %v", stored, err)
	}
}

type cancelledIdentityVerifier struct{}

func (cancelledIdentityVerifier) Verify(context.Context, string) (oauthxai.Identity, error) {
	return oauthxai.Identity{}, context.Canceled
}

func TestCompleteLoginCancellationKeepsAuthorizationResumable(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{29}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accounts := store.NewAccountRepository(database.DB, keys)
	sessions := store.NewOAuthSessionRepository(database.DB, keys)
	now := time.Now().UTC().Truncate(time.Second)
	state := "cancelled-completion"
	if err := sessions.Create(ctx, store.OAuthSession{State: state, DeviceCode: "device", TokenEndpoint: "https://auth.x.ai/token", PollInterval: 5 * time.Second, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := sessions.Authorize(ctx, state, store.OAuthAuthorization{AccessToken: "access", IDToken: "identity", AuthorizedAt: now, ExpiresAt: now.Add(time.Hour)}, now); err != nil {
		t.Fatal(err)
	}
	oauthService := oauthxai.NewService(nil, nil, sessions, oauthxai.Options{})
	service := NewService(accounts, oauthService, cancelledIdentityVerifier{}, nil, nil, nil)
	if _, err := service.CompleteLogin(ctx, state); err != context.Canceled {
		t.Fatalf("completion error = %v", err)
	}
	resumable, err := oauthService.Session(ctx, state)
	if err != nil || resumable.Status != "authorized" || resumable.Authorization == nil {
		t.Fatalf("cancelled completion session = %+v, %v", resumable, err)
	}
}
