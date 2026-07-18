package accounts

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	appcrypto "byos/internal/crypto"
	oauthxai "byos/internal/oauth/xai"
	"byos/internal/store"
)

type refreshHookFunc func(context.Context, string) error

func (f refreshHookFunc) Refresh(ctx context.Context, id string) error { return f(ctx, id) }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestRefreshWorkerRunsMetadataHooksAfterSuccessfulRotation(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	repo := store.NewAccountRepository(database.DB, keys)
	expires := time.Now().Add(time.Minute)
	account, err := repo.UpsertLogin(ctx, store.Account{ExpiresAt: &expires, Credentials: store.AccountCredentials{Issuer: "issuer", Subject: "subject", AccessToken: "old", RefreshToken: "refresh", TokenEndpoint: "https://auth.x.ai/token"}})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString(`{"access_token":"new","expires_in":3600}`))}, nil
	})}
	refresh := oauthxai.NewRefreshService(client, repo, oauthxai.Options{})
	var calls atomic.Int32
	worker := NewRefreshWorker(repo, refresh, refreshHookFunc(func(_ context.Context, id string) error {
		if id != account.ID {
			t.Fatalf("id=%s", id)
		}
		calls.Add(1)
		return nil
	}))
	if err := worker.refreshDue(ctx); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("hooks=%d", calls.Load())
	}
	updated, err := repo.Get(ctx, account.ID)
	if err != nil || updated.Credentials.AccessToken != "new" {
		t.Fatalf("account=%+v err=%v", updated, err)
	}
}
