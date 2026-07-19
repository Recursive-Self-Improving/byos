package xai

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appcrypto "byos/internal/crypto"
	"byos/internal/provider"
	"byos/internal/store"
)

func TestRefreshSingleflightRotationAndInvalidGrant(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, _ := appcrypto.DeriveKeys(bytes.Repeat([]byte{12}, 32))
	accounts := store.NewAccountRepository(database.DB, keys)
	expires := time.Now().Add(time.Minute)
	account, err := accounts.UpsertLogin(ctx, store.Account{Provider: provider.XAI, Label: "account", Credentials: store.AccountCredentials{Issuer: Issuer, Subject: "refresh-sub", AccessToken: "old", RefreshToken: "refresh", TokenEndpoint: "https://auth.x.ai/token"}, ExpiresAt: &expires})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	release := make(chan struct{})
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		<-release
		return jsonResponse(`{"access_token":"new","expires_in":3600}`), nil
	})}
	service := NewRefreshService(client, accounts, Options{})
	var wg sync.WaitGroup
	wg.Add(2)
	errs := make(chan error, 2)
	for range 2 {
		go func() { defer wg.Done(); _, err := service.Refresh(ctx, account.ID); errs <- err }()
	}
	time.Sleep(10 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("refresh calls=%d", calls.Load())
	}
	updated, err := accounts.Get(ctx, account.ID)
	if err != nil || updated.Credentials.AccessToken != "new" || updated.Credentials.RefreshToken != "refresh" {
		t.Fatalf("updated=%+v err=%v", updated, err)
	}
	invalidClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 400, Body: io.NopCloser(strings.NewReader(`{"error":"invalid_grant"}`)), Header: make(http.Header)}, nil
	})}
	invalid := NewRefreshService(invalidClient, accounts, Options{})
	if _, err := invalid.Refresh(ctx, account.ID); err == nil {
		t.Fatal("invalid grant succeeded")
	}
	disabled, err := accounts.Get(ctx, account.ID)
	if err != nil || disabled.Enabled || disabled.Status != "relogin_required" || disabled.LastError == "" {
		t.Fatalf("disabled=%+v err=%v", disabled, err)
	}
}
func TestNeedsRefresh(t *testing.T) {
	now := time.Now()
	soon := now.Add(RefreshLead - time.Second)
	later := now.Add(RefreshLead + time.Second)
	if !NeedsRefresh(store.Account{ExpiresAt: &soon}, now) || NeedsRefresh(store.Account{ExpiresAt: &later}, now) {
		t.Fatal("refresh lead mismatch")
	}
}
func TestCredentialsUsable(t *testing.T) {
	now := time.Now()
	expired := now.Add(-time.Hour)
	later := now.Add(time.Hour)
	tests := []struct {
		name    string
		account store.Account
		want    bool
	}{{"fresh", store.Account{ExpiresAt: &later, Credentials: store.AccountCredentials{AccessToken: "token"}}, true}, {"expired refreshable", store.Account{ExpiresAt: &expired, Credentials: store.AccountCredentials{AccessToken: "token", RefreshToken: "refresh", TokenEndpoint: "https://auth.x.ai/token"}}, true}, {"expired no refresh", store.Account{ExpiresAt: &expired, Credentials: store.AccountCredentials{AccessToken: "token", TokenEndpoint: "https://auth.x.ai/token"}}, false}, {"missing access", store.Account{Credentials: store.AccountCredentials{RefreshToken: "refresh", TokenEndpoint: "https://auth.x.ai/token"}}, false}}
	for _, test := range tests {
		if got := CredentialsUsable(test.account, now); got != test.want {
			t.Fatalf("%s=%v", test.name, got)
		}
	}
}

func TestCredentialClientsRejectRedirects(t *testing.T) {
	request, err := http.NewRequest(http.MethodPost, "https://evil.example/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	client := secureOAuthClient(&http.Client{})
	if err := client.CheckRedirect(request, nil); err == nil {
		t.Fatal("credential redirect accepted")
	}
}
