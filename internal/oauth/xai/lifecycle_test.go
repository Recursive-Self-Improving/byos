package xai

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAuthorizedPollResultResumesWithoutTokenReexchange(t *testing.T) {
	service, database := oauthTestService(t, []string{`{"access_token":"persisted-access","refresh_token":"persisted-refresh","id_token":"persisted-id","token_type":"Bearer","expires_in":3600}`})
	defer database.Close()
	flow, err := service.StartDevice(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.Poll(context.Background(), flow.State)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := service.Session(context.Background(), flow.State)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Status != "authorized" || persisted.Authorization == nil || persisted.Authorization.AccessToken != first.AccessToken {
		t.Fatalf("persisted authorization = %+v", persisted)
	}

	restarted := NewService(nil, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("authorized session attempted a second token exchange")
		return nil, errors.New("unexpected token exchange")
	})}, service.sessions, Options{})
	restarted.now = service.now
	resumed, err := restarted.Poll(context.Background(), flow.State)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.AccessToken != first.AccessToken || resumed.IDToken != first.IDToken || !resumed.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatalf("resumed token = %+v, first = %+v", resumed, first)
	}
	if err := restarted.Complete(context.Background(), flow.State, "acct_resumed"); err != nil {
		t.Fatal(err)
	}
	completed, err := restarted.Session(context.Background(), flow.State)
	if err != nil || completed.Status != "completed" || completed.AccountID != "acct_resumed" || completed.Authorization != nil {
		t.Fatalf("completed session = %+v, %v", completed, err)
	}
}

func TestStopLeavesActivePollPersistedForRestart(t *testing.T) {
	service, database := oauthTestService(t, []string{`{"error":"authorization_pending"}`})
	defer database.Close()
	flow, err := service.StartDevice(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	waiting := make(chan struct{})
	service.wait = func(ctx context.Context, _ time.Duration) error {
		close(waiting)
		<-ctx.Done()
		return ctx.Err()
	}
	done := make(chan error, 1)
	go func() {
		_, err := service.Poll(context.Background(), flow.State)
		done <- err
	}()
	<-waiting
	service.Stop(flow.State)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("stopped poll error = %v", err)
	}
	pending, err := service.sessions.GetPending(context.Background(), flow.State, service.now())
	if err != nil || pending.Status != "pending" || pending.DeviceCode == "" {
		t.Fatalf("stopped session = %+v, %v", pending, err)
	}
}

func TestTerminalOAuthErrorsPersistOnlySafeMessages(t *testing.T) {
	service, database := oauthTestService(t, []string{`{"error":"access_denied","error_description":"tenant secret billing detail"}`})
	defer database.Close()
	flow, err := service.StartDevice(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Poll(context.Background(), flow.State)
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) || oauthErr.Code != "access_denied" {
		t.Fatalf("poll error = %v", err)
	}
	if strings.Contains(err.Error(), "tenant secret") || strings.Contains(err.Error(), "billing detail") {
		t.Fatalf("OAuth error leaked description: %v", err)
	}
	terminal, err := service.Session(context.Background(), flow.State)
	if err != nil {
		t.Fatal(err)
	}
	if terminal.Status != "failed" || terminal.SanitizedError != "Device authorization was denied." {
		t.Fatalf("terminal session = %+v", terminal)
	}
	if strings.Contains(terminal.SanitizedError, "tenant secret") || terminal.Authorization != nil {
		t.Fatalf("unsafe terminal session = %+v", terminal)
	}
	if _, err := service.sessions.GetResumable(context.Background(), flow.State, service.now()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("terminal session remained resumable: %v", err)
	}
}
