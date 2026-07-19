package xai

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	appcrypto "byos/internal/crypto"
	"byos/internal/provider"
	"byos/internal/store"
)

func oauthTestService(t *testing.T, tokenBodies []string) (*Service, *store.SQLite) {
	t.Helper()
	database, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := appcrypto.DeriveKeys(bytes.Repeat([]byte{11}, 32))
	sessions := store.NewOAuthSessionRepository(database.DB, keys)
	var mu sync.Mutex
	tokenIndex := 0
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			return jsonResponse(discoveryDocument("https://auth.x.ai/device")), nil
		case "/device":
			body, _ := io.ReadAll(r.Body)
			values, _ := url.ParseQuery(string(body))
			if values.Get("client_id") != DefaultClientID || values.Get("scope") != DefaultScopes {
				t.Fatalf("device form=%v", values)
			}
			return jsonResponse(`{"device_code":"device-secret","user_code":"USER-CODE","verification_uri":"https://auth.x.ai/verify","verification_uri_complete":"https://auth.x.ai/verify?code=USER-CODE","expires_in":600,"interval":1}`), nil
		case "/token":
			mu.Lock()
			defer mu.Unlock()
			body := tokenBodies[min(tokenIndex, len(tokenBodies)-1)]
			tokenIndex++
			return jsonResponse(body), nil
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
			return nil, nil
		}
	})
	client := &http.Client{Transport: transport}
	discovery := NewDiscoveryClient(client, DiscoveryURL)
	service := NewService(discovery, client, sessions, Options{})
	fixed := time.Now().UTC().Truncate(time.Second)
	service.now = func() time.Time { return fixed }
	service.wait = func(context.Context, time.Duration) error { return nil }
	return service, database
}
func jsonResponse(body string) *http.Response {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}
func TestStartDevicePersistsSafeNormalizedSession(t *testing.T) {
	service, database := oauthTestService(t, []string{`{"access_token":"token"}`})
	defer database.Close()
	flow, err := service.StartDevice(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if flow.State == "" || flow.UserCode != "USER-CODE" || flow.VerificationURIComplete == "" || flow.PollInterval != MinimumPollInterval {
		t.Fatalf("flow=%+v", flow)
	}
	encoded, _ := json.Marshal(flow)
	if strings.Contains(string(encoded), "device-secret") {
		t.Fatal("device code exposed")
	}
	pending, err := service.sessions.ListPending(context.Background(), provider.XAI, store.OAuthFlowDevice, service.now())
	if err != nil || len(pending) != 1 || pending[0].DeviceCode != "device-secret" {
		t.Fatalf("pending=%+v err=%v", pending, err)
	}
}
func TestPollPendingSlowDownSuccessAndDeduplicates(t *testing.T) {
	service, database := oauthTestService(t, []string{`{"error":"authorization_pending"}`, `{"error":"slow_down"}`, `{"access_token":"access","refresh_token":"refresh","id_token":"id","expires_in":3600}`})
	defer database.Close()
	flow, err := service.StartDevice(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var waits []time.Duration
	service.wait = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	var wg sync.WaitGroup
	wg.Add(2)
	results := make(chan TokenResponse, 2)
	for range 2 {
		go func() {
			defer wg.Done()
			token, err := service.Poll(context.Background(), flow.State)
			if err != nil {
				t.Error(err)
				return
			}
			results <- token
		}()
	}
	wg.Wait()
	close(results)
	for token := range results {
		if token.AccessToken != "access" {
			t.Fatalf("token=%+v", token)
		}
	}
	if len(waits) != 2 || waits[0] != 5*time.Second || waits[1] != 10*time.Second {
		t.Fatalf("waits=%v", waits)
	}
}
func TestPollTerminalAndCancellationPaths(t *testing.T) {
	tests := []struct{ name, body, code string }{{"denied", `{"error":"access_denied","error_description":"denied"}`, "access_denied"}, {"expired", `{"error":"expired_token"}`, "expired_token"}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, database := oauthTestService(t, []string{test.body})
			defer database.Close()
			flow, _ := service.StartDevice(context.Background())
			_, err := service.Poll(context.Background(), flow.State)
			var oauthErr *OAuthError
			if !errors.As(err, &oauthErr) || oauthErr.Code != test.code {
				t.Fatalf("error=%v", err)
			}
			if _, err := service.sessions.GetPending(context.Background(), provider.XAI, store.OAuthFlowDevice, flow.State, service.now()); err != sql.ErrNoRows {
				t.Fatalf("terminal resumed: %v", err)
			}
		})
	}
	service, database := oauthTestService(t, []string{`{"error":"authorization_pending"}`})
	defer database.Close()
	flow, _ := service.StartDevice(context.Background())
	if err := service.Cancel(context.Background(), flow.State); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Poll(context.Background(), flow.State); err != sql.ErrNoRows {
		t.Fatalf("cancelled poll=%v", err)
	}
}

func TestCancelStopsActivePoll(t *testing.T) {
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
	go func() { _, err := service.Poll(context.Background(), flow.State); done <- err }()
	<-waiting
	if err := service.Cancel(context.Background(), flow.State); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != context.Canceled {
		t.Fatalf("active poll error = %v", err)
	}
}

func TestPollLeaderContextCancellationStopsWorkerAndPreservesPending(t *testing.T) {
	service, database := oauthTestService(t, []string{`{"error":"authorization_pending"}`})
	defer database.Close()
	flow, err := service.StartDevice(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	waiting := make(chan struct{})
	service.wait = func(ctx context.Context, _ time.Duration) error { close(waiting); <-ctx.Done(); return ctx.Err() }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := service.Poll(ctx, flow.State); done <- err }()
	<-waiting
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("poll error=%v", err)
	}
	if _, err := service.sessions.GetPending(context.Background(), provider.XAI, store.OAuthFlowDevice, flow.State, service.now()); err != nil {
		t.Fatalf("pending lost=%v", err)
	}
}

func TestPollDoesNotExchangeAfterLocalExpiry(t *testing.T) {
	service, database := oauthTestService(t, []string{`{"error":"authorization_pending"}`})
	defer database.Close()
	current := time.Now().UTC().Truncate(time.Second)
	service.now = func() time.Time { return current }
	state := "short-lived"
	if err := service.sessions.Create(context.Background(), store.OAuthSession{Provider: provider.XAI, FlowType: store.OAuthFlowDevice, State: state, DeviceCode: "device", UserCode: "CODE", VerificationURI: "https://auth.x.ai/verify", TokenEndpoint: "https://auth.x.ai/token", PollInterval: MinimumPollInterval, ExpiresAt: current.Add(3 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	var waits []time.Duration
	service.wait = func(_ context.Context, duration time.Duration) error {
		waits = append(waits, duration)
		current = current.Add(duration)
		return nil
	}
	_, err := service.Poll(context.Background(), state)
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) || oauthErr.Code != "expired_token" {
		t.Fatalf("expiry error = %v", err)
	}
	if len(waits) != 1 || waits[0] != 3*time.Second {
		t.Fatalf("expiry waits = %v", waits)
	}
}

func TestJoinedPollCallerCancellationIsIndependent(t *testing.T) {
	service, database := oauthTestService(t, []string{`{"error":"authorization_pending"}`})
	defer database.Close()
	flow, err := service.StartDevice(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	waiting := make(chan struct{})
	service.wait = func(ctx context.Context, _ time.Duration) error {
		select {
		case <-waiting:
		default:
			close(waiting)
		}
		<-ctx.Done()
		return ctx.Err()
	}
	leaderDone := make(chan error, 1)
	go func() { _, err := service.Poll(context.Background(), flow.State); leaderDone <- err }()
	<-waiting
	joinCtx, cancelJoin := context.WithCancel(context.Background())
	cancelJoin()
	if _, err := service.Poll(joinCtx, flow.State); err != context.Canceled {
		t.Fatalf("joined caller error = %v", err)
	}
	select {
	case err := <-leaderDone:
		t.Fatalf("joined cancellation stopped leader: %v", err)
	default:
	}
	if err := service.Cancel(context.Background(), flow.State); err != nil {
		t.Fatal(err)
	}
	if err := <-leaderDone; err != context.Canceled {
		t.Fatalf("leader cancel error = %v", err)
	}
}
