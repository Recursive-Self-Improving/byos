package routing

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	appcrypto "supergrok-api/internal/crypto"
	oauthxai "supergrok-api/internal/oauth/xai"
	"supergrok-api/internal/store"
	"supergrok-api/internal/xai"
)

type executeStep struct {
	events []xai.Event
	err    error
}

type fakeExecutionClient struct {
	mu        sync.Mutex
	steps     []executeStep
	tokens    []string
	models    []string
	bodies    [][]byte
	onExecute func()
}

func (f *fakeExecutionClient) Execute(_ context.Context, token, model string, body []byte) ([]xai.Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens = append(f.tokens, token)
	f.models = append(f.models, model)
	f.bodies = append(f.bodies, bytes.Clone(body))
	if f.onExecute != nil {
		f.onExecute()
	}
	step := f.steps[0]
	f.steps = f.steps[1:]
	return step.events, step.err
}

func (*fakeExecutionClient) Stream(context.Context, string, string, []byte) (*xai.Stream, error) {
	panic("unexpected Stream call")
}

type fakeRefresher struct {
	accounts map[string]store.Account
	errors   map[string]error
	calls    []string
}

func (f *fakeRefresher) Refresh(_ context.Context, accountID string) (store.Account, error) {
	f.calls = append(f.calls, accountID)
	if err := f.errors[accountID]; err != nil {
		return store.Account{}, err
	}
	return f.accounts[accountID], nil
}

type executionFixture struct {
	executor *Executor
	client   *fakeExecutionClient
	refresh  *fakeRefresher
	accounts *store.AccountRepository
	states   *store.CooldownRepository
	manager  *CooldownManager
	close    func()
}

func newExecutionFixture(t *testing.T, count int) (*executionFixture, []store.Account) {
	t.Helper()
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accounts := store.NewAccountRepository(database.DB, keys)
	stored := make([]store.Account, 0, count)
	for index := range count {
		account, err := accounts.UpsertLogin(ctx, store.Account{Label: "account", Status: "ready", Credentials: store.AccountCredentials{Issuer: "issuer", Subject: string(rune('a' + index)), AccessToken: "token-" + string(rune('a'+index)), RefreshToken: "refresh", TokenEndpoint: "https://auth.invalid/token"}})
		if err != nil {
			t.Fatal(err)
		}
		stored = append(stored, account)
	}
	states := store.NewCooldownRepository(database.DB)
	manager := NewCooldownManager(states, accounts)
	client := &fakeExecutionClient{}
	refresh := &fakeRefresher{accounts: make(map[string]store.Account), errors: make(map[string]error)}
	executor := newExecutor(NewScheduler(), client, refresh, manager, accounts, store.NewModelCapabilityRepository(database.DB), states, ResolverFunc(func(model string) (string, error) {
		if model == "alias" {
			return "grok-4.5", nil
		}
		return model, nil
	}))
	return &executionFixture{executor: executor, client: client, refresh: refresh, accounts: accounts, states: states, manager: manager, close: func() { database.Close() }}, stored
}

type recordedUsage struct {
	mu     sync.Mutex
	values map[string][]LocalUsageDelta
}

func (r *recordedUsage) Record(_ context.Context, accountID string, delta LocalUsageDelta) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.values[accountID] = append(r.values[accountID], delta)
	return nil
}
func (r *recordedUsage) latest(accountID string) LocalUsageDelta {
	r.mu.Lock()
	defer r.mu.Unlock()
	values := r.values[accountID]
	if len(values) == 0 {
		return LocalUsageDelta{}
	}
	return values[len(values)-1]
}

func TestExecuteRecordsSuccessAndFailedFailoverPerAccount(t *testing.T) {
	fixture, accounts := newExecutionFixture(t, 2)
	defer fixture.close()
	recorder := &recordedUsage{values: make(map[string][]LocalUsageDelta)}
	fixture.executor.SetUsageRecorder(recorder)
	fixture.client.steps = []executeStep{{err: &xai.UpstreamError{Status: http.StatusInternalServerError}}, {events: []xai.Event{{Data: []byte(`{"type":"response.completed","response":{"usage":{"input_tokens":7,"output_tokens":9}}}`)}}}}
	_, err := fixture.executor.Execute(context.Background(), Request{Model: "grok-4.5", Body: []byte(`{"tools":[{"type":"x_search"}]}`), PreferredAccountID: accounts[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if got := recorder.latest(accounts[0].ID); got.Requests != 1 || got.Failures != 1 {
		t.Fatalf("failed account delta=%+v", got)
	}
	if got := recorder.latest(accounts[1].ID); got.Requests != 1 || got.Failures != 0 || got.InputTokens != 7 || got.OutputTokens != 9 {
		t.Fatalf("success account delta=%+v", got)
	}
}

type contextCheckingRecorder struct {
	mu       sync.Mutex
	canceled bool
	delta    LocalUsageDelta
}

func (r *contextCheckingRecorder) Record(ctx context.Context, _ string, delta LocalUsageDelta) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.canceled = ctx.Err() != nil
	r.delta = delta
	return nil
}

func TestExecuteRecordsCancellationWithDetachedContext(t *testing.T) {
	fixture, accounts := newExecutionFixture(t, 1)
	defer fixture.close()
	recorder := &contextCheckingRecorder{}
	fixture.executor.SetUsageRecorder(recorder)
	ctx, cancel := context.WithCancel(context.Background())
	fixture.client.onExecute = cancel
	fixture.client.steps = []executeStep{{err: context.Canceled}}
	_, _ = fixture.executor.Execute(ctx, Request{Model: "grok-4.5", Body: []byte(`{"tools":[{"type":"x_search"}]}`), PreferredAccountID: accounts[0].ID})
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.canceled || recorder.delta.Failures != 1 {
		t.Fatalf("recorder=%+v", recorder)
	}
}

func TestExecuteRecordsIncompleteTerminalUsage(t *testing.T) {
	fixture, accounts := newExecutionFixture(t, 1)
	defer fixture.close()
	recorder := &recordedUsage{values: make(map[string][]LocalUsageDelta)}
	fixture.executor.SetUsageRecorder(recorder)
	fixture.client.steps = []executeStep{{events: []xai.Event{{Data: []byte(`{"type":"response.incomplete","response":{"usage":{"input_tokens":5,"output_tokens":6}}}`)}}}}
	if _, err := fixture.executor.Execute(context.Background(), Request{Model: "grok-4.5", Body: []byte(`{"tools":[{"type":"x_search"}]}`), PreferredAccountID: accounts[0].ID}); err != nil {
		t.Fatal(err)
	}
	if got := recorder.latest(accounts[0].ID); got.Failures != 0 || got.InputTokens != 5 || got.OutputTokens != 6 {
		t.Fatalf("delta=%+v", got)
	}
}

func TestExecuteSuccessResolvesAliasAndPreservesPreparedSearch(t *testing.T) {
	fixture, accounts := newExecutionFixture(t, 1)
	defer fixture.close()
	fixture.client.steps = []executeStep{{events: []xai.Event{{Data: []byte(`{"type":"response.completed"}`)}}}}
	result, err := fixture.executor.Execute(context.Background(), Request{Model: "alias", Body: []byte(`{"input":"hello","tools":[{"type":"x_search"}],"tool_choice":"required"}`), PreferredAccountID: accounts[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if result.Model != "grok-4.5" || result.AccountID != accounts[0].ID || len(result.Events) != 1 {
		t.Fatalf("result=%+v", result)
	}
	if len(fixture.client.bodies) != 1 || !bytes.Contains(fixture.client.bodies[0], []byte(`"type":"x_search"`)) || !bytes.Contains(fixture.client.bodies[0], []byte(`"tool_choice":"required"`)) || !bytes.Contains(fixture.client.bodies[0], []byte(`"model":"grok-4.5"`)) {
		t.Fatalf("unprepared body: %s", fixture.client.bodies[0])
	}
}

func TestExecuteRejectsMissingPreparedSearchBeforeScheduling(t *testing.T) {
	fixture, _ := newExecutionFixture(t, 1)
	defer fixture.close()
	_, err := fixture.executor.Execute(context.Background(), Request{Model: "grok-4.5", Body: []byte(`{"input":"hello"}`)})
	if err == nil || len(fixture.client.tokens) != 0 {
		t.Fatalf("err=%v calls=%v", err, fixture.client.tokens)
	}
}

func TestExecuteValidationDoesNotRetry(t *testing.T) {
	fixture, accounts := newExecutionFixture(t, 2)
	defer fixture.close()
	fixture.client.steps = []executeStep{{err: &xai.UpstreamError{Status: http.StatusBadRequest, Body: "private"}}}
	_, err := fixture.executor.Execute(context.Background(), Request{Model: "grok-4.5", Body: []byte(`{"tools":[{"type":"x_search"}]}`), PreferredAccountID: accounts[0].ID})
	var executionErr *ExecutionError
	if !errors.As(err, &executionErr) || executionErr.Classified.Class != ClassValidation || len(fixture.client.tokens) != 1 {
		t.Fatalf("err=%v calls=%v", err, fixture.client.tokens)
	}
}

func TestExecuteRefreshesAndRetriesUnauthorizedOnSameAccount(t *testing.T) {
	fixture, accounts := newExecutionFixture(t, 2)
	defer fixture.close()
	refreshed := accounts[0]
	refreshed.Credentials.AccessToken = "fresh-token"
	fixture.refresh.accounts[accounts[0].ID] = refreshed
	fixture.client.steps = []executeStep{{err: &xai.UpstreamError{Status: http.StatusUnauthorized}}, {events: []xai.Event{{Data: []byte(`{"type":"response.completed"}`)}}}}
	result, err := fixture.executor.Execute(context.Background(), Request{Model: "grok-4.5", Body: []byte(`{"tools":[{"type":"x_search"}]}`), PreferredAccountID: accounts[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if result.AccountID != accounts[0].ID || len(fixture.refresh.calls) != 1 || len(fixture.client.tokens) != 2 || fixture.client.tokens[0] == fixture.client.tokens[1] || fixture.client.tokens[1] != "fresh-token" {
		t.Fatalf("result=%+v refresh=%v tokens=%v", result, fixture.refresh.calls, fixture.client.tokens)
	}
}

func TestExecuteFailsOverRateLimitAndTransient(t *testing.T) {
	fixture, accounts := newExecutionFixture(t, 3)
	defer fixture.close()
	fixture.client.steps = []executeStep{
		{err: &xai.UpstreamError{Status: http.StatusTooManyRequests}},
		{err: &xai.UpstreamError{Status: http.StatusServiceUnavailable}},
		{events: []xai.Event{{Data: []byte(`{"type":"response.completed"}`)}}},
	}
	result, err := fixture.executor.Execute(context.Background(), Request{Model: "grok-4.5", Body: []byte(`{"tools":[{"type":"x_search"}]}`), PreferredAccountID: accounts[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	accountByToken := make(map[string]store.Account, len(accounts))
	for _, account := range accounts {
		accountByToken[account.Credentials.AccessToken] = account
	}
	if len(fixture.client.tokens) != 3 || result.AccountID != accountByToken[fixture.client.tokens[2]].ID {
		t.Fatalf("result=%+v tokens=%v", result, fixture.client.tokens)
	}
	for _, token := range fixture.client.tokens[:2] {
		account := accountByToken[token]
		state, err := fixture.states.Get(context.Background(), account.ID, "grok-4.5", time.Now().UTC())
		if err != nil || state.Until == nil {
			t.Fatalf("missing cooldown for %s: %+v %v", account.ID, state, err)
		}
	}
}

func TestExecuteFinalRateLimitExposesSanitizedRetryAfter(t *testing.T) {
	fixture, accounts := newExecutionFixture(t, 1)
	defer fixture.close()
	now := time.Now().UTC().Truncate(time.Second)
	fixture.executor.now = func() time.Time { return now }
	fixture.manager.now = func() time.Time { return now }
	fixture.client.steps = []executeStep{{err: &xai.UpstreamError{Status: http.StatusTooManyRequests, Body: "private-upstream-detail", Headers: http.Header{"Retry-After": []string{"120"}}}}}
	_, err := fixture.executor.Execute(context.Background(), Request{Model: "grok-4.5", Body: []byte(`{"tools":[{"type":"x_search"}]}`), PreferredAccountID: accounts[0].ID})
	var executionErr *ExecutionError
	if !errors.As(err, &executionErr) || executionErr.Classified.Class != ClassRateLimit || !executionErr.Classified.ExplicitRetryAfter || !executionErr.Classified.RetryAfter.Equal(now.Add(2*time.Minute)) || executionErr.Classified.Cooldown != 2*time.Minute {
		t.Fatalf("err=%v classified=%+v", err, executionErr)
	}
	if bytes.Contains([]byte(err.Error()), []byte("private-upstream-detail")) {
		t.Fatalf("upstream detail leaked: %v", err)
	}
}

func TestExecuteAllAccountsCooling(t *testing.T) {
	fixture, accounts := newExecutionFixture(t, 2)
	defer fixture.close()
	now := time.Now().UTC()
	for _, account := range accounts {
		until := now.Add(time.Hour)
		if err := fixture.states.Put(context.Background(), store.Cooldown{AccountID: account.ID, Model: "grok-4.5", Until: &until}); err != nil {
			t.Fatal(err)
		}
	}
	_, err := fixture.executor.Execute(context.Background(), Request{Model: "grok-4.5", Body: []byte(`{"tools":[{"type":"x_search"}]}`)})
	var executionErr *ExecutionError
	if !errors.As(err, &executionErr) || executionErr.Classified.Class != ClassRateLimit || executionErr.Classified.RetryAfter.IsZero() || executionErr.Classified.Cooldown <= 0 || len(fixture.client.tokens) != 0 {
		t.Fatalf("err=%v calls=%v", err, fixture.client.tokens)
	}
}

func TestExecuteCancellationNeverFailsOver(t *testing.T) {
	fixture, accounts := newExecutionFixture(t, 2)
	defer fixture.close()
	fixture.client.steps = []executeStep{{err: context.Canceled}}
	_, err := fixture.executor.Execute(context.Background(), Request{Model: "grok-4.5", Body: []byte(`{"tools":[{"type":"x_search"}]}`), PreferredAccountID: accounts[0].ID})
	var executionErr *ExecutionError
	if !errors.As(err, &executionErr) || executionErr.Classified.Class != ClassCancelled || len(fixture.client.tokens) != 1 {
		t.Fatalf("err=%v calls=%v", err, fixture.client.tokens)
	}
}

func TestExecuteProactivelyRefreshesNearExpiry(t *testing.T) {
	fixture, accounts := newExecutionFixture(t, 1)
	defer fixture.close()
	expires := time.Now().UTC().Add(oauthxai.RefreshLead / 2)
	account := accounts[0]
	account.ExpiresAt = &expires
	if _, err := fixture.accounts.UpsertLogin(context.Background(), account); err != nil {
		t.Fatal(err)
	}
	account.Credentials.AccessToken = "proactive-token"
	fixture.refresh.accounts[account.ID] = account
	fixture.client.steps = []executeStep{{events: []xai.Event{{Data: []byte(`{"type":"response.completed"}`)}}}}
	_, err := fixture.executor.Execute(context.Background(), Request{Model: "grok-4.5", Body: []byte(`{"tools":[{"type":"x_search"}]}`), PreferredAccountID: account.ID})
	if err != nil || len(fixture.refresh.calls) != 1 || fixture.client.tokens[0] != "proactive-token" {
		t.Fatalf("err=%v refresh=%v tokens=%v", err, fixture.refresh.calls, fixture.client.tokens)
	}
}
