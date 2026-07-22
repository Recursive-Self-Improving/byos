package routing

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	appcrypto "byos/internal/crypto"
	"byos/internal/provider"
	"byos/internal/store"
	"byos/internal/xai"
)

type fakeStream struct {
	mu     sync.Mutex
	events []provider.Event
	errs   []error
	closed bool
}

func (s *fakeStream) Next(context.Context) (provider.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) > 0 {
		e := s.events[0]
		s.events = s.events[1:]
		return e, nil
	}
	if len(s.errs) > 0 {
		e := s.errs[0]
		s.errs = s.errs[1:]
		return provider.Event{}, e
	}
	return provider.Event{}, errors.New("truncated stream")
}
func (s *fakeStream) Close() error { s.mu.Lock(); s.closed = true; s.mu.Unlock(); return nil }

type streamStep struct {
	stream provider.Stream
	err    error
}
type fakeStreamGeneration struct {
	mu       sync.Mutex
	ledger   *[]string
	steps    []streamStep
	requests []provider.GenerationRequest
}

func (f *fakeStreamGeneration) Execute(context.Context, provider.GenerationRequest) ([]provider.Event, error) {
	panic("unexpected execute")
}
func (f *fakeStreamGeneration) Stream(_ context.Context, r provider.GenerationRequest) (provider.Stream, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	*f.ledger = append(*f.ledger, "client")
	f.requests = append(f.requests, r)
	s := f.steps[0]
	f.steps = f.steps[1:]
	return s.stream, s.err
}

func streamFixture(t *testing.T, count int) (*executionFixture, *fakeStreamGeneration) {
	t.Helper()
	f := newExecutionFixture(t, count)
	client := &fakeStreamGeneration{ledger: f.ledger}
	caps, _ := f.executor.registry.Capabilities(provider.XAI, "xai")
	caps.Generation = client
	f.executor.registry = fakeRegistry{ledger: f.ledger, caps: map[string]provider.Capabilities{"xai/xai": caps}}
	*f.ledger = nil
	return f, client
}

func TestStreamFailsOverOnlyBeforeFirstEventWithoutDuplicates(t *testing.T) {
	f, client := streamFixture(t, 2)
	defer f.close()
	first := &fakeStream{errs: []error{&provider.UpstreamError{Provider: provider.XAI, Status: 503, Classification: provider.ErrorClassification{Class: provider.ClassTransient, RetryNext: true}}}}
	second := &fakeStream{events: []provider.Event{{Event: "delta", Data: []byte("only-once")}, {Event: "done", Data: []byte(`{"type":"response.completed"}`)}}}
	client.steps = []streamStep{{stream: first}, {stream: second}}
	stream, err := f.executor.Stream(context.Background(), Request{Model: "grok", Body: []byte(`{"model":"grok"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if stream.Committed() {
		t.Fatal("committed before downstream delivery")
	}
	event, err := stream.Next(context.Background())
	if err != nil || string(event.Data) != "only-once" || !stream.Committed() {
		t.Fatalf("event=%s committed=%v err=%v", event.Data, stream.Committed(), err)
	}
	if len(client.requests) != 2 {
		t.Fatalf("attempts=%d", len(client.requests))
	}
	for _, r := range client.requests {
		if r.Model.Provider != provider.XAI {
			t.Fatal("cross-provider stream attempt")
		}
	}
}

func TestStreamFailureAfterFirstEventNeverReplays(t *testing.T) {
	f, client := streamFixture(t, 2)
	defer f.close()
	upstream := &fakeStream{events: []provider.Event{{Data: []byte("committed")}}, errs: []error{errors.New("truncated")}}
	client.steps = []streamStep{{stream: upstream}}
	stream, err := f.executor.Stream(context.Background(), Request{Model: "grok", Body: []byte(`{"model":"grok"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err = stream.Next(context.Background())
	var executionErr *ExecutionError
	if !errors.As(err, &executionErr) || !stream.Committed() {
		t.Fatalf("err=%v committed=%v", err, stream.Committed())
	}
	if len(client.requests) != 1 {
		t.Fatalf("post-commit replay attempts=%d", len(client.requests))
	}
}

func TestStreamCancellationBeforeDeliveryDoesNotCommit(t *testing.T) {
	f, client := streamFixture(t, 1)
	defer f.close()
	upstream := &fakeStream{events: []provider.Event{{Data: []byte("buffered")}}}
	client.steps = []streamStep{{stream: upstream}}
	stream, err := f.executor.Stream(context.Background(), Request{Model: "grok", Body: []byte(`{"model":"grok"}`)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = stream.Next(ctx)
	var executionErr *ExecutionError
	if !errors.As(err, &executionErr) || executionErr.Classified.Class != provider.ClassCancelled || stream.Committed() {
		t.Fatalf("err=%v committed=%v", err, stream.Committed())
	}
	upstream.mu.Lock()
	closed := upstream.closed
	upstream.mu.Unlock()
	if !closed {
		t.Fatal("active upstream not closed")
	}
}

func TestRoutedStreamConcurrentNextAndCloseRecordsOnce(t *testing.T) {
	f, client := streamFixture(t, 1)
	defer f.close()
	upstream := &fakeStream{events: []provider.Event{{Data: []byte("first")}}, errs: []error{errors.New("truncated")}}
	client.steps = []streamStep{{stream: upstream}}
	stream, err := f.executor.Stream(context.Background(), Request{Model: "grok", Body: []byte(`{"model":"grok"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := stream.Next(context.Background()); done <- err }()
	_ = stream.Close()
	if err := <-done; err == nil {
		t.Fatal("Next succeeded after Close")
	}
	want := usageRecord{accountID: stream.AccountID(), delta: LocalUsageDelta{Requests: 1, Failures: 1}}
	if stream.Model() != "grok-4.5" || len(*f.usage) != 1 || (*f.usage)[0] != want {
		t.Fatalf("model=%q usage=%+v, want [%+v]", stream.Model(), *f.usage, want)
	}
}

func TestStreamPreparationOrderMatchesExecuteAndRejectsBeforeMutation(t *testing.T) {
	f, client := streamFixture(t, 1)
	defer f.close()
	client.steps = []streamStep{{stream: &fakeStream{events: []provider.Event{{Data: []byte(`{"type":"response.completed"}`)}}}}}
	input := []byte(`{"model":"grok","input":"hello"}`)
	original := bytes.Clone(input)
	stream, err := f.executor.Stream(context.Background(), Request{Model: "grok", Body: input})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	requireLedger(t, *f.ledger, "resolve", "capabilities", "policy", "account-list", "credential-usable", "capability-list", "cooldown-get", "cooldown-get", "account-get", "credential", "client")
	if !bytes.Equal(input, original) {
		t.Fatalf("input mutated: got %s want %s", input, original)
	}

	*f.ledger = nil
	unknown := []byte(" { \"model\" : \"unknown\" } ")
	unknownOriginal := bytes.Clone(unknown)
	_, err = f.executor.Stream(context.Background(), Request{Model: "unknown", Body: unknown})
	if !errors.Is(err, ErrModelUnavailable) {
		t.Fatalf("unknown model err=%v", err)
	}
	requireLedger(t, *f.ledger, "resolve")
	if !bytes.Equal(unknown, unknownOriginal) {
		t.Fatalf("unknown input mutated: got %s want %s", unknown, unknownOriginal)
	}

	*f.ledger = nil
	resolved := provider.ResolvedModel{PublicName: "devin", UpstreamName: "devin", Provider: provider.Devin, PolicyKey: "devin"}
	f.executor.catalog = fakeCatalog{ledger: f.ledger, models: map[string]provider.ResolvedModel{"devin": resolved}}
	_, err = f.executor.Stream(context.Background(), Request{Model: "devin", Body: unknown})
	if !errors.Is(err, ErrModelUnavailable) {
		t.Fatalf("missing capability err=%v", err)
	}
	requireLedger(t, *f.ledger, "resolve", "capabilities")
	if !bytes.Equal(unknown, unknownOriginal) {
		t.Fatalf("missing-capability input mutated: got %s want %s", unknown, unknownOriginal)
	}

	*f.ledger = nil
	resolved = provider.ResolvedModel{PublicName: "grok", UpstreamName: "grok-4.5", Provider: provider.XAI, PolicyKey: "xai"}
	f.executor.catalog = fakeCatalog{ledger: f.ledger, models: map[string]provider.ResolvedModel{"grok": resolved}}
	f.executor.registry = fakeRegistry{ledger: f.ledger, caps: map[string]provider.Capabilities{"xai/xai": {Policy: ledgerPolicy{ledger: f.ledger, policy: xai.RequestPolicy{}}, Generation: client, Credentials: f.credentials}}}
	rejected := []byte(`{"model":"grok","input":"hello","tools":[{"type":"x_search"},{"type":"x_search"}]}`)
	rejectedOriginal := bytes.Clone(rejected)
	credentialCallsBefore := len(f.credentials.calls)
	clientCallsBefore := len(client.requests)
	cooldownsBefore := f.cooldownRows(t)
	_, err = f.executor.Stream(context.Background(), Request{Model: "grok", Body: rejected})
	var upstream *provider.UpstreamError
	if !errors.As(err, &upstream) || upstream.Classification.Class != provider.ClassValidation || upstream.Classification.PublicStatus != 400 || upstream.Classification.PublicCode != "invalid_request_error" || upstream.Classification.PublicMessage != "invalid request" {
		t.Fatalf("xAI policy error=%#v", err)
	}
	requireLedger(t, *f.ledger, "resolve", "capabilities", "policy")
	if !bytes.Equal(rejected, rejectedOriginal) || len(f.credentials.calls) != credentialCallsBefore || len(client.requests) != clientCallsBefore || f.cooldownRows(t) != cooldownsBefore {
		t.Fatalf("xAI policy side effects: body=%s credentials=%v requests=%d cooldowns=%d", rejected, f.credentials.calls, len(client.requests), f.cooldownRows(t))
	}
}

func TestStreamTerminalUsageRecordedExactlyOnce(t *testing.T) {
	tests := []struct {
		name      string
		eventType string
		data      []byte
		input     int64
		output    int64
		cacheRead int64
	}{
		{name: "normal completion", eventType: "response.completed", data: []byte(`{"type":"response.completed","response":{"usage":{"input_tokens":11,"output_tokens":13,"input_tokens_details":{"cached_tokens":7}}}}`), input: 11, output: 13, cacheRead: 7},
		{name: "incomplete response", eventType: "response.incomplete", data: []byte(`{"type":"response.incomplete","response":{"usage":{"input_tokens":17,"output_tokens":19,"input_tokens_details":{"cached_tokens":3}}}}`), input: 17, output: 19, cacheRead: 3},
		{name: "no cache-read reported", eventType: "response.completed", data: []byte(`{"type":"response.completed","response":{"usage":{"input_tokens":23,"output_tokens":29}}}`), input: 23, output: 29, cacheRead: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f, client := streamFixture(t, 1)
			defer f.close()
			client.steps = []streamStep{{stream: &fakeStream{events: []provider.Event{{Event: test.eventType, Data: test.data}}}}}

			stream, err := f.executor.Stream(context.Background(), Request{Model: "grok", Body: []byte(`{"model":"grok"}`)})
			if err != nil {
				t.Fatal(err)
			}
			if len(*f.usage) != 0 {
				t.Fatalf("usage recorded before buffered event delivery: %+v", *f.usage)
			}
			event, err := stream.Next(context.Background())
			if err != nil || event.Event != test.eventType {
				t.Fatalf("event=%+v err=%v", event, err)
			}
			if err := stream.Close(); err != nil {
				t.Fatal(err)
			}
			if stream.Model() != "grok-4.5" || !stream.Committed() {
				t.Fatalf("model=%q committed=%v", stream.Model(), stream.Committed())
			}
			want := usageRecord{accountID: stream.AccountID(), delta: LocalUsageDelta{Requests: 1, InputTokens: test.input, OutputTokens: test.output, CacheReadTokens: test.cacheRead}}
			if len(*f.usage) != 1 || (*f.usage)[0] != want {
				t.Fatalf("usage=%+v, want [%+v]", *f.usage, want)
			}
		})
	}
}

func TestStreamPrecommitFailoverRecordsEachAttemptOnce(t *testing.T) {
	f, client := streamFixture(t, 2)
	defer f.close()
	first := &fakeStream{errs: []error{&provider.UpstreamError{Provider: provider.XAI, Status: 503, Classification: provider.ErrorClassification{Class: provider.ClassTransient, RetryNext: true}}}}
	second := &fakeStream{events: []provider.Event{{Event: "response.completed", Usage: provider.Usage{InputTokens: 29, OutputTokens: 31}}}}
	client.steps = []streamStep{{stream: first}, {stream: second}}

	stream, err := f.executor.Stream(context.Background(), Request{Model: "grok", Body: []byte(`{"model":"grok"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if len(*f.usage) != 1 || (*f.usage)[0].delta != (LocalUsageDelta{Requests: 1, Failures: 1}) {
		t.Fatalf("precommit usage=%+v", *f.usage)
	}
	if len(client.requests) != 2 || client.requests[0].Model.UpstreamName != "grok-4.5" || client.requests[1].Model.UpstreamName != "grok-4.5" {
		t.Fatalf("requests=%+v", client.requests)
	}
	if client.requests[0].Credential.Value != "token-"+(*f.usage)[0].accountID {
		t.Fatalf("failed usage account=%q credential=%q", (*f.usage)[0].accountID, client.requests[0].Credential.Value)
	}
	if _, err := stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if stream.Model() != "grok-4.5" || len(*f.usage) != 2 {
		t.Fatalf("model=%q usage=%+v", stream.Model(), *f.usage)
	}
	if (*f.usage)[0].accountID == stream.AccountID() {
		t.Fatalf("failover reused failed account: %+v", *f.usage)
	}
	want := usageRecord{accountID: stream.AccountID(), delta: LocalUsageDelta{Requests: 1, InputTokens: 29, OutputTokens: 31}}
	if (*f.usage)[1] != want {
		t.Fatalf("terminal usage=%+v, want %+v", (*f.usage)[1], want)
	}
}

func TestStreamCommittedErrorRecordsFailureOnceWithoutReplay(t *testing.T) {
	f, client := streamFixture(t, 2)
	defer f.close()
	client.steps = []streamStep{{stream: &fakeStream{events: []provider.Event{{Data: []byte("committed")}}, errs: []error{errors.New("truncated")}}}}

	stream, err := f.executor.Stream(context.Background(), Request{Model: "grok", Body: []byte(`{"model":"grok"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Next(context.Background()); err == nil {
		t.Fatal("expected committed stream failure")
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	want := usageRecord{accountID: stream.AccountID(), delta: LocalUsageDelta{Requests: 1, Failures: 1}}
	if stream.Model() != "grok-4.5" || len(client.requests) != 1 || len(*f.usage) != 1 || (*f.usage)[0] != want {
		t.Fatalf("model=%q attempts=%d usage=%+v, want [%+v]", stream.Model(), len(client.requests), *f.usage, want)
	}
}

func TestStreamUnauthorizedPrecommitRecoveryRetriesSameAccountOnceWithFreshCredential(t *testing.T) {
	f, client := streamFixture(t, 1)
	defer f.close()
	credentials := &authRecoveryCredentials{values: map[string]string{}, fresh: map[string]string{}}
	for id, token := range f.credentials.values {
		credentials.values[id] = token
		credentials.fresh[id] = "fresh-" + id
	}
	installAuthRecoveryCredentials(f, credentials, client)
	client.steps = []streamStep{
		{stream: &fakeStream{errs: []error{unauthorizedExecutionError()}}},
		{stream: &fakeStream{events: []provider.Event{{Data: []byte("fresh-event")}}}},
	}

	stream, err := f.executor.Stream(context.Background(), Request{Model: "grok", Body: []byte(`{"model":"grok"}`)})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if len(credentials.recoveryIDs) != 1 || len(credentials.credentialIDs) != 2 || credentials.credentialIDs[0] != credentials.credentialIDs[1] || credentials.recoveryIDs[0] != credentials.credentialIDs[0] {
		t.Fatalf("credential calls=%v recovery calls=%v", credentials.credentialIDs, credentials.recoveryIDs)
	}
	if len(client.requests) != 2 || client.requests[0].Credential.Value == client.requests[1].Credential.Value || client.requests[1].Credential.Value != "fresh-"+credentials.recoveryIDs[0] {
		t.Fatalf("requests=%d credentials=%q,%q", len(client.requests), client.requests[0].Credential.Value, client.requests[1].Credential.Value)
	}
	event, err := stream.Next(context.Background())
	if err != nil || string(event.Data) != "fresh-event" {
		t.Fatalf("event=%q err=%v", event.Data, err)
	}
}

func TestStreamUnauthorizedRecoveryFailureClassificationAndNoRejectedTokenResend(t *testing.T) {
	invalidGrant := &provider.UpstreamError{Provider: provider.XAI, Status: 401, Classification: provider.ErrorClassification{
		Class: provider.ClassInvalidGrant, RetryNext: true, DisableAccount: true, ReloginRequired: true,
		CooldownScope: provider.CooldownAccount, PublicStatus: 401, PublicCode: "provider_authentication_error", PublicMessage: "account requires login",
	}}
	for _, tc := range []struct {
		name      string
		recovery  error
		wantClass provider.ErrorClass
	}{
		{name: "invalid grant", recovery: invalidGrant, wantClass: provider.ClassInvalidGrant},
		{name: "generic refresh failure", recovery: errors.New("refresh transport failed"), wantClass: provider.ClassUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, client := streamFixture(t, 1)
			defer f.close()
			credentials := &authRecoveryCredentials{values: map[string]string{}, fresh: map[string]string{}, recoveryErr: tc.recovery}
			for id, token := range f.credentials.values {
				credentials.values[id] = token
			}
			installAuthRecoveryCredentials(f, credentials, client)
			client.steps = []streamStep{{stream: &fakeStream{errs: []error{unauthorizedExecutionError()}}}}

			_, err := f.executor.Stream(context.Background(), Request{Model: "grok", Body: []byte(`{"model":"grok"}`)})
			var executionErr *ExecutionError
			if !errors.As(err, &executionErr) || executionErr.Classified.Class != tc.wantClass || !executionErr.Classified.RetryNext {
				t.Fatalf("err=%v classification=%+v", err, executionErr)
			}
			if len(client.requests) != 1 || len(credentials.credentialIDs) != 1 || len(credentials.recoveryIDs) != 1 {
				t.Fatalf("requests=%d credential calls=%v recovery calls=%v", len(client.requests), credentials.credentialIDs, credentials.recoveryIDs)
			}
		})
	}
}

func TestStreamUnauthorizedRecoveryFailureFailsOverWithoutRejectedTokenResend(t *testing.T) {
	for _, tc := range []struct {
		name     string
		recovery error
	}{
		{name: "invalid grant", recovery: &provider.UpstreamError{Provider: provider.XAI, Status: 401, Classification: provider.ErrorClassification{Class: provider.ClassInvalidGrant, RetryNext: true, DisableAccount: true, ReloginRequired: true, CooldownScope: provider.CooldownAccount, PublicStatus: 401, PublicCode: "provider_authentication_error"}}},
		{name: "generic refresh failure", recovery: errors.New("refresh transport failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, client := streamFixture(t, 2)
			defer f.close()
			credentials := &authRecoveryCredentials{values: map[string]string{}, fresh: map[string]string{}, recoveryErr: tc.recovery}
			for id, token := range f.credentials.values {
				credentials.values[id] = token
			}
			installAuthRecoveryCredentials(f, credentials, client)
			client.steps = []streamStep{
				{stream: &fakeStream{errs: []error{unauthorizedExecutionError()}}},
				{stream: &fakeStream{events: []provider.Event{{Data: []byte("failover-event")}}}},
			}

			stream, err := f.executor.Stream(context.Background(), Request{Model: "grok", Body: []byte(`{"model":"grok"}`)})
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			if len(client.requests) != 2 || len(credentials.credentialIDs) != 2 || len(credentials.recoveryIDs) != 1 || credentials.credentialIDs[0] == credentials.credentialIDs[1] || credentials.recoveryIDs[0] != credentials.credentialIDs[0] {
				t.Fatalf("requests=%d credential calls=%v recovery calls=%v", len(client.requests), credentials.credentialIDs, credentials.recoveryIDs)
			}
			if client.requests[0].Credential.Value == client.requests[1].Credential.Value {
				t.Fatalf("rejected credential resent: %q", client.requests[0].Credential.Value)
			}
		})
	}
}

func TestStreamPermissionPrecommitFailureIsTerminalWithoutRecoveryOrFailover(t *testing.T) {
	f, client := streamFixture(t, 2)
	defer f.close()
	credentials := &authRecoveryCredentials{values: map[string]string{}, fresh: map[string]string{}}
	for id, token := range f.credentials.values {
		credentials.values[id] = token
	}
	installAuthRecoveryCredentials(f, credentials, client)
	client.steps = []streamStep{{stream: &fakeStream{errs: []error{permissionExecutionError()}}}}

	_, err := f.executor.Stream(context.Background(), Request{Model: "grok", Body: []byte(`{"model":"grok"}`)})
	var executionErr *ExecutionError
	if !errors.As(err, &executionErr) || executionErr.Classified.Class != provider.ClassPermission || executionErr.Classified.RetryNext || executionErr.Classified.RefreshSame || executionErr.Classified.PublicStatus != 403 || executionErr.Classified.PublicCode != "provider_permission_error" {
		t.Fatalf("err=%v classification=%+v", err, executionErr)
	}
	if len(client.requests) != 1 || len(credentials.credentialIDs) != 1 || len(credentials.recoveryIDs) != 0 {
		t.Fatalf("requests=%d credential calls=%v recovery calls=%v", len(client.requests), credentials.credentialIDs, credentials.recoveryIDs)
	}
}

// streamProtocolBodies returns three canonical body shapes for OpenAI Chat,
// OpenAI Responses, and Anthropic Messages protocols.
func streamProtocolBodies(model string) [][]byte {
	return [][]byte{
		[]byte(`{"model":"` + model + `","messages":[{"role":"user","content":"hello"}],"stream":true}`),
		[]byte(`{"model":"` + model + `","input":"hello","stream":true}`),
		[]byte(`{"model":"` + model + `","messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}],"system":"hi","stream":true}`),
	}
}

type streamMultiFixture struct {
	executor     *Executor
	xaiClient    *fakeStreamGeneration
	devinClient  *fakeStreamGeneration
	xaiCreds     *recordingCredentials
	devinCreds   *recordingCredentials
	accounts     *store.AccountRepository
	db           *sql.DB
	close        func()
	ledger       *[]string
	usage        *[]usageRecord
	xaiAccount   store.Account
	devinAccount store.Account
}

func newStreamMultiFixture(t *testing.T) *streamMultiFixture {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{51}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accountRepo := store.NewAccountRepository(db.DB, keys)
	xaiAccount, err := accountRepo.UpsertLogin(ctx, store.Account{Provider: provider.XAI, Label: "x", Status: "ready", Credentials: store.AccountCredentials{Issuer: "issuer", Subject: "stream-xai", AccessToken: "xai-token"}})
	if err != nil {
		t.Fatal(err)
	}
	devinExpiry := time.Now().Add(time.Hour)
	devinAccount, err := accountRepo.UpsertLogin(ctx, store.Account{Provider: provider.Devin, Label: "d", Status: "ready", ExpiresAt: &devinExpiry, Credentials: store.AccountCredentials{OpaqueToken: "devin-token", OpaqueTokenExpiresAt: &devinExpiry}})
	if err != nil {
		t.Fatal(err)
	}
	ledger := []string{}
	usage := []usageRecord{}
	xaiCreds := &recordingCredentials{values: map[string]string{xaiAccount.ID: "xai-token"}}
	devinCreds := &recordingCredentials{values: map[string]string{devinAccount.ID: "devin-token"}}
	xaiClient := &fakeStreamGeneration{ledger: &ledger}
	devinClient := &fakeStreamGeneration{ledger: &ledger}
	catalog := fakeCatalog{ledger: &ledger, models: staticConfiguredModels()}
	registry := fakeRegistry{ledger: &ledger, caps: map[string]provider.Capabilities{
		"xai/xai":     {Policy: ledgerPolicy{ledger: &ledger, policy: xai.RequestPolicy{}}, Generation: xaiClient, Credentials: xaiCreds},
		"devin/devin": {Policy: passthroughPolicy{}, Generation: devinClient, Credentials: devinCreds},
	}}
	states := store.NewCooldownRepository(db.DB)
	executor := newExecutor(NewScheduler(), catalog, registry, NewCooldownManager(states, accountRepo), ledgerAccounts{ledger: &ledger, repo: accountRepo}, ledgerCapabilities{ledger: &ledger, repo: store.NewModelCapabilityRepository(db.DB)}, ledgerCooldowns{ledger: &ledger, repo: states})
	executor.SetUsageRecorder(ledgerUsage{ledger: &ledger, records: &usage})
	return &streamMultiFixture{executor: executor, xaiClient: xaiClient, devinClient: devinClient, xaiCreds: xaiCreds, devinCreds: devinCreds, accounts: accountRepo, db: db.DB, close: func() { db.Close() }, ledger: &ledger, usage: &usage, xaiAccount: xaiAccount, devinAccount: devinAccount}
}

// TestStreamDispatchesAllConfiguredStaticNamesToExactProviderWithNoCrossProviderCalls
// asserts C9.3 for streaming: every configured static model and every protocol
// body shape opens exactly one stream on the resolved provider's client with
// the correct upstream name, never touches the other provider's client or
// credentials, and commits the first event from the serving provider.
func TestStreamDispatchesAllConfiguredStaticNamesToExactProviderWithNoCrossProviderCalls(t *testing.T) {
	f := newStreamMultiFixture(t)
	defer f.close()
	ctx := context.Background()
	configured := staticConfiguredModels()
	for _, name := range staticConfiguredModelNames() {
		resolved := configured[name]
		for bodyIndex, body := range streamProtocolBodies(name) {
			f.xaiClient.steps = []streamStep{{stream: &fakeStream{events: []provider.Event{{Event: "response.completed", Data: []byte(`{"type":"response.completed"}`)}}}}}
			f.devinClient.steps = []streamStep{{stream: &fakeStream{events: []provider.Event{{Event: "response.completed", Data: []byte(`{"type":"response.completed"}`)}}}}}
			f.xaiClient.requests = nil
			f.devinClient.requests = nil
			f.xaiCreds.credentialIDs = nil
			f.devinCreds.credentialIDs = nil
			original := bytes.Clone(body)
			stream, err := f.executor.Stream(ctx, Request{Model: name, Body: body})
			if err != nil {
				t.Fatalf("model=%s body=%d err=%v", name, bodyIndex, err)
			}
			if stream.Model() != resolved.UpstreamName {
				t.Fatalf("model=%s body=%d upstream=%q want=%q", name, bodyIndex, stream.Model(), resolved.UpstreamName)
			}
			if !bytes.Equal(body, original) {
				t.Fatalf("model=%s body=%d mutated: %s", name, bodyIndex, body)
			}
			var servedClient, wrongClient *fakeStreamGeneration
			var servedCreds, wrongCreds *recordingCredentials
			var servedAccount store.Account
			if resolved.Provider == provider.XAI {
				servedClient, wrongClient = f.xaiClient, f.devinClient
				servedCreds, wrongCreds = f.xaiCreds, f.devinCreds
				servedAccount = f.xaiAccount
			} else {
				servedClient, wrongClient = f.devinClient, f.xaiClient
				servedCreds, wrongCreds = f.devinCreds, f.xaiCreds
				servedAccount = f.devinAccount
			}
			if len(servedClient.requests) != 1 {
				t.Fatalf("model=%s body=%d served client requests=%d", name, bodyIndex, len(servedClient.requests))
			}
			if len(wrongClient.requests) != 0 {
				t.Fatalf("model=%s body=%d cross-provider client calls=%d", name, bodyIndex, len(wrongClient.requests))
			}
			if servedClient.requests[0].Model.Provider != resolved.Provider || servedClient.requests[0].Model.UpstreamName != resolved.UpstreamName {
				t.Fatalf("model=%s body=%d request model=%+v", name, bodyIndex, servedClient.requests[0].Model)
			}
			if len(servedCreds.credentialIDs) != 1 || servedCreds.credentialIDs[0] != servedAccount.ID {
				t.Fatalf("model=%s body=%d served credential calls=%v", name, bodyIndex, servedCreds.credentialIDs)
			}
			if len(wrongCreds.credentialIDs) != 0 {
				t.Fatalf("model=%s body=%d cross-provider credential calls=%v", name, bodyIndex, wrongCreds.credentialIDs)
			}
			if stream.AccountID() != servedAccount.ID {
				t.Fatalf("model=%s body=%d account=%q want=%q", name, bodyIndex, stream.AccountID(), servedAccount.ID)
			}
			if err := stream.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// TestStreamManagedAffinitySkipsWrongProviderWithoutCrossProviderCredential
// asserts C9.3 managed Responses affinity for streaming: a wrong-provider
// preferred account is skipped before any credential access and dispatch falls
// back to a same-provider account with no cross-provider client or credential.
func TestStreamManagedAffinitySkipsWrongProviderWithoutCrossProviderCredential(t *testing.T) {
	for _, tc := range []struct {
		name         string
		model        string
		preferredXAI bool
		wantProvider provider.Kind
	}{
		{name: "xAI model with Devin preferred", model: "grok-4.5", preferredXAI: false, wantProvider: provider.XAI},
		{name: "Devin model with xAI preferred", model: "glm", preferredXAI: true, wantProvider: provider.Devin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newStreamMultiFixture(t)
			defer f.close()
			ctx := context.Background()
			preferred := f.devinAccount.ID
			var wantAccount store.Account
			var wantClient, wrongClient *fakeStreamGeneration
			var wantCreds, wrongCreds *recordingCredentials
			if tc.preferredXAI {
				preferred = f.xaiAccount.ID
			}
			if tc.wantProvider == provider.XAI {
				wantAccount = f.xaiAccount
				wantClient, wrongClient = f.xaiClient, f.devinClient
				wantCreds, wrongCreds = f.xaiCreds, f.devinCreds
			} else {
				wantAccount = f.devinAccount
				wantClient, wrongClient = f.devinClient, f.xaiClient
				wantCreds, wrongCreds = f.devinCreds, f.xaiCreds
			}
			wantClient.steps = []streamStep{{stream: &fakeStream{events: []provider.Event{{Event: "response.completed", Data: []byte(`{"type":"response.completed"}`)}}}}}
			stream, err := f.executor.Stream(ctx, Request{Model: tc.model, Body: []byte(`{"model":"` + tc.model + `","stream":true}`), PreferredAccountID: preferred})
			if err != nil {
				t.Fatalf("err=%v", err)
			}
			defer stream.Close()
			if stream.AccountID() != wantAccount.ID {
				t.Fatalf("account=%q want=%q (preferred=%q)", stream.AccountID(), wantAccount.ID, preferred)
			}
			if len(wantClient.requests) != 1 || len(wrongClient.requests) != 0 {
				t.Fatalf("client calls served=%d wrong=%d", len(wantClient.requests), len(wrongClient.requests))
			}
			if len(wantCreds.credentialIDs) != 1 || wantCreds.credentialIDs[0] != wantAccount.ID {
				t.Fatalf("served credential calls=%v", wantCreds.credentialIDs)
			}
			if len(wrongCreds.credentialIDs) != 0 {
				t.Fatalf("cross-provider credential calls=%v", wrongCreds.credentialIDs)
			}
		})
	}
}

// TestStreamDevinUnauthorizedPrecommitRecoveryPersistsReloginAndFailsOver
// asserts C9.4 for streaming: a Devin 401/403 pre-commit triggers
// AuthenticationFailed (persisting relogin), then fails over to another Devin
// account without resending the rejected token, and never crosses to xAI.
func TestStreamDevinUnauthorizedPrecommitRecoveryPersistsReloginAndFailsOver(t *testing.T) {
	ctx := context.Background()
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(fmt.Sprintf("status=%d", status), func(t *testing.T) {
			db, err := store.Open(ctx, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{52}, 32))
			if err != nil {
				t.Fatal(err)
			}
			accountRepo := store.NewAccountRepository(db.DB, keys)
			expiry := time.Now().Add(time.Hour)
			first, err := accountRepo.UpsertLogin(ctx, store.Account{Provider: provider.Devin, Label: "d1", Status: "ready", ExpiresAt: &expiry, Credentials: store.AccountCredentials{OpaqueToken: "devin-one", OpaqueTokenExpiresAt: &expiry}})
			if err != nil {
				t.Fatal(err)
			}
			second, err := accountRepo.UpsertLogin(ctx, store.Account{Provider: provider.Devin, Label: "d2", Status: "ready", ExpiresAt: &expiry, Credentials: store.AccountCredentials{OpaqueToken: "devin-two", OpaqueTokenExpiresAt: &expiry}})
			if err != nil {
				t.Fatal(err)
			}
			ledger := []string{}
			usage := []usageRecord{}
			creds := &recordingCredentials{values: map[string]string{first.ID: "devin-one", second.ID: "devin-two"}, recoveryErr: &provider.UpstreamError{Provider: provider.Devin, Status: status, Classification: provider.ErrorClassification{Class: provider.ClassUnauthorized, RetryNext: true, DisableAccount: true, ReloginRequired: true, CooldownScope: provider.CooldownAccount, PublicStatus: http.StatusUnauthorized, PublicCode: "provider_authentication_error", PublicMessage: "account requires login"}}}
			client := &fakeStreamGeneration{ledger: &ledger}
			catalog := fakeCatalog{ledger: &ledger, models: staticConfiguredModels()}
			registry := fakeRegistry{ledger: &ledger, caps: map[string]provider.Capabilities{
				"devin/devin": {Policy: passthroughPolicy{}, Generation: client, Credentials: creds},
			}}
			states := store.NewCooldownRepository(db.DB)
			executor := newExecutor(NewScheduler(), catalog, registry, NewCooldownManager(states, accountRepo), ledgerAccounts{ledger: &ledger, repo: accountRepo}, ledgerCapabilities{ledger: &ledger, repo: store.NewModelCapabilityRepository(db.DB)}, ledgerCooldowns{ledger: &ledger, repo: states})
			executor.SetUsageRecorder(ledgerUsage{ledger: &ledger, records: &usage})
			client.steps = []streamStep{
				{stream: &fakeStream{errs: []error{&provider.UpstreamError{Provider: provider.Devin, Status: status, Classification: provider.ErrorClassification{Class: provider.ClassUnauthorized, RefreshSame: true, RetryNext: true, CooldownScope: provider.CooldownAccount, PublicStatus: status, PublicCode: "provider_authentication_error"}}}}},
				{stream: &fakeStream{events: []provider.Event{{Data: []byte("failover-event")}}}},
			}
			stream, err := executor.Stream(ctx, Request{Model: "glm", Body: []byte(`{"model":"glm","stream":true}`), PreferredAccountID: first.ID})
			if err != nil {
				t.Fatalf("err=%v", err)
			}
			defer stream.Close()
			if len(creds.recoveryIDs) != 1 || creds.recoveryIDs[0] != first.ID {
				t.Fatalf("recovery calls=%v, want first account %q", creds.recoveryIDs, first.ID)
			}
			if len(client.requests) != 2 || client.requests[0].Credential.Value == client.requests[1].Credential.Value {
				t.Fatalf("requests=%d credentials=%q,%q", len(client.requests), client.requests[0].Credential.Value, client.requests[1].Credential.Value)
			}
			if stream.AccountID() != second.ID {
				t.Fatalf("account=%q want failover to %q", stream.AccountID(), second.ID)
			}
			storedFirst, err := accountRepo.Get(ctx, first.ID)
			if err != nil {
				t.Fatal(err)
			}
			if storedFirst.Status != "relogin_required" || storedFirst.Enabled {
				t.Fatalf("first account not marked relogin: status=%q enabled=%v", storedFirst.Status, storedFirst.Enabled)
			}
		})
	}
}

// TestStreamDevinPrecommitFailoverRecordsEachAttemptOnceAndStaysProviderLocal
// asserts C9.4 for streaming: a Devin pre-commit transient failure records one
// failed local usage row, fails over to another Devin account, records the
// terminal usage once, and never crosses to xAI.
func TestStreamDevinPrecommitFailoverRecordsEachAttemptOnceAndStaysProviderLocal(t *testing.T) {
	f := newStreamMultiFixture(t)
	defer f.close()
	ctx := context.Background()
	secondExpiry := time.Now().Add(time.Hour)
	second, err := f.accounts.UpsertLogin(ctx, store.Account{Provider: provider.Devin, Label: "d2", Status: "ready", ExpiresAt: &secondExpiry, Credentials: store.AccountCredentials{OpaqueToken: "devin-second", OpaqueTokenExpiresAt: &secondExpiry}})
	if err != nil {
		t.Fatal(err)
	}
	f.devinCreds.values[second.ID] = "devin-second"
	f.devinClient.steps = []streamStep{
		{stream: &fakeStream{errs: []error{&provider.UpstreamError{Provider: provider.Devin, Status: 503, Classification: provider.ErrorClassification{Class: provider.ClassTransient, RetryNext: true}}}}},
		{stream: &fakeStream{events: []provider.Event{{Event: "response.completed", Usage: provider.Usage{InputTokens: 37, OutputTokens: 41}}}}},
	}
	stream, err := f.executor.Stream(ctx, Request{Model: "glm-5-2", Body: []byte(`{"model":"glm-5-2","stream":true}`)})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if len(*f.usage) != 1 || (*f.usage)[0].delta != (LocalUsageDelta{Requests: 1, Failures: 1}) {
		t.Fatalf("precommit usage=%+v", *f.usage)
	}
	if len(f.devinClient.requests) != 2 || len(f.xaiClient.requests) != 0 {
		t.Fatalf("devin requests=%d xai requests=%d", len(f.devinClient.requests), len(f.xaiClient.requests))
	}
	for _, r := range f.devinClient.requests {
		if r.Model.Provider != provider.Devin {
			t.Fatalf("cross-provider stream attempt: %+v", r.Model)
		}
	}
	if _, err := stream.Next(ctx); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if stream.Model() != "glm-5-2" || len(*f.usage) != 2 {
		t.Fatalf("model=%q usage=%+v", stream.Model(), *f.usage)
	}
	if (*f.usage)[0].accountID == stream.AccountID() {
		t.Fatalf("failover reused failed account: %+v", *f.usage)
	}
	want := usageRecord{accountID: stream.AccountID(), delta: LocalUsageDelta{Requests: 1, InputTokens: 37, OutputTokens: 41}}
	if (*f.usage)[1] != want {
		t.Fatalf("terminal usage=%+v, want %+v", (*f.usage)[1], want)
	}
}

// TestStreamDevinCommittedErrorRecordsFailureOnceWithoutReplay asserts C9.4 for
// streaming: once a Devin stream has committed (emitted its first event), a
// later upstream error records exactly one failure usage row and never opens a
// second stream on any provider.
func TestStreamDevinCommittedErrorRecordsFailureOnceWithoutReplay(t *testing.T) {
	f := newStreamMultiFixture(t)
	defer f.close()
	f.devinClient.steps = []streamStep{{stream: &fakeStream{events: []provider.Event{{Data: []byte("committed")}}, errs: []error{errors.New("truncated")}}}}
	stream, err := f.executor.Stream(context.Background(), Request{Model: "glm", Body: []byte(`{"model":"glm","stream":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Next(context.Background()); err == nil {
		t.Fatal("expected committed stream failure")
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	want := usageRecord{accountID: stream.AccountID(), delta: LocalUsageDelta{Requests: 1, Failures: 1}}
	if stream.Model() != "glm-5-2" || len(f.devinClient.requests) != 1 || len(f.xaiClient.requests) != 0 || len(*f.usage) != 1 || (*f.usage)[0] != want {
		t.Fatalf("model=%q devinAttempts=%d xaiAttempts=%d usage=%+v, want [%+v]", stream.Model(), len(f.devinClient.requests), len(f.xaiClient.requests), *f.usage, want)
	}
}

// TestStreamDevinTerminalUsageRecordedExactlyOnce asserts C9.4 for streaming:
// a successful Devin stream records exactly one terminal usage row attributed
// to the serving Devin account.
func TestStreamDevinTerminalUsageRecordedExactlyOnce(t *testing.T) {
	f := newStreamMultiFixture(t)
	defer f.close()
	f.devinClient.steps = []streamStep{{stream: &fakeStream{events: []provider.Event{{Event: "response.completed", Usage: provider.Usage{InputTokens: 53, OutputTokens: 61}}}}}}
	stream, err := f.executor.Stream(context.Background(), Request{Model: "swe", Body: []byte(`{"model":"swe","stream":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if stream.Model() != "swe-1-7" || !stream.Committed() {
		t.Fatalf("model=%q committed=%v", stream.Model(), stream.Committed())
	}
	want := usageRecord{accountID: stream.AccountID(), delta: LocalUsageDelta{Requests: 1, InputTokens: 53, OutputTokens: 61}}
	if len(*f.usage) != 1 || (*f.usage)[0] != want {
		t.Fatalf("usage=%+v, want [%+v]", *f.usage, want)
	}
}
