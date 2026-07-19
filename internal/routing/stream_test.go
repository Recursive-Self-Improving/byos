package routing

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"byos/internal/provider"
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
	}{
		{name: "normal completion", eventType: "response.completed", data: []byte(`{"type":"response.completed","response":{"usage":{"input_tokens":11,"output_tokens":13}}}`), input: 11, output: 13},
		{name: "incomplete response", eventType: "response.incomplete", data: []byte(`{"type":"response.incomplete","response":{"usage":{"input_tokens":17,"output_tokens":19}}}`), input: 17, output: 19},
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
			want := usageRecord{accountID: stream.AccountID(), delta: LocalUsageDelta{Requests: 1, InputTokens: test.input, OutputTokens: test.output}}
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
