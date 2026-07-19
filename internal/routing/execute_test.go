package routing

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	appcrypto "byos/internal/crypto"
	"byos/internal/provider"
	"byos/internal/store"
	"byos/internal/xai"
)

type fakeCatalog struct {
	ledger *[]string
	models map[string]provider.ResolvedModel
}

func (f fakeCatalog) Resolve(name string) (provider.ResolvedModel, error) {
	*f.ledger = append(*f.ledger, "resolve")
	m, ok := f.models[name]
	if !ok {
		return provider.ResolvedModel{}, fmt.Errorf("%w: secret catalog detail", provider.ErrUnknownModel)
	}
	return m, nil
}

type fakeRegistry struct {
	ledger *[]string
	caps   map[string]provider.Capabilities
}

func (f fakeRegistry) Capabilities(kind provider.Kind, key string) (provider.Capabilities, bool) {
	*f.ledger = append(*f.ledger, "capabilities")
	c, ok := f.caps[kind.String()+"/"+key]
	return c, ok
}

type fakePolicy struct {
	ledger *[]string
	seen   provider.CanonicalRequest
}

func (f *fakePolicy) Prepare(_ context.Context, _ provider.ResolvedModel, canonical provider.CanonicalRequest) error {
	*f.ledger = append(*f.ledger, "policy")
	f.seen = cloneCanonical(canonical)
	canonical["policy_applied"] = true
	return nil
}

func cloneCanonical(canonical provider.CanonicalRequest) provider.CanonicalRequest {
	cloned := make(provider.CanonicalRequest, len(canonical))
	for key, value := range canonical {
		cloned[key] = value
	}
	return cloned
}

type ledgerPolicy struct {
	ledger *[]string
	policy provider.RequestPolicy
}

func (p ledgerPolicy) Prepare(ctx context.Context, model provider.ResolvedModel, canonical provider.CanonicalRequest) error {
	*p.ledger = append(*p.ledger, "policy")
	return p.policy.Prepare(ctx, model, canonical)
}

type fakeCredentials struct {
	ledger *[]string
	values map[string]string
	calls  []string
}

func (f *fakeCredentials) Credential(_ context.Context, id string) (provider.Credential, error) {
	*f.ledger = append(*f.ledger, "credential")
	f.calls = append(f.calls, id)
	return provider.Credential{Value: f.values[id]}, nil
}
func (f *fakeCredentials) AuthenticationFailed(context.Context, string, *provider.UpstreamError) error {
	return nil
}
func (f *fakeCredentials) CredentialUsable(_ context.Context, id string) (bool, error) {
	*f.ledger = append(*f.ledger, "credential-usable")
	return f.values[id] != "", nil
}

type ledgerAccounts struct {
	ledger *[]string
	repo   *store.AccountRepository
}

func (s ledgerAccounts) List(ctx context.Context) ([]store.Account, error) {
	*s.ledger = append(*s.ledger, "account-list")
	return s.repo.List(ctx)
}

func (s ledgerAccounts) Get(ctx context.Context, id string) (store.Account, error) {
	*s.ledger = append(*s.ledger, "account-get")
	return s.repo.Get(ctx, id)
}

type ledgerCapabilities struct {
	ledger *[]string
	repo   *store.ModelCapabilityRepository
}

func (s ledgerCapabilities) List(ctx context.Context, accountID string) ([]store.ModelCapability, error) {
	*s.ledger = append(*s.ledger, "capability-list")
	return s.repo.List(ctx, accountID)
}

type ledgerCooldowns struct {
	ledger *[]string
	repo   *store.CooldownRepository
}

func (s ledgerCooldowns) Get(ctx context.Context, accountID, model string, now time.Time) (store.Cooldown, error) {
	*s.ledger = append(*s.ledger, "cooldown-get")
	return s.repo.Get(ctx, accountID, model, now)
}

type usageRecord struct {
	accountID string
	delta     LocalUsageDelta
}

type ledgerUsage struct {
	ledger  *[]string
	records *[]usageRecord
}

func (u ledgerUsage) Record(_ context.Context, accountID string, delta LocalUsageDelta) error {
	*u.ledger = append(*u.ledger, "usage")
	*u.records = append(*u.records, usageRecord{accountID: accountID, delta: delta})
	return nil
}

func requireLedger(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("ledger=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ledger=%v, want %v", got, want)
		}
	}
}

type executeStep struct {
	events []provider.Event
	err    error
}
type fakeGeneration struct {
	mu       sync.Mutex
	ledger   *[]string
	steps    []executeStep
	requests []provider.GenerationRequest
}

func (f *fakeGeneration) Execute(_ context.Context, r provider.GenerationRequest) ([]provider.Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	*f.ledger = append(*f.ledger, "client")
	r.Canonical = cloneCanonical(r.Canonical)
	f.requests = append(f.requests, r)
	s := f.steps[0]
	f.steps = f.steps[1:]
	return s.events, s.err
}
func (f *fakeGeneration) Stream(context.Context, provider.GenerationRequest) (provider.Stream, error) {
	panic("unexpected stream")
}

type executionFixture struct {
	executor    *Executor
	client      *fakeGeneration
	credentials *fakeCredentials
	policy      *fakePolicy
	accounts    *store.AccountRepository
	db          *sql.DB
	close       func()
	ledger      *[]string
	usage       *[]usageRecord
}

func newExecutionFixture(t *testing.T, count int) *executionFixture {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accounts := store.NewAccountRepository(db.DB, keys)
	ledger := []string{}
	usage := []usageRecord{}
	credentials := &fakeCredentials{ledger: &ledger, values: map[string]string{}}
	for i := range count {
		a, err := accounts.UpsertLogin(ctx, store.Account{Provider: provider.XAI, Label: "x", Status: "ready", Credentials: store.AccountCredentials{Issuer: "issuer", Subject: string(rune('a' + i)), AccessToken: "token"}})
		if err != nil {
			t.Fatal(err)
		}
		credentials.values[a.ID] = "token-" + a.ID
	}
	states := store.NewCooldownRepository(db.DB)
	cooldowns := NewCooldownManager(states, accounts)
	policy := &fakePolicy{ledger: &ledger}
	client := &fakeGeneration{ledger: &ledger}
	resolved := provider.ResolvedModel{PublicName: "grok", UpstreamName: "grok-4.5", Provider: provider.XAI, OwnedBy: "xai", PolicyKey: "xai"}
	catalog := fakeCatalog{ledger: &ledger, models: map[string]provider.ResolvedModel{"grok": resolved}}
	registry := fakeRegistry{ledger: &ledger, caps: map[string]provider.Capabilities{"xai/xai": {Policy: policy, Generation: client, Credentials: credentials}}}
	executor := newExecutor(NewScheduler(), catalog, registry, cooldowns, ledgerAccounts{ledger: &ledger, repo: accounts}, ledgerCapabilities{ledger: &ledger, repo: store.NewModelCapabilityRepository(db.DB)}, ledgerCooldowns{ledger: &ledger, repo: states})
	executor.SetUsageRecorder(ledgerUsage{ledger: &ledger, records: &usage})
	return &executionFixture{executor: executor, client: client, credentials: credentials, policy: policy, accounts: accounts, db: db.DB, close: func() { db.Close() }, ledger: &ledger, usage: &usage}
}

func (f *executionFixture) cooldownRows(t *testing.T) int {
	t.Helper()
	var count int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM account_model_states`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestExecutePreparationOrderAndBodyOwnership(t *testing.T) {
	f := newExecutionFixture(t, 1)
	defer f.close()
	f.client.steps = []executeStep{{events: []provider.Event{{Data: []byte(`{"type":"response.completed"}`)}}}}
	input := []byte(`{"model":"grok","input":"<hello>","large":9007199254740993}`)
	original := bytes.Clone(input)
	_, err := f.executor.Execute(context.Background(), Request{Model: "grok", Body: input})
	if err != nil {
		t.Fatal(err)
	}
	requireLedger(t, *f.ledger, "resolve", "capabilities", "policy", "account-list", "credential-usable", "capability-list", "cooldown-get", "cooldown-get", "account-get", "credential", "client", "usage")
	if !bytes.Equal(input, original) || f.policy.seen["model"] != "grok" || f.policy.seen["large"] != json.Number("9007199254740993") || f.policy.seen["input"] != "<hello>" {
		t.Fatalf("policy canonical=%#v input=%s", f.policy.seen, input)
	}
	request := f.client.requests[0]
	if request.Model.PublicName != "grok" || request.Model.UpstreamName != "grok-4.5" || request.Canonical["model"] != "grok-4.5" || request.Canonical["large"] != json.Number("9007199254740993") || request.Canonical["input"] != "<hello>" || request.Canonical["policy_applied"] != true {
		t.Fatalf("request=%+v canonical=%#v", request, request.Canonical)
	}
}

func TestExecuteRejectsDuplicateSearchBeforeBodyOrDownstreamAccess(t *testing.T) {
	f := newExecutionFixture(t, 1)
	defer f.close()
	resolved := provider.ResolvedModel{PublicName: "grok", UpstreamName: "grok-4.5", Provider: provider.XAI, PolicyKey: "xai"}
	f.executor.registry = fakeRegistry{ledger: f.ledger, caps: map[string]provider.Capabilities{"xai/xai": {Policy: ledgerPolicy{ledger: f.ledger, policy: xai.RequestPolicy{}}, Generation: f.client, Credentials: f.credentials}}}
	f.executor.catalog = fakeCatalog{ledger: f.ledger, models: map[string]provider.ResolvedModel{"grok": resolved}}
	for _, body := range [][]byte{[]byte(`{"model":"grok","input":"hello","tools":[{"type":"x_search"},{"type":"x_search"}]}`), []byte(`{"model":"grok","messages":[{"role":"user","content":"hello"}],"tools":[{"type":"x_search"},{"type":"x_search"}]}`)} {
		original := bytes.Clone(body)
		cooldownsBefore := f.cooldownRows(t)
		_, err := f.executor.Execute(context.Background(), Request{Model: "grok", Body: body})
		var upstream *provider.UpstreamError
		if !errors.As(err, &upstream) || upstream.Classification.Class != provider.ClassValidation || upstream.Classification.PublicStatus != 400 || upstream.Classification.PublicCode != "invalid_request_error" || upstream.Classification.PublicMessage != "invalid request" {
			t.Fatalf("error=%#v", err)
		}
		requireLedger(t, *f.ledger, "resolve", "capabilities", "policy")
		if !bytes.Equal(body, original) || len(f.credentials.calls) != 0 || len(f.client.requests) != 0 || f.cooldownRows(t) != cooldownsBefore {
			t.Fatalf("speculative side effects: body=%s credentials=%v requests=%d cooldowns=%d", body, f.credentials.calls, len(f.client.requests), f.cooldownRows(t))
		}
		*f.ledger = nil
	}
}
func TestExecuteRejectsUnknownAndMissingCapabilityBeforeMutation(t *testing.T) {
	f := newExecutionFixture(t, 1)
	defer f.close()
	input := []byte(" { \"model\" : \"unknown\" } ")
	original := bytes.Clone(input)
	_, err := f.executor.Execute(context.Background(), Request{Model: "unknown", Body: input})
	if !errors.Is(err, ErrModelUnavailable) {
		t.Fatalf("err=%v", err)
	}
	requireLedger(t, *f.ledger, "resolve")
	if !bytes.Equal(input, original) || len(f.credentials.calls) != 0 || len(f.client.requests) != 0 {
		t.Fatalf("speculative side effects: body=%s credentials=%v requests=%d", input, f.credentials.calls, len(f.client.requests))
	}
	*f.ledger = nil
	resolved := provider.ResolvedModel{PublicName: "devin", UpstreamName: "devin", Provider: provider.Devin, PolicyKey: "devin"}
	f.executor.catalog = fakeCatalog{ledger: f.ledger, models: map[string]provider.ResolvedModel{"devin": resolved}}
	_, err = f.executor.Execute(context.Background(), Request{Model: "devin", Body: input})
	if !errors.Is(err, ErrModelUnavailable) {
		t.Fatalf("err=%v", err)
	}
	requireLedger(t, *f.ledger, "resolve", "capabilities")
	if !bytes.Equal(input, original) || len(f.credentials.calls) != 0 || len(f.client.requests) != 0 {
		t.Fatalf("speculative side effects: body=%s credentials=%v requests=%d", input, f.credentials.calls, len(f.client.requests))
	}
}

func TestExecuteFiltersWrongProviderBeforeCredentialAndFailover(t *testing.T) {
	f := newExecutionFixture(t, 2)
	defer f.close()
	ctx := context.Background()
	wrong, err := f.accounts.UpsertLogin(ctx, store.Account{Provider: provider.Devin, Label: "d", Status: "ready", Credentials: store.AccountCredentials{OpaqueToken: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	f.client.steps = []executeStep{{err: &provider.UpstreamError{Provider: provider.XAI, Status: 503, Classification: provider.ErrorClassification{Class: provider.ClassTransient, RetryNext: true, CooldownScope: provider.CooldownModel, Cooldown: time.Minute}}}, {events: []provider.Event{{Data: []byte(`{"type":"response.completed"}`)}}}}
	result, err := f.executor.Execute(ctx, Request{Model: "grok", Body: []byte(`{"model":"grok"}`), PreferredAccountID: wrong.ID})
	if err != nil {
		t.Fatal(err)
	}
	if result.AccountID == wrong.ID {
		t.Fatal("cross-provider affinity selected")
	}
	for _, id := range f.credentials.calls {
		if id == wrong.ID {
			t.Fatal("wrong-provider credential accessed")
		}
	}
	for _, request := range f.client.requests {
		if request.Model.Provider != provider.XAI {
			t.Fatal("failover crossed providers")
		}
	}
}

func TestExecuteManagedAffinityEligibility(t *testing.T) {
	t.Run("same-provider preferred retained", func(t *testing.T) {
		f := newExecutionFixture(t, 2)
		defer f.close()
		accounts, err := f.accounts.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		preferred := accounts[1].ID
		f.client.steps = []executeStep{{events: []provider.Event{{Data: []byte(`{"type":"response.completed"}`)}}}}
		result, err := f.executor.Execute(context.Background(), Request{Model: "grok", Body: []byte(`{"model":"grok"}`), PreferredAccountID: preferred})
		if err != nil {
			t.Fatal(err)
		}
		if result.AccountID != preferred || len(f.credentials.calls) != 1 || f.credentials.calls[0] != preferred {
			t.Fatalf("result=%+v credential calls=%v", result, f.credentials.calls)
		}
	})

	for _, state := range []string{"deleted", "disabled", "cooled"} {
		t.Run(state+" preferred skipped", func(t *testing.T) {
			f := newExecutionFixture(t, 2)
			defer f.close()
			ctx := context.Background()
			accounts, err := f.accounts.List(ctx)
			if err != nil {
				t.Fatal(err)
			}
			preferred := accounts[0].ID
			switch state {
			case "deleted":
				err = f.accounts.Delete(ctx, preferred)
			case "disabled":
				err = f.accounts.Update(ctx, preferred, accounts[0].Label, false)
			case "cooled":
				err = f.executor.cooldowns.Apply(ctx, preferred, "grok-4.5", provider.ErrorClassification{Class: provider.ClassTransient, CooldownScope: provider.CooldownModel, Cooldown: time.Hour})
			}
			if err != nil {
				t.Fatal(err)
			}
			f.client.steps = []executeStep{{events: []provider.Event{{Data: []byte(`{"type":"response.completed"}`)}}}}
			result, err := f.executor.Execute(ctx, Request{Model: "grok", Body: []byte(`{"model":"grok"}`), PreferredAccountID: preferred})
			if err != nil {
				t.Fatal(err)
			}
			if result.AccountID == preferred {
				t.Fatalf("ineligible preferred account selected: %+v", result)
			}
			for _, id := range f.credentials.calls {
				if id == preferred {
					t.Fatalf("ineligible preferred credential accessed: %v", f.credentials.calls)
				}
			}
		})
	}
}

func TestExecuteRecordsTerminalUsageExactlyOnce(t *testing.T) {
	f := newExecutionFixture(t, 1)
	defer f.close()
	f.client.steps = []executeStep{{events: []provider.Event{
		{Event: "response.output_text.delta", Data: []byte(`{"type":"response.output_text.delta"}`)},
		{Event: "response.completed", Data: []byte(`{"type":"response.completed","response":{"usage":{"input_tokens":17,"output_tokens":23}}}`)},
	}}}

	result, err := f.executor.Execute(context.Background(), Request{Model: "grok", Body: []byte(`{"model":"grok"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if result.Model != "grok-4.5" {
		t.Fatalf("model=%q", result.Model)
	}
	if len(*f.usage) != 1 {
		t.Fatalf("usage records=%+v", *f.usage)
	}
	want := usageRecord{accountID: result.AccountID, delta: LocalUsageDelta{Requests: 1, InputTokens: 17, OutputTokens: 23}}
	if (*f.usage)[0] != want {
		t.Fatalf("usage=%+v, want %+v", (*f.usage)[0], want)
	}
}

type authRecoveryCredentials struct {
	values        map[string]string
	fresh         map[string]string
	recoveryErr   error
	credentialIDs []string
	recoveryIDs   []string
}

func (c *authRecoveryCredentials) Credential(_ context.Context, id string) (provider.Credential, error) {
	c.credentialIDs = append(c.credentialIDs, id)
	return provider.Credential{Value: c.values[id]}, nil
}

func (c *authRecoveryCredentials) AuthenticationFailed(_ context.Context, id string, _ *provider.UpstreamError) error {
	c.recoveryIDs = append(c.recoveryIDs, id)
	if c.recoveryErr == nil {
		c.values[id] = c.fresh[id]
	}
	return c.recoveryErr
}

func (c *authRecoveryCredentials) CredentialUsable(_ context.Context, id string) (bool, error) {
	return c.values[id] != "", nil
}

func unauthorizedExecutionError() error {
	return &provider.UpstreamError{Provider: provider.XAI, Status: 401, Classification: provider.ErrorClassification{
		Class: provider.ClassUnauthorized, RefreshSame: true, RetryNext: true,
		CooldownScope: provider.CooldownAccount, PublicStatus: 401, PublicCode: "provider_authentication_error",
	}}
}

func permissionExecutionError() error {
	return &provider.UpstreamError{Provider: provider.XAI, Status: 403, Classification: provider.ErrorClassification{
		Class: provider.ClassPermission, CooldownScope: provider.CooldownAccount,
		PublicStatus: 403, PublicCode: "provider_permission_error",
	}}
}

func installAuthRecoveryCredentials(f *executionFixture, credentials *authRecoveryCredentials, generation provider.GenerationClient) {
	caps, _ := f.executor.registry.Capabilities(provider.XAI, "xai")
	caps.Credentials = credentials
	caps.Generation = generation
	f.executor.registry = fakeRegistry{ledger: f.ledger, caps: map[string]provider.Capabilities{"xai/xai": caps}}
}

func TestExecuteUnauthorizedRecoveryRetriesSameAccountOnceWithFreshCredential(t *testing.T) {
	f := newExecutionFixture(t, 1)
	defer f.close()
	credentials := &authRecoveryCredentials{values: map[string]string{}, fresh: map[string]string{}}
	for id, token := range f.credentials.values {
		credentials.values[id] = token
		credentials.fresh[id] = "fresh-" + id
	}
	installAuthRecoveryCredentials(f, credentials, f.client)
	f.client.steps = []executeStep{{err: unauthorizedExecutionError()}, {events: []provider.Event{{Data: []byte(`{"type":"response.completed"}`)}}}}

	result, err := f.executor.Execute(context.Background(), Request{Model: "grok", Body: []byte(`{"model":"grok"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials.recoveryIDs) != 1 || len(credentials.credentialIDs) != 2 || credentials.recoveryIDs[0] != result.AccountID || credentials.credentialIDs[0] != result.AccountID || credentials.credentialIDs[1] != result.AccountID {
		t.Fatalf("account=%q credential calls=%v recovery calls=%v", result.AccountID, credentials.credentialIDs, credentials.recoveryIDs)
	}
	if len(f.client.requests) != 2 || f.client.requests[0].Credential.Value == f.client.requests[1].Credential.Value || f.client.requests[1].Credential.Value != "fresh-"+result.AccountID {
		t.Fatalf("requests=%d credentials=%q,%q", len(f.client.requests), f.client.requests[0].Credential.Value, f.client.requests[1].Credential.Value)
	}
}

func TestExecuteUnauthorizedRecoveryFailureNeverResendsRejectedCredential(t *testing.T) {
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
			f := newExecutionFixture(t, 1)
			defer f.close()
			credentials := &authRecoveryCredentials{values: map[string]string{}, fresh: map[string]string{}, recoveryErr: tc.recovery}
			for id, token := range f.credentials.values {
				credentials.values[id] = token
			}
			installAuthRecoveryCredentials(f, credentials, f.client)
			f.client.steps = []executeStep{{err: unauthorizedExecutionError()}}

			_, err := f.executor.Execute(context.Background(), Request{Model: "grok", Body: []byte(`{"model":"grok"}`)})
			var executionErr *ExecutionError
			if !errors.As(err, &executionErr) || executionErr.Classified.Class != tc.wantClass || executionErr.Classified.RetryNext != true {
				t.Fatalf("err=%v classification=%+v", err, executionErr)
			}
			if len(f.client.requests) != 1 || len(credentials.credentialIDs) != 1 || len(credentials.recoveryIDs) != 1 {
				t.Fatalf("requests=%d credential calls=%v recovery calls=%v", len(f.client.requests), credentials.credentialIDs, credentials.recoveryIDs)
			}
		})
	}
}

func TestExecuteUnauthorizedRecoveryFailureFailsOverWithoutRejectedTokenResend(t *testing.T) {
	for _, recovery := range []error{
		&provider.UpstreamError{Provider: provider.XAI, Status: 401, Classification: provider.ErrorClassification{Class: provider.ClassInvalidGrant, RetryNext: true, DisableAccount: true, ReloginRequired: true, CooldownScope: provider.CooldownAccount, PublicStatus: 401, PublicCode: "provider_authentication_error"}},
		errors.New("refresh transport failed"),
	} {
		f := newExecutionFixture(t, 2)
		credentials := &authRecoveryCredentials{values: map[string]string{}, fresh: map[string]string{}, recoveryErr: recovery}
		for id, token := range f.credentials.values {
			credentials.values[id] = token
		}
		installAuthRecoveryCredentials(f, credentials, f.client)
		f.client.steps = []executeStep{{err: unauthorizedExecutionError()}, {events: []provider.Event{{Data: []byte(`{"type":"response.completed"}`)}}}}

		result, err := f.executor.Execute(context.Background(), Request{Model: "grok", Body: []byte(`{"model":"grok"}`)})
		if err != nil {
			f.close()
			t.Fatal(err)
		}
		if len(f.client.requests) != 2 || len(credentials.credentialIDs) != 2 || len(credentials.recoveryIDs) != 1 || credentials.credentialIDs[0] == credentials.credentialIDs[1] || credentials.recoveryIDs[0] != credentials.credentialIDs[0] || result.AccountID != credentials.credentialIDs[1] {
			f.close()
			t.Fatalf("account=%q requests=%d credential calls=%v recovery calls=%v", result.AccountID, len(f.client.requests), credentials.credentialIDs, credentials.recoveryIDs)
		}
		if f.client.requests[0].Credential.Value == f.client.requests[1].Credential.Value {
			f.close()
			t.Fatalf("rejected credential resent: %q", f.client.requests[0].Credential.Value)
		}
		f.close()
	}
}

func TestExecutePermissionFailureIsTerminalWithoutRecoveryOrFailover(t *testing.T) {
	f := newExecutionFixture(t, 2)
	defer f.close()
	credentials := &authRecoveryCredentials{values: map[string]string{}, fresh: map[string]string{}}
	for id, token := range f.credentials.values {
		credentials.values[id] = token
	}
	installAuthRecoveryCredentials(f, credentials, f.client)
	f.client.steps = []executeStep{{err: permissionExecutionError()}}

	_, err := f.executor.Execute(context.Background(), Request{Model: "grok", Body: []byte(`{"model":"grok"}`)})
	var executionErr *ExecutionError
	if !errors.As(err, &executionErr) || executionErr.Classified.Class != provider.ClassPermission || executionErr.Classified.RetryNext || executionErr.Classified.RefreshSame || executionErr.Classified.PublicStatus != 403 || executionErr.Classified.PublicCode != "provider_permission_error" {
		t.Fatalf("err=%v classification=%+v", err, executionErr)
	}
	if len(f.client.requests) != 1 || len(credentials.credentialIDs) != 1 || len(credentials.recoveryIDs) != 0 {
		t.Fatalf("requests=%d credential calls=%v recovery calls=%v", len(f.client.requests), credentials.credentialIDs, credentials.recoveryIDs)
	}
}
