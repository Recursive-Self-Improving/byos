package routing

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"byos/internal/config"
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
		{Event: "response.completed", Data: []byte(`{"type":"response.completed","response":{"usage":{"input_tokens":17,"output_tokens":23,"input_tokens_details":{"cached_tokens":5}}}}`)},
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
	want := usageRecord{accountID: result.AccountID, delta: LocalUsageDelta{Requests: 1, InputTokens: 17, OutputTokens: 23, CacheReadTokens: 5}}
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

// passthroughPolicy is the Devin pass-through request policy: it performs no
// canonical mutation, mirroring the production Devin policy that does not apply
// xAI-specific backend-search gating.
type passthroughPolicy struct{}

func (passthroughPolicy) Prepare(_ context.Context, _ provider.ResolvedModel, _ provider.CanonicalRequest) error {
	return nil
}

// recordingCredentials serves only accounts seeded into its values map and
// records every Credential / AuthenticationFailed / CredentialUsable call so
// tests can assert no cross-provider credential access occurred.
type recordingCredentials struct {
	values        map[string]string
	credentialIDs []string
	recoveryIDs   []string
	recoveryErr   error
}

func (c *recordingCredentials) Credential(_ context.Context, id string) (provider.Credential, error) {
	c.credentialIDs = append(c.credentialIDs, id)
	return provider.Credential{Value: c.values[id]}, nil
}

func (c *recordingCredentials) AuthenticationFailed(_ context.Context, id string, _ *provider.UpstreamError) error {
	c.recoveryIDs = append(c.recoveryIDs, id)
	if c.recoveryErr == nil && c.values[id] != "" {
		c.values[id] = "fresh-" + id
	}
	return c.recoveryErr
}

func (c *recordingCredentials) CredentialUsable(_ context.Context, id string) (bool, error) {
	return c.values[id] != "", nil
}

// staticConfiguredModels returns the fixed model identities from the default
// production configuration, keyed by public name.
func staticConfiguredModels() map[string]provider.ResolvedModel {
	entries := config.Default().Models.Entries
	configured := make(map[string]provider.ResolvedModel, len(entries))
	for _, entry := range entries {
		configured[entry.PublicName] = provider.ResolvedModel{
			PublicName: entry.PublicName, UpstreamName: entry.UpstreamName,
			Provider: provider.Kind(entry.Provider), OwnedBy: entry.OwnedBy, PolicyKey: entry.PolicyKey,
		}
	}
	return configured
}

func staticConfiguredModelNames() []string {
	entries := config.Default().Models.Entries
	names := make([]string, len(entries))
	for i, entry := range entries {
		names[i] = entry.PublicName
	}
	return names
}

type multiProviderFixture struct {
	executor     *Executor
	xaiClient    *fakeGeneration
	devinClient  *fakeGeneration
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

func newMultiProviderFixture(t *testing.T) *multiProviderFixture {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	accountRepo := store.NewAccountRepository(db.DB, keys)
	xaiAccount, err := accountRepo.UpsertLogin(ctx, store.Account{Provider: provider.XAI, Label: "x", Status: "ready", Credentials: store.AccountCredentials{Issuer: "issuer", Subject: "multi-xai", AccessToken: "xai-token"}})
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
	xaiClient := &fakeGeneration{ledger: &ledger}
	devinClient := &fakeGeneration{ledger: &ledger}
	catalog := fakeCatalog{ledger: &ledger, models: staticConfiguredModels()}
	registry := fakeRegistry{ledger: &ledger, caps: map[string]provider.Capabilities{
		"xai/xai":     {Policy: ledgerPolicy{ledger: &ledger, policy: xai.RequestPolicy{}}, Generation: xaiClient, Credentials: xaiCreds},
		"devin/devin": {Policy: passthroughPolicy{}, Generation: devinClient, Credentials: devinCreds},
	}}
	states := store.NewCooldownRepository(db.DB)
	executor := newExecutor(NewScheduler(), catalog, registry, NewCooldownManager(states, accountRepo), ledgerAccounts{ledger: &ledger, repo: accountRepo}, ledgerCapabilities{ledger: &ledger, repo: store.NewModelCapabilityRepository(db.DB)}, ledgerCooldowns{ledger: &ledger, repo: states})
	executor.SetUsageRecorder(ledgerUsage{ledger: &ledger, records: &usage})
	return &multiProviderFixture{executor: executor, xaiClient: xaiClient, devinClient: devinClient, xaiCreds: xaiCreds, devinCreds: devinCreds, accounts: accountRepo, db: db.DB, close: func() { db.Close() }, ledger: &ledger, usage: &usage, xaiAccount: xaiAccount, devinAccount: devinAccount}
}

// protocolBodies returns three canonical body shapes representing the OpenAI
// Chat, OpenAI Responses, and Anthropic Messages protocols. Routing parses each
// once and dispatches by resolved model name; the body shape must not change
// the selected provider or upstream.
func protocolBodies(model string) [][]byte {
	return [][]byte{
		[]byte(`{"model":"` + model + `","messages":[{"role":"user","content":"hello"}]}`),
		[]byte(`{"model":"` + model + `","input":"hello"}`),
		[]byte(`{"model":"` + model + `","messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}],"system":"hi"}`),
	}
}

// TestExecuteDispatchesAllConfiguredStaticNamesToExactProviderWithNoCrossProviderCalls
// asserts C9.3: for every configured static model name and every protocol body
// shape, non-stream dispatch reaches exactly the resolved provider's generation
// client and credentials with the correct upstream name, and never touches the
// other provider's client or credential manager.
func TestExecuteDispatchesAllConfiguredStaticNamesToExactProviderWithNoCrossProviderCalls(t *testing.T) {
	f := newMultiProviderFixture(t)
	defer f.close()
	ctx := context.Background()
	configured := staticConfiguredModels()
	for _, name := range staticConfiguredModelNames() {
		resolved := configured[name]
		for bodyIndex, body := range protocolBodies(name) {
			f.xaiClient.steps = []executeStep{{events: []provider.Event{{Data: []byte(`{"type":"response.completed"}`)}}}}
			f.devinClient.steps = []executeStep{{events: []provider.Event{{Data: []byte(`{"type":"response.completed"}`)}}}}
			f.xaiClient.requests = nil
			f.devinClient.requests = nil
			f.xaiCreds.credentialIDs = nil
			f.devinCreds.credentialIDs = nil
			original := bytes.Clone(body)
			result, err := f.executor.Execute(ctx, Request{Model: name, Body: body})
			if err != nil {
				t.Fatalf("model=%s body=%d err=%v", name, bodyIndex, err)
			}
			if result.Model != resolved.UpstreamName {
				t.Fatalf("model=%s body=%d upstream=%q want=%q", name, bodyIndex, result.Model, resolved.UpstreamName)
			}
			if !bytes.Equal(body, original) {
				t.Fatalf("model=%s body=%d mutated: %s", name, bodyIndex, body)
			}
			var servedClient *fakeGeneration
			var wrongClient *fakeGeneration
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
			if result.AccountID != servedAccount.ID {
				t.Fatalf("model=%s body=%d account=%q want=%q", name, bodyIndex, result.AccountID, servedAccount.ID)
			}
		}
	}
}

// TestExecuteManagedAffinitySkipsWrongProviderWithoutCrossProviderCredential
// asserts C9.3 managed Responses affinity: a preferred account of the wrong
// provider is skipped before any credential access, and dispatch falls back to
// a same-provider account with no cross-provider client or credential calls.
func TestExecuteManagedAffinitySkipsWrongProviderWithoutCrossProviderCredential(t *testing.T) {
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
			f := newMultiProviderFixture(t)
			defer f.close()
			ctx := context.Background()
			preferred := f.devinAccount.ID
			var wantAccount store.Account
			var wantClient *fakeGeneration
			var wrongClient *fakeGeneration
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
			wantClient.steps = []executeStep{{events: []provider.Event{{Data: []byte(`{"type":"response.completed"}`)}}}}
			result, err := f.executor.Execute(ctx, Request{Model: tc.model, Body: []byte(`{"model":"` + tc.model + `"}`), PreferredAccountID: preferred})
			if err != nil {
				t.Fatalf("err=%v", err)
			}
			if result.AccountID != wantAccount.ID {
				t.Fatalf("account=%q want=%q (preferred=%q)", result.AccountID, wantAccount.ID, preferred)
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

// TestExecuteDevinUnauthorizedRecoveryPersistsReloginAndFailsOver asserts C9.4:
// a Devin 401/403 with RefreshSame triggers AuthenticationFailed (persisting
// relogin), then fails over to another Devin account without resending the
// rejected token. The recovery classification must carry ReloginRequired and
// DisableAccount so the account is marked for relogin.
func TestExecuteDevinUnauthorizedRecoveryPersistsReloginAndFailsOver(t *testing.T) {
	ctx := context.Background()
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(fmt.Sprintf("status=%d", status), func(t *testing.T) {
			db, err := store.Open(ctx, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{42}, 32))
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
			client := &fakeGeneration{ledger: &ledger}
			catalog := fakeCatalog{ledger: &ledger, models: staticConfiguredModels()}
			registry := fakeRegistry{ledger: &ledger, caps: map[string]provider.Capabilities{
				"devin/devin": {Policy: passthroughPolicy{}, Generation: client, Credentials: creds},
			}}
			states := store.NewCooldownRepository(db.DB)
			executor := newExecutor(NewScheduler(), catalog, registry, NewCooldownManager(states, accountRepo), ledgerAccounts{ledger: &ledger, repo: accountRepo}, ledgerCapabilities{ledger: &ledger, repo: store.NewModelCapabilityRepository(db.DB)}, ledgerCooldowns{ledger: &ledger, repo: states})
			executor.SetUsageRecorder(ledgerUsage{ledger: &ledger, records: &usage})
			client.steps = []executeStep{
				{err: &provider.UpstreamError{Provider: provider.Devin, Status: status, Classification: provider.ErrorClassification{Class: provider.ClassUnauthorized, RefreshSame: true, RetryNext: true, CooldownScope: provider.CooldownAccount, PublicStatus: status, PublicCode: "provider_authentication_error"}}},
				{events: []provider.Event{{Data: []byte(`{"type":"response.completed"}`)}}},
			}
			result, err := executor.Execute(ctx, Request{Model: "glm", Body: []byte(`{"model":"glm"}`), PreferredAccountID: first.ID})
			if err != nil {
				t.Fatalf("err=%v", err)
			}
			if len(creds.recoveryIDs) != 1 || creds.recoveryIDs[0] != first.ID {
				t.Fatalf("recovery calls=%v, want first account %q", creds.recoveryIDs, first.ID)
			}
			if len(client.requests) != 2 || client.requests[0].Credential.Value == client.requests[1].Credential.Value {
				t.Fatalf("requests=%d credentials=%q,%q", len(client.requests), client.requests[0].Credential.Value, client.requests[1].Credential.Value)
			}
			if result.AccountID != second.ID {
				t.Fatalf("account=%q want failover to %q", result.AccountID, second.ID)
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

// TestExecuteDevinTransientFailoverAppliesModelCooldownAndStaysProviderLocal
// asserts C9.4: a Devin transient upstream error fails over to another Devin
// account, applies a model-scoped cooldown, and never crosses to xAI.
func TestExecuteDevinTransientFailoverAppliesModelCooldownAndStaysProviderLocal(t *testing.T) {
	f := newMultiProviderFixture(t)
	defer f.close()
	ctx := context.Background()
	secondExpiry := time.Now().Add(time.Hour)
	second, err := f.accounts.UpsertLogin(ctx, store.Account{Provider: provider.Devin, Label: "d2", Status: "ready", ExpiresAt: &secondExpiry, Credentials: store.AccountCredentials{OpaqueToken: "devin-second", OpaqueTokenExpiresAt: &secondExpiry}})
	if err != nil {
		t.Fatal(err)
	}
	f.devinCreds.values[second.ID] = "devin-second"
	f.devinClient.steps = []executeStep{
		{err: &provider.UpstreamError{Provider: provider.Devin, Status: 503, Classification: provider.ErrorClassification{Class: provider.ClassTransient, RetryNext: true, CooldownScope: provider.CooldownModel, Cooldown: time.Minute}}},
		{events: []provider.Event{{Data: []byte(`{"type":"response.completed"}`)}}},
	}
	result, err := f.executor.Execute(ctx, Request{Model: "glm-5-2", Body: []byte(`{"model":"glm-5-2"}`), PreferredAccountID: f.devinAccount.ID})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if result.AccountID == f.devinAccount.ID {
		t.Fatalf("failover did not move off failed Devin account: %q", result.AccountID)
	}
	if result.AccountID != second.ID {
		t.Fatalf("account=%q want=%q", result.AccountID, second.ID)
	}
	if len(f.devinClient.requests) != 2 || len(f.xaiClient.requests) != 0 {
		t.Fatalf("devin requests=%d xai requests=%d", len(f.devinClient.requests), len(f.xaiClient.requests))
	}
	for _, req := range f.devinClient.requests {
		if req.Model.Provider != provider.Devin {
			t.Fatalf("cross-provider failover: %+v", req.Model)
		}
	}
}

// TestExecuteDevinConnectEndStreamUnavailableFailsOver proves a Connect
// EndStream error classified before the first event drives routing failover.
// The classification mirrors what the Devin transport produces for a Connect
// `unavailable` EndStream code (ClassTransient, RetryNext, model-scoped
// cooldown): the first account fails with that typed error, routing applies the
// model cooldown and fails over to a second Devin account without crossing to
// xAI, and no partial response is emitted.
func TestExecuteDevinConnectEndStreamUnavailableFailsOver(t *testing.T) {
	f := newMultiProviderFixture(t)
	defer f.close()
	ctx := context.Background()
	secondExpiry := time.Now().Add(time.Hour)
	second, err := f.accounts.UpsertLogin(ctx, store.Account{Provider: provider.Devin, Label: "d2", Status: "ready", ExpiresAt: &secondExpiry, Credentials: store.AccountCredentials{OpaqueToken: "devin-second", OpaqueTokenExpiresAt: &secondExpiry}})
	if err != nil {
		t.Fatal(err)
	}
	f.devinCreds.values[second.ID] = "devin-second"
	// This is the exact classification the Devin Connect EndStream path emits
	// for code "unavailable" (see internal/devin classifyConnectError).
	f.devinClient.steps = []executeStep{
		{err: &provider.UpstreamError{Provider: provider.Devin, Status: http.StatusServiceUnavailable, Classification: provider.ErrorClassification{Class: provider.ClassTransient, RetryNext: true, CooldownScope: provider.CooldownModel, Cooldown: time.Minute, PublicStatus: http.StatusServiceUnavailable, PublicCode: "provider_unavailable"}}},
		{events: []provider.Event{{Data: []byte(`{"type":"response.completed"}`)}}},
	}
	result, err := f.executor.Execute(ctx, Request{Model: "glm-5-2", Body: []byte(`{"model":"glm-5-2"}`), PreferredAccountID: f.devinAccount.ID})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if result.AccountID != second.ID {
		t.Fatalf("account=%q want failover to %q", result.AccountID, second.ID)
	}
	if len(f.devinClient.requests) != 2 || len(f.xaiClient.requests) != 0 {
		t.Fatalf("devin requests=%d xai requests=%d", len(f.devinClient.requests), len(f.xaiClient.requests))
	}
	// Failover stayed provider-local: both attempts targeted a Devin model.
	for _, req := range f.devinClient.requests {
		if req.Model.Provider != provider.Devin {
			t.Fatalf("cross-provider failover: %+v", req.Model)
		}
	}
}

// TestExecuteDevinRateLimitCooldownFailsOverAndClassifiesRateLimit asserts C9.4:
// a Devin 429 applies a model-scoped rate-limit cooldown and fails over to
// another Devin account; when all Devin accounts are cooling, the error
// classifies as rate-limited with a retry-after.
func TestExecuteDevinRateLimitCooldownFailsOverAndClassifiesRateLimit(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{43}, 32))
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
	creds := &recordingCredentials{values: map[string]string{first.ID: "devin-one", second.ID: "devin-two"}}
	client := &fakeGeneration{ledger: &ledger}
	catalog := fakeCatalog{ledger: &ledger, models: staticConfiguredModels()}
	registry := fakeRegistry{ledger: &ledger, caps: map[string]provider.Capabilities{
		"devin/devin": {Policy: passthroughPolicy{}, Generation: client, Credentials: creds},
	}}
	states := store.NewCooldownRepository(db.DB)
	executor := newExecutor(NewScheduler(), catalog, registry, NewCooldownManager(states, accountRepo), ledgerAccounts{ledger: &ledger, repo: accountRepo}, ledgerCapabilities{ledger: &ledger, repo: store.NewModelCapabilityRepository(db.DB)}, ledgerCooldowns{ledger: &ledger, repo: states})
	executor.SetUsageRecorder(ledgerUsage{ledger: &ledger, records: &usage})
	client.steps = []executeStep{
		{err: &provider.UpstreamError{Provider: provider.Devin, Status: http.StatusTooManyRequests, Classification: provider.ErrorClassification{Class: provider.ClassRateLimit, RetryNext: true, CooldownScope: provider.CooldownModel, Cooldown: time.Minute, PublicStatus: http.StatusTooManyRequests, PublicCode: "rate_limit_exceeded"}}},
		{events: []provider.Event{{Data: []byte(`{"type":"response.completed"}`)}}},
	}
	result, err := executor.Execute(ctx, Request{Model: "swe-1-6", Body: []byte(`{"model":"swe-1-6"}`), PreferredAccountID: first.ID})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if result.AccountID != second.ID {
		t.Fatalf("account=%q want failover to %q", result.AccountID, second.ID)
	}
	if len(client.requests) != 2 {
		t.Fatalf("requests=%d", len(client.requests))
	}
}

// TestExecuteDevinRecordsTerminalUsageExactlyOnce asserts C9.4: a successful
// Devin dispatch records exactly one local usage row with the terminal token
// delta, attributed to the serving Devin account.
func TestExecuteDevinRecordsTerminalUsageExactlyOnce(t *testing.T) {
	f := newMultiProviderFixture(t)
	defer f.close()
	f.devinClient.steps = []executeStep{{events: []provider.Event{
		{Event: "response.output_text.delta", Data: []byte(`{"type":"response.output_text.delta"}`)},
		{Event: "response.completed", Data: []byte(`{"type":"response.completed","response":{"usage":{"input_tokens":19,"output_tokens":29}}}`)},
	}}}
	result, err := f.executor.Execute(context.Background(), Request{Model: "glm", Body: []byte(`{"model":"glm"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if result.Model != "glm-5-2" {
		t.Fatalf("model=%q", result.Model)
	}
	if len(*f.usage) != 1 {
		t.Fatalf("usage records=%+v", *f.usage)
	}
	want := usageRecord{accountID: result.AccountID, delta: LocalUsageDelta{Requests: 1, InputTokens: 19, OutputTokens: 29}}
	if (*f.usage)[0] != want {
		t.Fatalf("usage=%+v, want %+v", (*f.usage)[0], want)
	}
}

// TestExecuteRejectsDevinModelWhenGenerationTrioMissing asserts C9.1: a Devin
// static model whose policy key has no registered generation trio is rejected
// before any credential or client call, even when a Devin account exists.
func TestExecuteRejectsDevinModelWhenGenerationTrioMissing(t *testing.T) {
	f := newMultiProviderFixture(t)
	defer f.close()
	ctx := context.Background()
	original := []byte(`{"model":"glm"}`)
	before := len(f.devinCreds.credentialIDs)
	// Strip the Devin capability registration before any Execute so the Devin
	// static model has no registered generation trio: the model must be
	// rejected with ErrModelUnavailable and no speculative credential or
	// client calls, even though a Devin account exists.
	f.executor.registry = fakeRegistry{ledger: f.ledger, caps: map[string]provider.Capabilities{
		"xai/xai": {Policy: ledgerPolicy{ledger: f.ledger, policy: xai.RequestPolicy{}}, Generation: f.xaiClient, Credentials: f.xaiCreds},
	}}
	_, err := f.executor.Execute(ctx, Request{Model: "glm", Body: original})
	if !errors.Is(err, ErrModelUnavailable) {
		t.Fatalf("err=%v want ErrModelUnavailable", err)
	}
	if len(f.devinCreds.credentialIDs) != before || len(f.devinClient.requests) != 0 || len(f.xaiCreds.credentialIDs) != 0 {
		t.Fatalf("speculative side effects: devinCreds=%v devinClient=%d xaiCreds=%v", f.devinCreds.credentialIDs, len(f.devinClient.requests), f.xaiCreds.credentialIDs)
	}
}
