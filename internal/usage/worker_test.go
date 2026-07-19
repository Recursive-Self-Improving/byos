package usage

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"byos/internal/provider"
)

type workerCapabilityRegistry struct {
	entries map[provider.Kind]provider.Capabilities
}

func (r workerCapabilityRegistry) Capabilities(kind provider.Kind, policyKey string) (provider.Capabilities, bool) {
	if policyKey != string(kind) {
		return provider.Capabilities{}, false
	}
	capabilities, ok := r.entries[kind]
	return capabilities, ok
}

type workerCredentials struct {
	calls               atomic.Int32
	token               string
	waitForCancellation bool
	err                 error
}

func (c *workerCredentials) Credential(ctx context.Context, _ string) (provider.Credential, error) {
	c.calls.Add(1)
	if c.waitForCancellation {
		<-ctx.Done()
		return provider.Credential{}, ctx.Err()
	}
	return provider.Credential{Value: c.token}, c.err
}

func (*workerCredentials) AuthenticationFailed(context.Context, string, *provider.UpstreamError) error {
	return nil
}

type workerUsageFetcher struct {
	mu                  sync.Mutex
	calls               atomic.Int32
	credential          string
	snapshot            provider.UsageSnapshot
	err                 error
	waitForCancellation bool
}

func (f *workerUsageFetcher) FetchUsage(ctx context.Context, credential provider.Credential) (provider.UsageSnapshot, error) {
	f.calls.Add(1)
	f.mu.Lock()
	f.credential = credential.Value
	f.mu.Unlock()
	if f.waitForCancellation {
		<-ctx.Done()
		return provider.UsageSnapshot{}, ctx.Err()
	}
	return f.snapshot, f.err
}

func (f *workerUsageFetcher) observedCredential() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.credential
}

type recordingUsageApplier struct {
	mu         sync.Mutex
	calls      atomic.Int32
	accountID  string
	snapshot   provider.UsageSnapshot
	fetchErr   error
	applyErr   error
	contextErr error
}

func (a *recordingUsageApplier) ApplyUsage(ctx context.Context, accountID string, snapshot provider.UsageSnapshot, fetchErr error) (Snapshot, error) {
	a.calls.Add(1)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.accountID = accountID
	a.snapshot = snapshot
	a.fetchErr = fetchErr
	a.contextErr = ctx.Err()
	if a.applyErr != nil {
		return Snapshot{}, a.applyErr
	}
	return Snapshot{}, fetchErr
}

func (a *recordingUsageApplier) observation() (string, provider.UsageSnapshot, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.accountID, a.snapshot, a.fetchErr
}

func (a *recordingUsageApplier) appliedContextError() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.contextErr
}

func TestUsageWorkerDispatchesSelectedCapabilityAndAppliesObservation(t *testing.T) {
	xaiCredentials := &workerCredentials{token: "xai-secret"}
	devinCredentials := &workerCredentials{token: "devin-secret"}
	observation := provider.UsageSnapshot{Raw: []byte(`{"usage":true}`)}
	fetcher := &workerUsageFetcher{snapshot: observation}
	applier := &recordingUsageApplier{}
	registry := workerCapabilityRegistry{entries: map[provider.Kind]provider.Capabilities{
		provider.XAI:   {Credentials: xaiCredentials, UsageFetcher: fetcher},
		provider.Devin: {Credentials: devinCredentials},
	}}
	worker := NewWorker(usageAccounts{}, registry, applier, time.Hour, time.Second, 2)

	for _, account := range []Account{{ID: "devin", Provider: provider.Devin, Enabled: true}, {ID: "missing", Provider: provider.Kind("missing"), Enabled: true}} {
		if err := worker.RefreshAccount(context.Background(), account); err != nil {
			t.Fatal(err)
		}
	}
	if devinCredentials.calls.Load() != 0 || fetcher.calls.Load() != 0 || applier.calls.Load() != 0 {
		t.Fatalf("unsupported dispatch credentials=%d fetch=%d apply=%d", devinCredentials.calls.Load(), fetcher.calls.Load(), applier.calls.Load())
	}
	if status := worker.Status("devin"); status != (RefreshStatus{}) {
		t.Fatalf("unsupported status mutated: %+v", status)
	}

	if err := worker.RefreshAccount(context.Background(), Account{ID: "xai", Provider: provider.XAI, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	credential := fetcher.observedCredential()
	accountID, appliedSnapshot, _ := applier.observation()
	if xaiCredentials.calls.Load() != 1 || fetcher.calls.Load() != 1 || credential != "xai-secret" || applier.calls.Load() != 1 || accountID != "xai" || string(appliedSnapshot.Raw) != string(observation.Raw) {
		t.Fatalf("dispatch credentials=%d fetch=%d credential=%q apply=%d account=%q raw=%s", xaiCredentials.calls.Load(), fetcher.calls.Load(), credential, applier.calls.Load(), accountID, appliedSnapshot.Raw)
	}
}

func TestUsageWorkerAppliesCredentialFailureAndUsesApplyError(t *testing.T) {
	credentialErr := errors.New("credential refresh failed")
	applyErr := errors.New("persist stale usage failed")
	credentials := &workerCredentials{err: credentialErr}
	fetcher := &workerUsageFetcher{}
	applier := &recordingUsageApplier{applyErr: applyErr}
	registry := workerCapabilityRegistry{entries: map[provider.Kind]provider.Capabilities{
		provider.XAI: {Credentials: credentials, UsageFetcher: fetcher},
	}}
	worker := NewWorker(usageAccounts{}, registry, applier, time.Hour, time.Second, 1)

	err := worker.RefreshAccount(context.Background(), Account{ID: "xai", Provider: provider.XAI, Enabled: true})
	if !errors.Is(err, applyErr) || errors.Is(err, credentialErr) {
		t.Fatalf("refresh error = %v, want apply error %v", err, applyErr)
	}
	accountID, snapshot, observedErr := applier.observation()
	if credentials.calls.Load() != 1 || fetcher.calls.Load() != 0 || applier.calls.Load() != 1 || accountID != "xai" || snapshot.Monthly != nil || snapshot.Weekly != nil || len(snapshot.Raw) != 0 || !snapshot.FetchedAt.IsZero() || !errors.Is(observedErr, credentialErr) {
		t.Fatalf("credentials=%d fetch=%d apply=%d account=%q snapshot=%+v error=%v", credentials.calls.Load(), fetcher.calls.Load(), applier.calls.Load(), accountID, snapshot, observedErr)
	}
	status := worker.Status("xai")
	if status.Refreshing || !status.Stale || status.LastError != applyErr.Error() || status.LastSuccess != (time.Time{}) {
		t.Fatalf("status = %+v", status)
	}
}

func TestUsageWorkerPreservesSanitizedCredentialUpstreamError(t *testing.T) {
	const (
		endpointSentinel = "https://auth.x.ai/oauth/token/credential-endpoint-sentinel"
		tokenSentinel    = "credential-token-sentinel"
		bodySentinel     = "credential-body-sentinel"
	)
	credentialErr := &provider.UpstreamError{
		Provider: provider.XAI,
		Status:   401,
		Classification: provider.ErrorClassification{
			Class:         provider.ClassInvalidGrant,
			PublicStatus:  401,
			PublicCode:    "provider_authentication_error",
			PublicMessage: "account requires login",
		},
	}
	credentials := &workerCredentials{err: credentialErr}
	applier := &recordingUsageApplier{}
	worker := NewWorker(usageAccounts{}, workerCapabilityRegistry{entries: map[provider.Kind]provider.Capabilities{
		provider.XAI: {Credentials: credentials, UsageFetcher: &workerUsageFetcher{}},
	}}, applier, time.Hour, time.Second, 1)

	err := worker.RefreshAccount(context.Background(), Account{ID: "xai", Provider: provider.XAI, Enabled: true})
	var upstream *provider.UpstreamError
	if !errors.As(err, &upstream) || upstream.Classification.PublicCode != "provider_authentication_error" || upstream.Classification.PublicMessage != "account requires login" {
		t.Fatalf("credential error = %#v", err)
	}
	_, _, observedErr := applier.observation()
	if !errors.As(observedErr, &upstream) || observedErr.Error() != "xai upstream returned HTTP 401" {
		t.Fatalf("applied error = %#v", observedErr)
	}
	for _, forbidden := range []string{endpointSentinel, tokenSentinel, bodySentinel} {
		if strings.Contains(err.Error(), forbidden) || strings.Contains(observedErr.Error(), forbidden) {
			t.Fatalf("credential error leaked %q: returned=%q applied=%q", forbidden, err, observedErr)
		}
	}
}

func TestUsageWorkerUsesApplyErrorAfterFetchFailure(t *testing.T) {
	fetchErr := errors.New("billing fetch failed")
	applyErr := errors.New("persist stale usage failed")
	credentials := &workerCredentials{token: "secret"}
	fetcher := &workerUsageFetcher{err: fetchErr}
	applier := &recordingUsageApplier{applyErr: applyErr}
	registry := workerCapabilityRegistry{entries: map[provider.Kind]provider.Capabilities{
		provider.XAI: {Credentials: credentials, UsageFetcher: fetcher},
	}}
	worker := NewWorker(usageAccounts{}, registry, applier, time.Hour, time.Second, 1)

	err := worker.RefreshAccount(context.Background(), Account{ID: "xai", Provider: provider.XAI, Enabled: true})
	if !errors.Is(err, applyErr) || errors.Is(err, fetchErr) {
		t.Fatalf("refresh error = %v, want apply error %v", err, applyErr)
	}
	_, _, observedErr := applier.observation()
	if credentials.calls.Load() != 1 || fetcher.calls.Load() != 1 || applier.calls.Load() != 1 || !errors.Is(observedErr, fetchErr) {
		t.Fatalf("credentials=%d fetch=%d apply=%d error=%v", credentials.calls.Load(), fetcher.calls.Load(), applier.calls.Load(), observedErr)
	}
	status := worker.Status("xai")
	if status.Refreshing || !status.Stale || status.LastError != applyErr.Error() {
		t.Fatalf("status = %+v", status)
	}
}

type blockingUsageApplier struct {
	calls     atomic.Int32
	mu        sync.Mutex
	fetchErrs []error
	deadlines []time.Time
}

func (a *blockingUsageApplier) ApplyUsage(ctx context.Context, _ string, _ provider.UsageSnapshot, fetchErr error) (Snapshot, error) {
	a.calls.Add(1)
	deadline, ok := ctx.Deadline()
	if !ok {
		return Snapshot{}, errors.New("persistence context has no deadline")
	}
	a.mu.Lock()
	a.fetchErrs = append(a.fetchErrs, fetchErr)
	a.deadlines = append(a.deadlines, deadline)
	a.mu.Unlock()
	<-ctx.Done()
	return Snapshot{}, ctx.Err()
}

func (a *blockingUsageApplier) observations() ([]error, []time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]error(nil), a.fetchErrs...), append([]time.Time(nil), a.deadlines...)
}

func TestUsageWorkerBoundsBlockingPersistenceWithFreshContext(t *testing.T) {
	credentialErr := errors.New("credential refresh failed")
	tests := []struct {
		name         string
		credentials  *workerCredentials
		fetcher      *workerUsageFetcher
		wantFetchErr error
	}{
		{name: "fetch timeout", credentials: &workerCredentials{token: "secret"}, fetcher: &workerUsageFetcher{waitForCancellation: true}, wantFetchErr: context.DeadlineExceeded},
		{name: "credential error", credentials: &workerCredentials{err: credentialErr}, fetcher: &workerUsageFetcher{}, wantFetchErr: credentialErr},
		{name: "normal success", credentials: &workerCredentials{token: "secret"}, fetcher: &workerUsageFetcher{snapshot: provider.UsageSnapshot{FetchedAt: time.Now().UTC()}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const timeout = 20 * time.Millisecond
			applier := &blockingUsageApplier{}
			worker := NewWorker(usageAccounts{}, workerCapabilityRegistry{entries: map[provider.Kind]provider.Capabilities{
				provider.XAI: {Credentials: test.credentials, UsageFetcher: test.fetcher},
			}}, applier, time.Hour, timeout, 1)
			account := Account{ID: "xai", Provider: provider.XAI, Enabled: true}
			started := time.Now()
			for call := 1; call <= 2; call++ {
				err := worker.RefreshAccount(context.Background(), account)
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("refresh %d error = %v", call, err)
				}
			}
			fetchErrs, deadlines := applier.observations()
			if applier.calls.Load() != 2 || len(fetchErrs) != 2 || len(deadlines) != 2 {
				t.Fatalf("apply calls=%d fetch errors=%d deadlines=%d", applier.calls.Load(), len(fetchErrs), len(deadlines))
			}
			for i := range fetchErrs {
				if !errors.Is(fetchErrs[i], test.wantFetchErr) || (test.wantFetchErr == nil && fetchErrs[i] != nil) {
					t.Fatalf("fetch error %d = %v, want %v", i, fetchErrs[i], test.wantFetchErr)
				}
				if deadlines[i].Before(started) || deadlines[i].After(time.Now().Add(timeout)) {
					t.Fatalf("persistence deadline %d = %v", i, deadlines[i])
				}
			}
			status := worker.Status(account.ID)
			if status.Refreshing || !status.Stale || status.LastError != context.DeadlineExceeded.Error() || !status.LastSuccess.IsZero() {
				t.Fatalf("status = %+v", status)
			}
		})
	}
}

func TestUsageWorkerAppliesTimeoutFailureWithLivePersistenceContext(t *testing.T) {
	credentials := &workerCredentials{waitForCancellation: true}
	fetcher := &workerUsageFetcher{}
	applier := &recordingUsageApplier{}
	registry := workerCapabilityRegistry{entries: map[provider.Kind]provider.Capabilities{
		provider.XAI: {Credentials: credentials, UsageFetcher: fetcher},
	}}
	worker := NewWorker(usageAccounts{}, registry, applier, time.Hour, time.Millisecond, 1)

	err := worker.RefreshAccount(context.Background(), Account{ID: "xai", Provider: provider.XAI, Enabled: true})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("refresh error = %v", err)
	}
	if applier.calls.Load() != 1 || applier.appliedContextError() != nil {
		t.Fatalf("apply calls=%d context error=%v", applier.calls.Load(), applier.appliedContextError())
	}
}
