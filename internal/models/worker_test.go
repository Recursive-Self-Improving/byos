package models

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"byos/internal/config"
	"byos/internal/provider"
	"byos/internal/store"
)

type modelAccounts struct{}

func (modelAccounts) ModelAccounts(context.Context) ([]Account, error) {
	return []Account{{ID: "a", Provider: provider.XAI, Enabled: true}}, nil
}

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
	calls atomic.Int32
	token string
	err   error
}

func (c *workerCredentials) Credential(context.Context, string) (provider.Credential, error) {
	c.calls.Add(1)
	return provider.Credential{Value: c.token}, c.err
}
func (*workerCredentials) AuthenticationFailed(context.Context, string, *provider.UpstreamError) error {
	return nil
}

type workerDiscoverer struct {
	mu      sync.Mutex
	calls   atomic.Int32
	token   string
	models  []provider.DiscoveredModel
	err     error
	started chan struct{}
	start   sync.Once
}

type workerDiscovererSnapshot struct {
	calls int32
	token string
}

func (d *workerDiscoverer) snapshot() workerDiscovererSnapshot {
	d.mu.Lock()
	defer d.mu.Unlock()
	return workerDiscovererSnapshot{calls: d.calls.Load(), token: d.token}
}

func (d *workerDiscoverer) Discover(ctx context.Context, credential provider.Credential) ([]provider.DiscoveredModel, error) {
	d.mu.Lock()
	d.calls.Add(1)
	d.token = credential.Value
	d.mu.Unlock()
	if d.started != nil {
		d.start.Do(func() { close(d.started) })
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return d.models, d.err
}

type recordingDiscoveryApplier struct {
	mu        sync.Mutex
	calls     atomic.Int32
	accountID string
	models    []provider.DiscoveredModel
	err       error
}

type discoveryApplierSnapshot struct {
	calls     int32
	accountID string
	models    []provider.DiscoveredModel
	err       error
}

func (a *recordingDiscoveryApplier) snapshot() discoveryApplierSnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	return discoveryApplierSnapshot{
		calls:     a.calls.Load(),
		accountID: a.accountID,
		models:    append([]provider.DiscoveredModel(nil), a.models...),
		err:       a.err,
	}
}

func (a *recordingDiscoveryApplier) ApplyDiscovery(_ context.Context, accountID string, models []provider.DiscoveredModel, err error) ([]Model, error) {
	a.mu.Lock()
	a.calls.Add(1)
	a.accountID = accountID
	a.models = append([]provider.DiscoveredModel(nil), models...)
	a.err = err
	a.mu.Unlock()
	return nil, err
}

func TestModelWorkerDispatchesSelectedDiscovererAndAppliesResult(t *testing.T) {
	credentials := &workerCredentials{token: "xai-secret"}
	discoverer := &workerDiscoverer{models: []provider.DiscoveredModel{{UpstreamName: "grok"}}}
	applier := &recordingDiscoveryApplier{}
	registry := workerCapabilityRegistry{entries: map[provider.Kind]provider.Capabilities{
		provider.XAI: {Credentials: credentials, ModelDiscoverer: discoverer},
	}}
	worker := NewWorker(modelAccounts{}, registry, applier, time.Hour, time.Second)

	if err := worker.RefreshAccount(context.Background(), Account{ID: "xai", Provider: provider.XAI, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	discovery := discoverer.snapshot()
	application := applier.snapshot()
	if credentials.calls.Load() != 1 || discovery.calls != 1 || application.calls != 1 {
		t.Fatalf("calls credentials=%d discoverer=%d apply=%d", credentials.calls.Load(), discovery.calls, application.calls)
	}
	if discovery.token != "xai-secret" || application.accountID != "xai" || len(application.models) != 1 || application.models[0].UpstreamName != "grok" {
		t.Fatalf("dispatch token=%q account=%q models=%+v", discovery.token, application.accountID, application.models)
	}
}

func TestModelWorkerProviderMismatchMakesNoCallsWritesOrStatus(t *testing.T) {
	xaiCredentials := &workerCredentials{token: "xai-secret"}
	xaiDiscoverer := &workerDiscoverer{}
	devinCredentials := &workerCredentials{token: "devin-secret"}
	applier := &recordingDiscoveryApplier{}
	registry := workerCapabilityRegistry{entries: map[provider.Kind]provider.Capabilities{
		provider.XAI:   {Credentials: xaiCredentials, ModelDiscoverer: xaiDiscoverer},
		provider.Devin: {Credentials: devinCredentials},
	}}
	worker := NewWorker(modelAccounts{}, registry, applier, time.Hour, time.Second)

	for _, account := range []Account{
		{ID: "devin", Provider: provider.Devin, Enabled: true},
		{ID: "missing", Provider: provider.Kind("missing"), Enabled: true},
		{ID: "disabled", Provider: provider.XAI, Enabled: false},
	} {
		if err := worker.RefreshAccount(context.Background(), account); err != nil {
			t.Fatal(err)
		}
		if got := worker.Status(account.ID); got != (RefreshStatus{}) {
			t.Fatalf("status %q mutated: %+v", account.ID, got)
		}
	}
	xaiDiscovery := xaiDiscoverer.snapshot()
	application := applier.snapshot()
	if xaiCredentials.calls.Load() != 0 || devinCredentials.calls.Load() != 0 || xaiDiscovery.calls != 0 || application.calls != 0 {
		t.Fatalf("unexpected calls xaiCred=%d devinCred=%d discover=%d apply=%d", xaiCredentials.calls.Load(), devinCredentials.calls.Load(), xaiDiscovery.calls, application.calls)
	}
}

func TestModelWorkerDeduplicatesAndCancels(t *testing.T) {
	discoverer := &workerDiscoverer{started: make(chan struct{})}
	registry := workerCapabilityRegistry{entries: map[provider.Kind]provider.Capabilities{
		provider.XAI: {Credentials: &workerCredentials{}, ModelDiscoverer: discoverer},
	}}
	worker := NewWorker(modelAccounts{}, registry, &recordingDiscoveryApplier{}, time.Hour, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 2)
	account := Account{ID: "a", Provider: provider.XAI, Enabled: true}
	go func() { done <- worker.RefreshAccount(ctx, account) }()
	<-discoverer.started
	go func() { done <- worker.RefreshAccount(ctx, account) }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	for range 2 {
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v", err)
		}
	}
	if discovery := discoverer.snapshot(); discovery.calls != 1 {
		t.Fatalf("calls=%d", discovery.calls)
	}
}

type boundedDiscoverer struct {
	active, max, calls atomic.Int32
	release            chan struct{}
}

func (d *boundedDiscoverer) Discover(ctx context.Context, _ provider.Credential) ([]provider.DiscoveredModel, error) {
	d.calls.Add(1)
	n := d.active.Add(1)
	defer d.active.Add(-1)
	for {
		old := d.max.Load()
		if n <= old || d.max.CompareAndSwap(old, n) {
			break
		}
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.release:
		return nil, nil
	}
}

type perAccountRegistry struct{ discoverer provider.ModelDiscoverer }

func (r perAccountRegistry) Capabilities(kind provider.Kind, policyKey string) (provider.Capabilities, bool) {
	if kind != provider.XAI || policyKey != "xai" {
		return provider.Capabilities{}, false
	}
	return provider.Capabilities{Credentials: &workerCredentials{}, ModelDiscoverer: r.discoverer}, true
}

func TestExplicitModelRefreshGlobalBound(t *testing.T) {
	discoverer := &boundedDiscoverer{release: make(chan struct{})}
	worker := NewWorker(modelAccounts{}, perAccountRegistry{discoverer}, &recordingDiscoveryApplier{}, time.Hour, time.Hour, 2)
	done := make(chan error, 3)
	for _, id := range []string{"a", "b", "c"} {
		id := id
		go func() {
			done <- worker.RefreshAccount(context.Background(), Account{ID: id, Provider: provider.XAI, Enabled: true})
		}()
	}
	deadline := time.After(time.Second)
	for discoverer.calls.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("discoveries did not start")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	time.Sleep(10 * time.Millisecond)
	if discoverer.calls.Load() != 2 || discoverer.max.Load() > 2 {
		t.Fatalf("calls=%d max=%d", discoverer.calls.Load(), discoverer.max.Load())
	}
	close(discoverer.release)
	for range 3 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

type timeoutCredentials struct{}

func (timeoutCredentials) Credential(ctx context.Context, _ string) (provider.Credential, error) {
	<-ctx.Done()
	return provider.Credential{}, ctx.Err()
}

func (timeoutCredentials) AuthenticationFailed(context.Context, string, *provider.UpstreamError) error {
	return nil
}

type delayedDiscoverer struct {
	delay  time.Duration
	models []provider.DiscoveredModel
}

func (d delayedDiscoverer) Discover(ctx context.Context, _ provider.Credential) ([]provider.DiscoveredModel, error) {
	timer := time.NewTimer(d.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return d.models, nil
	}
}

type contextCheckingApplier struct {
	delegate DiscoveryApplier
	active   bool
	bounded  bool
}

func (a *contextCheckingApplier) ApplyDiscovery(ctx context.Context, accountID string, models []provider.DiscoveredModel, discoveryErr error) ([]Model, error) {
	a.active = ctx.Err() == nil
	_, a.bounded = ctx.Deadline()
	return a.delegate.ApplyDiscovery(ctx, accountID, models, discoveryErr)
}

func TestModelWorkerTimeoutPersistsFreshnessWithLiveContext(t *testing.T) {
	for _, test := range []struct {
		name        string
		credentials provider.CredentialManager
		discoverer  provider.ModelDiscoverer
		prior       []store.ModelCapability
	}{
		{
			name:        "credential timeout marks prior snapshot stale",
			credentials: timeoutCredentials{},
			discoverer:  &workerDiscoverer{},
			prior:       []store.ModelCapability{{AccountID: "a", Model: "grok", Supported: true}},
		},
		{
			name:        "discovery timeout marks prior snapshot stale",
			credentials: &workerCredentials{},
			discoverer:  delayedDiscoverer{delay: time.Hour},
			prior:       []store.ModelCapability{{AccountID: "a", Model: "grok", Supported: true}},
		},
		{
			name:        "timeout without prior snapshot remains unknown",
			credentials: timeoutCredentials{},
			discoverer:  &workerDiscoverer{},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo := &memoryCaps{values: map[string][]store.ModelCapability{"a": append([]store.ModelCapability(nil), test.prior...)}}
			catalog := NewCatalog(repo, []string{"grok"}, nil)
			registry := workerCapabilityRegistry{entries: map[provider.Kind]provider.Capabilities{
				provider.XAI: {Credentials: test.credentials, ModelDiscoverer: test.discoverer},
			}}
			worker := NewWorker(modelAccounts{}, registry, catalog, time.Hour, 5*time.Millisecond)
			err := worker.RefreshAccount(context.Background(), Account{ID: "a", Provider: provider.XAI, Enabled: true})
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("refresh error = %v", err)
			}
			capabilities, listErr := catalog.Capabilities(context.Background(), "a")
			if listErr != nil {
				t.Fatal(listErr)
			}
			if len(test.prior) == 0 {
				if len(capabilities) != 0 {
					t.Fatalf("unknown snapshot became %+v", capabilities)
				}
			} else if len(capabilities) != 1 || !capabilities[0].Stale {
				t.Fatalf("timeout snapshot = %+v", capabilities)
			}
			status := worker.Status("a")
			if status.Refreshing || !status.Stale || status.LastError == "" {
				t.Fatalf("timeout status = %+v", status)
			}
		})
	}
}

func TestModelWorkerUsesFreshBoundedPersistenceContextAfterRefreshTimeout(t *testing.T) {
	repo := &memoryCaps{values: map[string][]store.ModelCapability{"a": {{AccountID: "a", Model: "grok", Supported: true}}}}
	applier := &contextCheckingApplier{delegate: NewCatalog(repo, []string{"grok"}, nil)}
	registry := workerCapabilityRegistry{entries: map[provider.Kind]provider.Capabilities{
		provider.XAI: {Credentials: timeoutCredentials{}, ModelDiscoverer: &workerDiscoverer{}},
	}}
	worker := NewWorker(modelAccounts{}, registry, applier, time.Hour, 5*time.Millisecond)
	err := worker.RefreshAccount(context.Background(), Account{ID: "a", Provider: provider.XAI, Enabled: true})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("refresh error = %v", err)
	}
	if !applier.active || !applier.bounded {
		t.Fatalf("persistence context active=%v bounded=%v", applier.active, applier.bounded)
	}
}

type blockingDiscoveryApplier struct {
	mu        sync.Mutex
	calls     int
	startedAt time.Time
	deadline  time.Time
	inputErr  error
	done      chan struct{}
	resultErr error
}

func (a *blockingDiscoveryApplier) ApplyDiscovery(ctx context.Context, _ string, _ []provider.DiscoveredModel, discoveryErr error) ([]Model, error) {
	a.mu.Lock()
	a.calls++
	call := a.calls
	if call == 1 {
		a.startedAt = time.Now()
		a.deadline, _ = ctx.Deadline()
		a.inputErr = discoveryErr
	}
	a.mu.Unlock()
	if call != 1 {
		return nil, discoveryErr
	}
	<-ctx.Done()
	close(a.done)
	return nil, a.resultErr
}

func TestModelWorkerPersistenceGetsFreshBoundedContext(t *testing.T) {
	persistenceErr := errors.New("persistence failed after cancellation")
	for _, test := range []struct {
		name         string
		credentials  provider.CredentialManager
		discoverer   provider.ModelDiscoverer
		wantInputErr bool
	}{
		{name: "after network timeout", credentials: timeoutCredentials{}, discoverer: &workerDiscoverer{}, wantInputErr: true},
		{name: "after normal result", credentials: &workerCredentials{}, discoverer: delayedDiscoverer{delay: 15 * time.Millisecond}},
	} {
		t.Run(test.name, func(t *testing.T) {
			const bound = 40 * time.Millisecond
			applier := &blockingDiscoveryApplier{done: make(chan struct{}), resultErr: persistenceErr}
			registry := workerCapabilityRegistry{entries: map[provider.Kind]provider.Capabilities{
				provider.XAI: {Credentials: test.credentials, ModelDiscoverer: test.discoverer},
			}}
			worker := NewWorker(modelAccounts{}, registry, applier, time.Hour, bound, 1)
			account := Account{ID: "first", Provider: provider.XAI, Enabled: true}

			started := time.Now()
			err := worker.RefreshAccount(context.Background(), account)
			if !errors.Is(err, persistenceErr) {
				t.Fatalf("refresh error = %v, want persistence error", err)
			}
			select {
			case <-applier.done:
			default:
				t.Fatal("applier returned without observing persistence deadline cancellation")
			}
			applier.mu.Lock()
			calls, applyStart, deadline, inputErr := applier.calls, applier.startedAt, applier.deadline, applier.inputErr
			applier.mu.Unlock()
			if calls != 1 || applyStart.IsZero() || deadline.IsZero() {
				t.Fatalf("persistence attempt calls=%d start=%v deadline=%v", calls, applyStart, deadline)
			}
			if got := deadline.Sub(applyStart); got < bound-10*time.Millisecond || got > bound+10*time.Millisecond {
				t.Fatalf("persistence context bound = %v, want %v", got, bound)
			}
			if test.wantInputErr != errors.Is(inputErr, context.DeadlineExceeded) {
				t.Fatalf("discovery input error = %v", inputErr)
			}
			if elapsed := time.Since(started); elapsed < bound || elapsed > 3*bound {
				t.Fatalf("refresh elapsed = %v, expected bounded network plus persistence", elapsed)
			}
			status := worker.Status(account.ID)
			if status.LastAttempt.IsZero() || status.Refreshing || !status.Stale || status.LastError != persistenceErr.Error() || !status.LastSuccess.IsZero() {
				t.Fatalf("persistence failure status = %+v", status)
			}

			released := make(chan error, 1)
			go func() {
				released <- worker.RefreshAccount(context.Background(), Account{ID: "second", Provider: provider.XAI, Enabled: true})
			}()
			select {
			case secondErr := <-released:
				if test.wantInputErr != errors.Is(secondErr, context.DeadlineExceeded) {
					t.Fatalf("second refresh error = %v", secondErr)
				}
			case <-time.After(3 * bound):
				t.Fatal("persistence deadline did not release concurrency slot")
			}
		})
	}
}

func TestModelWorkerNearTimeoutSuccessPersistsFreshSnapshot(t *testing.T) {
	repo := &memoryCaps{values: map[string][]store.ModelCapability{}}
	catalog := NewCatalog(repo, nil, nil)
	registry := workerCapabilityRegistry{entries: map[provider.Kind]provider.Capabilities{
		provider.XAI: {
			Credentials:     &workerCredentials{},
			ModelDiscoverer: delayedDiscoverer{delay: 15 * time.Millisecond, models: []provider.DiscoveredModel{{UpstreamName: "grok"}}},
		},
	}}
	worker := NewWorker(modelAccounts{}, registry, catalog, time.Hour, 50*time.Millisecond)
	if err := worker.RefreshAccount(context.Background(), Account{ID: "a", Provider: provider.XAI, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	capabilities, err := catalog.Capabilities(context.Background(), "a")
	if err != nil || len(capabilities) != 1 || capabilities[0].Model.ID != "grok" || capabilities[0].Stale {
		t.Fatalf("fresh snapshot = %+v, %v", capabilities, err)
	}
	status := worker.Status("a")
	if status.Refreshing || status.Stale || status.LastSuccess.IsZero() || status.LastError != "" {
		t.Fatalf("success status = %+v", status)
	}
}

// blockingModelAccounts exposes a controllable set of accounts and lets a test
type blockingModelAccounts struct {
	mu       sync.Mutex
	accounts []Account
	started  chan struct{}
	release  chan struct{}
	start    sync.Once
}

func (b *blockingModelAccounts) ModelAccounts(ctx context.Context) ([]Account, error) {
	if b.started != nil {
		b.startOnce()
	}
	if b.release != nil {
		select {
		case <-b.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Account(nil), b.accounts...), nil
}

func (b *blockingModelAccounts) startOnce() {
	b.start.Do(func() { close(b.started) })
}

// restartApplier counts ApplyDiscovery calls and signals when the second call
// begins. With worker concurrency 1 and two accounts, the second apply can
// only start after the first refresh cycle completed ApplyDiscovery and
// released its limiter slot, so observing the second call proves a full
// discover+apply cycle ran to completion — not merely that ApplyDiscovery was
// entered.
type restartApplier struct {
	mu     sync.Mutex
	calls  int
	second chan struct{}
	once   sync.Once
}

func (a *restartApplier) ApplyDiscovery(_ context.Context, _ string, _ []provider.DiscoveredModel, _ error) ([]Model, error) {
	a.mu.Lock()
	a.calls++
	n := a.calls
	a.mu.Unlock()
	if n == 2 {
		a.once.Do(func() { close(a.second) })
	}
	return nil, nil
}

func (a *restartApplier) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

func TestModelWorkerRunCancelsAndRestartsCleanly(t *testing.T) {
	discoverer := &workerDiscoverer{models: []provider.DiscoveredModel{{UpstreamName: "grok"}}}
	registry := workerCapabilityRegistry{entries: map[provider.Kind]provider.Capabilities{
		provider.XAI: {Credentials: &workerCredentials{}, ModelDiscoverer: discoverer},
	}}
	accounts := &blockingModelAccounts{
		accounts: []Account{{ID: "a", Provider: provider.XAI, Enabled: true}},
		started:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	worker := NewWorker(accounts, registry, &recordingDiscoveryApplier{}, time.Hour, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	select {
	case <-accounts.started:
	case <-time.After(time.Second):
		t.Fatal("first worker did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first Run did not return after cancel")
	}
	// Restart with a fresh worker and context: it must be reusable after the
	// prior cancellation and must not retain stuck limiter slots. Using
	// concurrency 1 with two accounts, the second apply can only begin once
	// the first refresh cycle completed ApplyDiscovery and released its
	// limiter slot, so observing the second apply entry proves a full
	// discover+apply cycle ran to completion — not merely that ApplyDiscovery
	// was entered. Then assert the success status and confirm Run returns
	// context.Canceled, all observed deterministically without sleeping.
	accounts2 := &blockingModelAccounts{accounts: []Account{
		{ID: "a", Provider: provider.XAI, Enabled: true},
		{ID: "b", Provider: provider.XAI, Enabled: true},
	}}
	applier2 := &restartApplier{second: make(chan struct{})}
	restarted := NewWorker(accounts2, registry, applier2, time.Hour, time.Second, 1)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	done2 := make(chan error, 1)
	go func() { done2 <- restarted.Run(ctx2) }()
	select {
	case <-applier2.second:
	case <-time.After(time.Second):
		t.Fatalf("restarted worker did not complete a cycle and release its limiter slot (applies=%d)", applier2.count())
	}
	if calls := applier2.count(); calls != 2 {
		t.Fatalf("apply calls = %d, want 2", calls)
	}
	// The second apply entry proves the first refresh released its limiter
	// slot and ran its terminal status update, so account "a" must now be
	// non-refreshing, non-stale, with a nonzero LastSuccess and no LastError.
	status := restarted.Status("a")
	if status.Refreshing || status.Stale || status.LastSuccess.IsZero() || status.LastError != "" {
		t.Fatalf("restarted status = %+v, want non-refreshing success", status)
	}
	cancel2()
	select {
	case err := <-done2:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("second Run returned %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second Run did not return after cancel")
	}
}

func TestModelWorkerDevinHasNoDiscovererAndAbsentCapabilityIsNoOp(t *testing.T) {
	// C8.3: Devin has no ModelDiscoverer registered. The worker must treat the
	// absent capability as a clean no-op: no credential, discovery, or apply
	// calls, no status mutation, and no error. The static five-name Devin
	// fallback remains independent of this worker.
	xaiDiscoverer := &workerDiscoverer{models: []provider.DiscoveredModel{{UpstreamName: "grok"}}}
	xaiCredentials := &workerCredentials{token: "xai-secret"}
	devinCredentials := &workerCredentials{token: "devin-secret"}
	registry := workerCapabilityRegistry{entries: map[provider.Kind]provider.Capabilities{
		provider.XAI:   {Credentials: xaiCredentials, ModelDiscoverer: xaiDiscoverer},
		provider.Devin: {Credentials: devinCredentials},
	}}
	applier := &recordingDiscoveryApplier{}
	worker := NewWorker(modelAccounts{}, registry, applier, time.Hour, time.Second)
	if err := worker.RefreshAccount(context.Background(), Account{ID: "devin", Provider: provider.Devin, Enabled: true}); err != nil {
		t.Fatalf("Devin refresh error = %v", err)
	}
	if got := worker.Status("devin"); got != (RefreshStatus{}) {
		t.Fatalf("Devin status mutated: %+v", got)
	}
	xaiDiscovery := xaiDiscoverer.snapshot()
	application := applier.snapshot()
	if xaiCredentials.calls.Load() != 0 || devinCredentials.calls.Load() != 0 || xaiDiscovery.calls != 0 || application.calls != 0 {
		t.Fatalf("unexpected calls xaiCred=%d devinCred=%d discover=%d apply=%d", xaiCredentials.calls.Load(), devinCredentials.calls.Load(), xaiDiscovery.calls, application.calls)
	}
	// The static catalog fallback is independent of this worker: the
	// real/default configured static entries resolve the Devin models
	// without any worker/discoverer involvement. The zero-call assertions
	// above prove the worker adds no Devin discovery of its own; the
	// configured static catalog still resolves them.
	staticCatalog, err := NewStaticCatalog(config.Default().Models.Entries)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"glm", "swe", "glm-5-2", "swe-1-6", "swe-1-7"} {
		resolved, err := staticCatalog.Resolve(name)
		if err != nil {
			t.Fatalf("static catalog resolve %q = %v", name, err)
		}
		if resolved.Provider != provider.Devin {
			t.Fatalf("static catalog %q provider = %v, want devin", name, resolved.Provider)
		}
	}
	// The absent capability/unknown snapshot fallback keeps a Devin account
	// eligible: with no capability snapshot stored, AccountSupports reports
	// the resolved Devin model routable via the real Catalog APIs.
	catalog := NewCatalog(capabilityStoreStub{}, nil, nil)
	devin := provider.ResolvedModel{PublicName: "glm-5-2", UpstreamName: "glm-5-2", Provider: provider.Devin, OwnedBy: "devin", PolicyKey: "devin"}
	if supported, err := catalog.AccountSupports(context.Background(), "devin", devin); err != nil || !supported {
		t.Fatalf("AccountSupports absent snapshot = %v, %v; want true, nil", supported, err)
	}
}
