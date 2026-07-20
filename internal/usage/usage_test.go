package usage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"byos/internal/provider"
	"byos/internal/store"
	"byos/internal/xai"
)

const monthlyFixture = `{"config":{"monthlyLimit":{"val":1000},"used":{"val":250},"billingPeriodEnd":"2026-08-01T00:00:00Z"}}`
const weeklyFixture = `{"config":{"currentPeriod":{"type":"USAGE_PERIOD_TYPE_WEEKLY"},"creditUsagePercent":25,"billingPeriodEnd":"2026-07-20T00:00:00Z","onDemand":{"val":12},"prepaidCredits":7}}`

func TestBillingCombinedSchemasAndHeaders(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.RequestURI())
		if r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("X-XAI-Token-Auth") != "xai-grok-cli" || r.Header.Get("Accept") != "application/json" {
			t.Errorf("headers=%v", r.Header)
		}
		if r.URL.RawQuery == "format=credits" {
			_, _ = w.Write([]byte(weeklyFixture))
			return
		}
		_, _ = w.Write([]byte(monthlyFixture))
	}))
	defer server.Close()
	adapter := NewBillingAdapter(xai.NewClient(xai.HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second}))
	result, err := adapter.Fetch(context.Background(), "secret")
	if err != nil {
		t.Fatal(err)
	}
	if result.Monthly.Remaining != 750 || result.Weekly == nil || result.Weekly.RemainingPercent != 75 || result.Weekly.OnDemand == nil || *result.Weekly.OnDemand != 12 || result.Weekly.Prepaid == nil || *result.Weekly.Prepaid != 7 {
		t.Fatalf("result=%+v", result)
	}
	if len(paths) != 2 || paths[1] != "/billing?format=credits" {
		t.Fatalf("paths=%v", paths)
	}
}

func TestBillingMonthlyOnlyAndWeeklyOnly(t *testing.T) {
	tests := []struct {
		name                        string
		monthlyStatus, weeklyStatus int
		wantMonthly, wantWeekly     bool
	}{
		{"monthly only", http.StatusOK, http.StatusServiceUnavailable, true, false},
		{"weekly only", http.StatusServiceUnavailable, http.StatusOK, false, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.RawQuery == "format=credits" {
					w.WriteHeader(test.weeklyStatus)
					if test.weeklyStatus == http.StatusOK {
						_, _ = w.Write([]byte(weeklyFixture))
					}
					return
				}
				w.WriteHeader(test.monthlyStatus)
				if test.monthlyStatus == http.StatusOK {
					_, _ = w.Write([]byte(monthlyFixture))
				}
			}))
			defer server.Close()
			result, err := NewBillingAdapter(xai.NewClient(xai.HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second})).Fetch(context.Background(), "token")
			if err != nil || (result.Monthly != nil) != test.wantMonthly || (result.Weekly != nil) != test.wantWeekly {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		})
	}
}

func TestBillingSchemaAndHTTPErrors(t *testing.T) {
	for _, payload := range []string{`{"config":{"monthlyLimit":{"val":"100"},"used":{"val":1},"billingPeriodEnd":"2026-08-01T00:00:00Z"}}`, `{"config":{"monthlyLimit":{"val":100},"used":{"val":1},"billingPeriodEnd":3}}`} {
		if _, err := parseMonthly([]byte(payload)); !errors.Is(err, ErrSchema) {
			t.Fatalf("payload=%s err=%v", payload, err)
		}
	}
	if _, err := parseWeekly([]byte(`{"config":{"currentPeriod":{"type":"USAGE_PERIOD_TYPE_WEEKLY"},"creditUsagePercent":"25","billingPeriodEnd":"2026-08-01T00:00:00Z"}}`)); !errors.Is(err, ErrSchema) {
		t.Fatalf("weekly err=%v", err)
	}
	for _, status := range []int{http.StatusUnauthorized, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", "9")
				w.WriteHeader(status)
			}))
			defer server.Close()
			_, err := NewBillingAdapter(xai.NewClient(xai.HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second})).Fetch(context.Background(), "t")
			var upstream *HTTPError
			if !errors.As(err, &upstream) || upstream.Status != status || upstream.RetryAfter != "9" {
				t.Fatalf("err=%#v", err)
			}
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	client := xai.NewClient(xai.HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second})
	server.Close()
	if _, err := NewBillingAdapter(client).Fetch(context.Background(), "token"); err == nil {
		t.Fatal("network error accepted")
	}
}

type memorySnapshots struct {
	mu     sync.Mutex
	values map[string][]store.UsageSnapshot
}

func (m *memorySnapshots) Put(_ context.Context, v store.UsageSnapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values[v.AccountID] = append(m.values[v.AccountID], v)
	return nil
}
func (m *memorySnapshots) Latest(_ context.Context, id string) (store.UsageSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.values[id]
	if len(v) == 0 {
		return store.UsageSnapshot{}, sql.ErrNoRows
	}
	return v[len(v)-1], nil
}

type memoryCounters struct {
	mu     sync.Mutex
	values map[string]store.LocalUsageCounters
}

func (m *memoryCounters) Add(_ context.Context, id string, d store.LocalUsageCounters) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.values[id]
	v.Requests += d.Requests
	v.Failures += d.Failures
	v.InputTokens += d.InputTokens
	v.OutputTokens += d.OutputTokens
	v.CacheReadTokens += d.CacheReadTokens
	m.values[id] = v
	return nil
}
func (m *memoryCounters) Get(_ context.Context, id string) (store.LocalUsageCounters, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.values[id], nil
}

func TestServiceStaleFallbackAndUnknown(t *testing.T) {
	snapshots := &memorySnapshots{values: map[string][]store.UsageSnapshot{}}
	counters := &memoryCounters{values: map[string]store.LocalUsageCounters{}}
	reset := time.Now().UTC()
	service := NewService(snapshots, counters)
	fresh, err := service.ApplyUsage(context.Background(), "a", provider.UsageSnapshot{
		Monthly: &provider.MonthlyUsage{Limit: 10, Used: 4, Remaining: 6, ResetAt: reset},
		Raw:     []byte(`{"private":"raw"}`), FetchedAt: reset,
	}, nil)
	if err != nil || fresh.Stale || fresh.Monthly.Remaining != 6 {
		t.Fatalf("fresh=%+v err=%v", fresh, err)
	}
	if err := service.Record(context.Background(), "a", Delta{Requests: 2, Failures: 1, InputTokens: 3, OutputTokens: 4}); err != nil {
		t.Fatal(err)
	}
	fetchErr := errors.New("network unavailable")
	stale, err := service.ApplyUsage(context.Background(), "a", provider.UsageSnapshot{}, fetchErr)
	if err == nil || !stale.Stale || stale.Unknown || stale.Local.Requests != 2 {
		t.Fatalf("stale=%+v err=%v", stale, err)
	}
	stored, _ := snapshots.Latest(context.Background(), "a")
	if string(stored.Raw) != `{"private":"raw"}` {
		t.Fatalf("stale raw = %s", stored.Raw)
	}
	restarted := NewService(snapshots, counters)
	persisted, err := restarted.Latest(context.Background(), "a")
	if err != nil || !persisted.Stale || persisted.Error == "" || persisted.Local.OutputTokens != 4 {
		t.Fatalf("persisted=%+v err=%v", persisted, err)
	}
	if err := service.Record(context.Background(), "missing", Delta{Requests: 7, Failures: 2, InputTokens: 11, OutputTokens: 13}); err != nil {
		t.Fatal(err)
	}
	observedAt := reset.Add(time.Minute)
	unknown, err := service.ApplyUsage(context.Background(), "missing", provider.UsageSnapshot{FetchedAt: observedAt}, fetchErr)
	if err == nil || !unknown.Unknown || !unknown.Stale || unknown.Error != "usage refresh failed" || unknown.Monthly != nil || unknown.Weekly != nil || !unknown.FetchedAt.Equal(observedAt) || unknown.Local.Requests != 7 || unknown.Local.OutputTokens != 13 {
		t.Fatalf("unknown=%+v err=%v", unknown, err)
	}
	storedUnknown, storedErr := snapshots.Latest(context.Background(), "missing")
	if storedErr != nil || storedUnknown.Raw != nil || !storedUnknown.Stale || storedUnknown.Error != "usage refresh failed" || !storedUnknown.FetchedAt.Equal(observedAt) {
		t.Fatalf("stored unknown=%+v err=%v", storedUnknown, storedErr)
	}
	restartedUnknown, err := NewService(snapshots, counters).Latest(context.Background(), "missing")
	if err != nil || !restartedUnknown.Unknown || !restartedUnknown.Stale || restartedUnknown.Error != "usage refresh failed" || restartedUnknown.Monthly != nil || restartedUnknown.Weekly != nil || !restartedUnknown.FetchedAt.Equal(observedAt) || restartedUnknown.Local.Requests != 7 || restartedUnknown.Local.Failures != 2 || restartedUnknown.Local.InputTokens != 11 || restartedUnknown.Local.OutputTokens != 13 {
		t.Fatalf("restarted unknown=%+v err=%v", restartedUnknown, err)
	}
}

func TestServiceRecordAndCountersThreadCacheReadTokens(t *testing.T) {
	snapshots := &memorySnapshots{values: map[string][]store.UsageSnapshot{}}
	counters := &memoryCounters{values: map[string]store.LocalUsageCounters{}}
	service := NewService(snapshots, counters)

	// Record a terminal delta carrying nonzero cache-read tokens. Cache-read
	// is a local proxy counter only; it must accumulate like the other
	// counters without being treated as upstream billing quota.
	if err := service.Record(context.Background(), "acct-cache", Delta{Requests: 1, InputTokens: 17, OutputTokens: 23, CacheReadTokens: 5}); err != nil {
		t.Fatal(err)
	}
	if err := service.Record(context.Background(), "acct-cache", Delta{Requests: 1, InputTokens: 4, CacheReadTokens: 8}); err != nil {
		t.Fatal(err)
	}

	got, err := service.Counters(context.Background(), "acct-cache")
	if err != nil {
		t.Fatal(err)
	}
	if got != (Counters{Requests: 2, Failures: 0, InputTokens: 21, OutputTokens: 23, CacheReadTokens: 13}) {
		t.Fatalf("counters=%+v, want {Requests:2 InputTokens:21 OutputTokens:23 CacheReadTokens:13}", got)
	}

	// Latest projects the accumulated local counters (including cache-read)
	// alongside an upstream snapshot without conflating them with quota.
	reset := time.Now().UTC().Truncate(time.Second)
	if _, err := service.ApplyUsage(context.Background(), "acct-cache", provider.UsageSnapshot{Monthly: &provider.MonthlyUsage{Limit: 100, Used: 40, Remaining: 60, ResetAt: reset}, FetchedAt: reset}, nil); err != nil {
		t.Fatal(err)
	}
	latest, err := service.Latest(context.Background(), "acct-cache")
	if err != nil {
		t.Fatal(err)
	}
	if latest.Local != (Counters{Requests: 2, Failures: 0, InputTokens: 21, OutputTokens: 23, CacheReadTokens: 13}) {
		t.Fatalf("latest local=%+v, want accumulated counters with cache-read", latest.Local)
	}
	if latest.Monthly == nil || latest.Monthly.Remaining != 60 {
		t.Fatalf("latest monthly=%+v, want upstream quota preserved independently", latest.Monthly)
	}

	// An account with no recorded cache-read reports zero, proving the
	// counter is always populated rather than absent.
	empty, err := service.Counters(context.Background(), "acct-empty")
	if err != nil {
		t.Fatal(err)
	}
	if empty != (Counters{}) {
		t.Fatalf("empty counters=%+v, want zero value with CacheReadTokens=0", empty)
	}
}

type capturingUsageApplier struct {
	service  *Service
	snapshot Snapshot
}

func (a *capturingUsageApplier) ApplyUsage(ctx context.Context, accountID string, observation provider.UsageSnapshot, fetchErr error) (Snapshot, error) {
	snapshot, err := a.service.ApplyUsage(ctx, accountID, observation, fetchErr)
	a.snapshot = snapshot
	return snapshot, err
}

func TestWorkerCredentialFailurePersistsStaleOrReportsUnknown(t *testing.T) {
	snapshots := &memorySnapshots{values: map[string][]store.UsageSnapshot{}}
	counters := &memoryCounters{values: map[string]store.LocalUsageCounters{}}
	service := NewService(snapshots, counters)
	reset := time.Now().UTC()
	if _, err := service.ApplyUsage(context.Background(), "prior", provider.UsageSnapshot{
		Monthly:   &provider.MonthlyUsage{Limit: 10, Used: 4, Remaining: 6, ResetAt: reset},
		Raw:       []byte(`{"private":"raw"}`),
		FetchedAt: reset,
	}, nil); err != nil {
		t.Fatal(err)
	}

	credentialErr := errors.New("credential refresh failed")
	credentials := &workerCredentials{err: credentialErr}
	fetcher := &workerUsageFetcher{}
	registry := workerCapabilityRegistry{entries: map[provider.Kind]provider.Capabilities{
		provider.XAI: {Credentials: credentials, UsageFetcher: fetcher},
	}}
	applier := &capturingUsageApplier{service: service}
	worker := NewWorker(usageAccounts{}, registry, applier, time.Hour, time.Second, 1)
	if err := worker.RefreshAccount(context.Background(), Account{ID: "prior", Provider: provider.XAI, Enabled: true}); !errors.Is(err, credentialErr) {
		t.Fatalf("refresh error = %v", err)
	}
	if !applier.snapshot.Stale || applier.snapshot.Unknown || applier.snapshot.Error != "usage refresh failed" || applier.snapshot.Monthly == nil || applier.snapshot.Monthly.Remaining != 6 {
		t.Fatalf("stale snapshot = %+v", applier.snapshot)
	}
	status := worker.Status("prior")
	if status.Refreshing || !status.Stale || status.LastError != "credential refresh failed" {
		t.Fatalf("status = %+v", status)
	}
	restarted := NewService(snapshots, counters)
	persisted, err := restarted.Latest(context.Background(), "prior")
	if err != nil || !persisted.Stale || persisted.Unknown || persisted.Error != "usage refresh failed" || persisted.Monthly == nil || persisted.Monthly.Remaining != 6 {
		t.Fatalf("persisted = %+v, error = %v", persisted, err)
	}

	if err := service.Record(context.Background(), "missing", Delta{Requests: 3, Failures: 1, InputTokens: 5, OutputTokens: 8}); err != nil {
		t.Fatal(err)
	}
	if err := worker.RefreshAccount(context.Background(), Account{ID: "missing", Provider: provider.XAI, Enabled: true}); !errors.Is(err, credentialErr) {
		t.Fatalf("missing refresh error = %v", err)
	}
	if !applier.snapshot.Stale || !applier.snapshot.Unknown || applier.snapshot.Error != "usage refresh failed" || applier.snapshot.Monthly != nil || applier.snapshot.Weekly != nil || applier.snapshot.FetchedAt.IsZero() || applier.snapshot.Local.Requests != 3 || applier.snapshot.Local.OutputTokens != 8 {
		t.Fatalf("unknown snapshot = %+v", applier.snapshot)
	}
	if fetcher.calls.Load() != 0 {
		t.Fatalf("fetch calls = %d", fetcher.calls.Load())
	}
	storedUnknown, storedErr := snapshots.Latest(context.Background(), "missing")
	if storedErr != nil || storedUnknown.Raw != nil || !storedUnknown.Stale || storedUnknown.Error != "usage refresh failed" {
		t.Fatalf("stored unknown = %+v, error = %v", storedUnknown, storedErr)
	}
	restartedUnknown, err := NewService(snapshots, counters).Latest(context.Background(), "missing")
	if err != nil || !restartedUnknown.Stale || !restartedUnknown.Unknown || restartedUnknown.Error != "usage refresh failed" || restartedUnknown.Monthly != nil || restartedUnknown.Weekly != nil || restartedUnknown.FetchedAt.IsZero() || restartedUnknown.Local.Requests != 3 || restartedUnknown.Local.Failures != 1 || restartedUnknown.Local.InputTokens != 5 || restartedUnknown.Local.OutputTokens != 8 {
		t.Fatalf("restarted unknown = %+v, error = %v", restartedUnknown, err)
	}
}

func TestWorkerFetchTimeoutPersistsUnknownUsage(t *testing.T) {
	snapshots := &memorySnapshots{values: map[string][]store.UsageSnapshot{}}
	counters := &memoryCounters{values: map[string]store.LocalUsageCounters{}}
	service := NewService(snapshots, counters)
	if err := service.Record(context.Background(), "missing", Delta{Requests: 2, Failures: 1}); err != nil {
		t.Fatal(err)
	}
	worker := NewWorker(usageAccounts{}, workerCapabilityRegistry{entries: map[provider.Kind]provider.Capabilities{
		provider.XAI: {Credentials: &workerCredentials{token: "secret"}, UsageFetcher: &workerUsageFetcher{waitForCancellation: true}},
	}}, service, time.Hour, 20*time.Millisecond, 1)

	err := worker.RefreshAccount(context.Background(), Account{ID: "missing", Provider: provider.XAI, Enabled: true})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("refresh error = %v", err)
	}
	persisted, err := NewService(snapshots, counters).Latest(context.Background(), "missing")
	if err != nil || !persisted.Stale || !persisted.Unknown || persisted.Error != context.DeadlineExceeded.Error() || persisted.Monthly != nil || persisted.Weekly != nil || persisted.FetchedAt.IsZero() || persisted.Local.Requests != 2 || persisted.Local.Failures != 1 {
		t.Fatalf("persisted timeout = %+v, error = %v", persisted, err)
	}
	status := worker.Status("missing")
	if status.Refreshing || !status.Stale || status.LastError != context.DeadlineExceeded.Error() || !status.LastSuccess.IsZero() {
		t.Fatalf("status = %+v", status)
	}
}

func TestCredentialUpstreamErrorPersistenceIsSanitizedAfterRestart(t *testing.T) {
	const (
		endpointSentinel = "https://auth.x.ai/oauth/token/persistence-endpoint-sentinel"
		tokenSentinel    = "persistence-token-sentinel"
		bodySentinel     = "persistence-body-sentinel"
	)
	credentialErr := &provider.UpstreamError{
		Provider: provider.XAI,
		Status:   http.StatusUnauthorized,
		Classification: provider.ErrorClassification{
			Class:           provider.ClassInvalidGrant,
			DisableAccount:  true,
			ReloginRequired: true,
			PublicStatus:    http.StatusUnauthorized,
			PublicCode:      "provider_authentication_error",
			PublicMessage:   "account requires login",
		},
	}
	snapshots := &memorySnapshots{values: map[string][]store.UsageSnapshot{}}
	counters := &memoryCounters{values: map[string]store.LocalUsageCounters{}}
	service := NewService(snapshots, counters)
	worker := NewWorker(usageAccounts{}, workerCapabilityRegistry{entries: map[provider.Kind]provider.Capabilities{
		provider.XAI: {Credentials: &workerCredentials{err: credentialErr}, UsageFetcher: &workerUsageFetcher{}},
	}}, service, time.Hour, time.Second, 1)

	err := worker.RefreshAccount(context.Background(), Account{ID: "xai", Provider: provider.XAI, Enabled: true})
	var upstream *provider.UpstreamError
	if !errors.As(err, &upstream) || upstream.Classification.PublicCode != "provider_authentication_error" || upstream.Classification.PublicMessage != "account requires login" {
		t.Fatalf("credential error = %#v", err)
	}
	persisted, err := NewService(snapshots, counters).Latest(context.Background(), "xai")
	if err != nil || !persisted.Stale || !persisted.Unknown || persisted.Error != "xai upstream returned HTTP 401" {
		t.Fatalf("persisted = %+v, error = %v", persisted, err)
	}
	for _, forbidden := range []string{endpointSentinel, tokenSentinel, bodySentinel} {
		if strings.Contains(persisted.Error, forbidden) {
			t.Fatalf("persisted credential error leaked %q: %q", forbidden, persisted.Error)
		}
	}
}

func TestServiceSanitizesWrappedContextErrors(t *testing.T) {
	// Wrapped context errors must canonicalize to the bare context error text
	// so outer wrapper text (which may carry secrets) never persists.
	const cancelSentinel = "wrapped-cancel-secret-sentinel-7f3a"
	const deadlineSentinel = "wrapped-deadline-secret-sentinel-2c91"
	cases := []struct {
		name     string
		wrapped  error
		want     string
		sentinel string
	}{
		{
			name:     "canceled",
			wrapped:  fmt.Errorf("fetching usage for token=%s: %w", cancelSentinel, context.Canceled),
			want:     context.Canceled.Error(),
			sentinel: cancelSentinel,
		},
		{
			name:     "deadline exceeded",
			wrapped:  fmt.Errorf("billing request body=%s: %w", deadlineSentinel, context.DeadlineExceeded),
			want:     context.DeadlineExceeded.Error(),
			sentinel: deadlineSentinel,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snapshots := &memorySnapshots{values: map[string][]store.UsageSnapshot{}}
			counters := &memoryCounters{values: map[string]store.LocalUsageCounters{}}
			service := NewService(snapshots, counters)
			unknown, err := service.ApplyUsage(context.Background(), "ctx-"+tc.name, provider.UsageSnapshot{FetchedAt: time.Now().UTC()}, tc.wrapped)
			if err == nil || !unknown.Stale || !unknown.Unknown || unknown.Error != tc.want {
				t.Fatalf("unknown = %+v, err = %v", unknown, err)
			}
			if strings.Contains(unknown.Error, tc.sentinel) {
				t.Fatalf("wrapped context error leaked sentinel %q: %q", tc.sentinel, unknown.Error)
			}
			stored, storedErr := snapshots.Latest(context.Background(), "ctx-"+tc.name)
			if storedErr != nil || stored.Error != tc.want || strings.Contains(stored.Error, tc.sentinel) {
				t.Fatalf("stored = %+v, err = %v", storedErr, stored)
			}
		})
	}
}

type usageAccounts struct{ accounts []Account }

func (a usageAccounts) UsageAccounts(context.Context) ([]Account, error) { return a.accounts, nil }

type boundedRefresher struct {
	active, max, calls atomic.Int32
	release            chan struct{}
}

func (r *boundedRefresher) ApplyUsage(ctx context.Context, _ string, _ provider.UsageSnapshot, fetchErr error) (Snapshot, error) {
	r.calls.Add(1)
	n := r.active.Add(1)
	defer r.active.Add(-1)
	for {
		old := r.max.Load()
		if n <= old || r.max.CompareAndSwap(old, n) {
			break
		}
	}
	select {
	case <-ctx.Done():
		return Snapshot{}, ctx.Err()
	case <-r.release:
		return Snapshot{}, fetchErr
	}
}
func TestWorkerBoundedCancellationAndRestart(t *testing.T) {
	ref := &boundedRefresher{release: make(chan struct{})}
	accounts := usageAccounts{accounts: []Account{{ID: "a", Provider: provider.XAI, Enabled: true}, {ID: "b", Provider: provider.XAI, Enabled: true}, {ID: "c", Provider: provider.XAI, Enabled: true}}}
	registry := workerCapabilityRegistry{entries: map[provider.Kind]provider.Capabilities{provider.XAI: {Credentials: &workerCredentials{}, UsageFetcher: &workerUsageFetcher{}}}}
	worker := NewWorker(accounts, registry, ref, time.Hour, time.Hour, 2)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	deadline := time.After(time.Second)
	for ref.calls.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("refresh did not start")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if ref.max.Load() > 2 {
		t.Fatalf("max=%d", ref.max.Load())
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	close(ref.release)
	ref2 := &boundedRefresher{release: make(chan struct{})}
	close(ref2.release)
	worker2 := NewWorker(accounts, registry, ref2, time.Hour, time.Second, 2)
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan error, 1)
	go func() { done2 <- worker2.Run(ctx2) }()
	deadline = time.After(time.Second)
	for ref2.calls.Load() < 3 {
		select {
		case <-deadline:
			t.Fatalf("restart calls=%d", ref2.calls.Load())
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel2()
	<-done2
}

func TestExplicitUsageRefreshGlobalBound(t *testing.T) {
	refresher := &boundedRefresher{release: make(chan struct{})}
	registry := workerCapabilityRegistry{entries: map[provider.Kind]provider.Capabilities{provider.XAI: {Credentials: &workerCredentials{}, UsageFetcher: &workerUsageFetcher{}}}}
	worker := NewWorker(usageAccounts{}, registry, refresher, time.Hour, time.Hour, 2)
	done := make(chan error, 3)
	for _, id := range []string{"a", "b", "c"} {
		id := id
		go func() {
			done <- worker.RefreshAccount(context.Background(), Account{ID: id, Provider: provider.XAI, Enabled: true})
		}()
	}
	deadline := time.After(time.Second)
	for refresher.calls.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("refreshes did not start")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	time.Sleep(10 * time.Millisecond)
	if refresher.calls.Load() != 2 || refresher.max.Load() > 2 {
		t.Fatalf("calls=%d max=%d", refresher.calls.Load(), refresher.max.Load())
	}
	close(refresher.release)
	for range 3 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}
