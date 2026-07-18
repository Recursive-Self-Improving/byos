package usage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"byoo/internal/store"
	"byoo/internal/xai"
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
	m.values[id] = v
	return nil
}
func (m *memoryCounters) Get(_ context.Context, id string) (store.LocalUsageCounters, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.values[id], nil
}

type fakeBilling struct {
	result BillingResult
	err    error
}

func (f *fakeBilling) Fetch(context.Context, string) (BillingResult, error) { return f.result, f.err }

func TestServiceStaleFallbackAndUnknown(t *testing.T) {
	snapshots := &memorySnapshots{values: map[string][]store.UsageSnapshot{}}
	counters := &memoryCounters{values: map[string]store.LocalUsageCounters{}}
	monthly := Monthly{Limit: 10, Used: 4, Remaining: 6, ResetAt: time.Now().UTC()}
	billing := &fakeBilling{result: BillingResult{Monthly: &monthly, Raw: json.RawMessage(`{"private":"raw"}`)}}
	service := NewService(billing, snapshots, counters)
	fresh, err := service.Refresh(context.Background(), "a", "token")
	if err != nil || fresh.Stale || fresh.Monthly.Remaining != 6 {
		t.Fatalf("fresh=%+v err=%v", fresh, err)
	}
	if err := service.Record(context.Background(), "a", Delta{Requests: 2, Failures: 1, InputTokens: 3, OutputTokens: 4}); err != nil {
		t.Fatal(err)
	}
	billing.err = errors.New("network unavailable")
	stale, err := service.Refresh(context.Background(), "a", "token")
	if err == nil || !stale.Stale || stale.Unknown || stale.Local.Requests != 2 {
		t.Fatalf("stale=%+v err=%v", stale, err)
	}
	restarted := NewService(billing, snapshots, counters)
	persisted, err := restarted.Latest(context.Background(), "a")
	if err != nil || !persisted.Stale || persisted.Error == "" || persisted.Local.OutputTokens != 4 {
		t.Fatalf("persisted=%+v err=%v", persisted, err)
	}
	unknown, err := service.Refresh(context.Background(), "missing", "token")
	if err == nil || !unknown.Unknown || !unknown.Stale || unknown.Monthly != nil {
		t.Fatalf("unknown=%+v err=%v", unknown, err)
	}
}

type usageAccounts struct{ accounts []Account }

func (a usageAccounts) UsageAccounts(context.Context) ([]Account, error) { return a.accounts, nil }

type boundedRefresher struct {
	active, max, calls atomic.Int32
	release            chan struct{}
}

func (r *boundedRefresher) Refresh(ctx context.Context, _, _ string) (Snapshot, error) {
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
		return Snapshot{}, nil
	}
}
func TestWorkerBoundedCancellationAndRestart(t *testing.T) {
	ref := &boundedRefresher{release: make(chan struct{})}
	accounts := usageAccounts{accounts: []Account{{ID: "a", Enabled: true}, {ID: "b", Enabled: true}, {ID: "c", Enabled: true}}}
	worker := NewWorker(accounts, ref, time.Hour, time.Hour, 2)
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
	worker2 := NewWorker(accounts, ref2, time.Hour, time.Second, 2)
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
	worker := NewWorker(usageAccounts{}, refresher, time.Hour, time.Hour, 2)
	done := make(chan error, 3)
	for _, id := range []string{"a", "b", "c"} {
		go func() { done <- worker.RefreshAccount(context.Background(), Account{ID: id, Enabled: true}) }()
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
