package models

import (
	"context"
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

func TestDiscoverySchemasFallbackAndCredentials(t *testing.T) {
	tests := []struct {
		name           string
		v2Status       int
		v2Body         string
		legacyBody     string
		wantID         string
		wantLegacy     bool
		wantCredential bool
	}{
		{"array schema", 200, `[{"id":"grok-4.5","displayName":"Grok","contextWindow":131072,"maxCompletionTokens":8192,"reasoningEfforts":["high"],"supportsBackendSearch":true}]`, ``, "grok-4.5", false, false},
		{"envelope model key", 200, `{"models":[{"model":"grok-4.5","display_name":"Grok"}]}`, ``, "grok-4.5", false, false},
		{"404 fallback", 404, ``, `[{"id":"legacy"}]`, "legacy", true, false},
		{"schema fallback", 200, `{"items":[]}`, `{"models":[{"model":"legacy"}]}`, "legacy", true, false},
		{"credential no fallback", 401, ``, `[{"id":"must-not-call"}]`, "", false, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var legacy atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer token" {
					t.Errorf("authorization=%q", r.Header.Get("Authorization"))
				}
				switch r.URL.Path {
				case "/models-v2":
					w.WriteHeader(test.v2Status)
					_, _ = w.Write([]byte(test.v2Body))
				case "/models":
					legacy.Store(true)
					_, _ = w.Write([]byte(test.legacyBody))
				default:
					t.Errorf("path=%s", r.URL.Path)
				}
			}))
			defer server.Close()
			upstream := NewUpstream(xai.NewClient(xai.HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second}))
			models, err := upstream.Discover(context.Background(), "token")
			if test.wantCredential {
				if !errors.Is(err, ErrCredential) || legacy.Load() {
					t.Fatalf("err=%v legacy=%v", err, legacy.Load())
				}
				return
			}
			if err != nil || len(models) != 1 || models[0].ID != test.wantID || legacy.Load() != test.wantLegacy {
				t.Fatalf("models=%+v err=%v legacy=%v", models, err, legacy.Load())
			}
		})
	}
}

func TestDiscoveryRejectsChangedTypes(t *testing.T) {
	for _, payload := range []string{`[{"id":4}]`, `[{"id":"grok","contextWindow":"large"}]`, `[{"id":"grok","supportsBackendSearch":"yes"}]`} {
		if _, err := parseCatalog([]byte(payload)); !errors.Is(err, ErrSchema) {
			t.Fatalf("payload %s err=%v", payload, err)
		}
	}
}

type memoryCaps struct {
	mu       sync.Mutex
	values   map[string][]store.ModelCapability
	markErr  error
	skipMark bool
}

func (m *memoryCaps) Replace(_ context.Context, id string, values []store.ModelCapability) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values[id] = append([]store.ModelCapability(nil), values...)
	return nil
}
func (m *memoryCaps) List(_ context.Context, id string) ([]store.ModelCapability, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]store.ModelCapability(nil), m.values[id]...), nil
}
func (m *memoryCaps) MarkStale(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.markErr != nil {
		return m.markErr
	}
	if m.skipMark {
		return nil
	}
	values := m.values[id]
	for i := range values {
		values[i].Stale = true
	}
	m.values[id] = values
	return nil
}

type sequenceDiscovery struct {
	models []Model
	err    error
}

func (d *sequenceDiscovery) Discover(context.Context, string) ([]Model, error) {
	return d.models, d.err
}

func TestCatalogAllowlistAliasesAndStaleSnapshot(t *testing.T) {
	repo := &memoryCaps{values: map[string][]store.ModelCapability{}}
	discovery := &sequenceDiscovery{models: []Model{{ID: "grok-4.5"}, {ID: "not-allowed"}}}
	catalog := NewCatalog(repo, discovery, []string{"grok-4.5", "grok-5"}, map[string]string{"grok": "grok-4.5"})
	if _, err := catalog.Refresh(context.Background(), "a", "token"); err != nil {
		t.Fatal(err)
	}
	public, err := catalog.Public(context.Background(), []string{"a"})
	if err != nil || len(public) != 2 || public[0].ID != "grok" || public[1].ID != "grok-4.5" {
		t.Fatalf("public=%+v err=%v", public, err)
	}
	if public[0].OwnedBy != "byoo" || public[1].OwnedBy != "xai" {
		t.Fatalf("model ownership = %+v", public)
	}
	if resolved, ok := catalog.Resolve("grok"); !ok || resolved != "grok-4.5" {
		t.Fatalf("resolve=%s,%v", resolved, ok)
	}
	discovery.err = errors.New("offline")
	if _, err := catalog.Refresh(context.Background(), "a", "token"); err == nil {
		t.Fatal("refresh succeeded")
	}
	capabilities, err := catalog.Capabilities(context.Background(), "a")
	if err != nil || len(capabilities) != 2 || !capabilities[0].Stale {
		t.Fatalf("caps=%+v err=%v", capabilities, err)
	}
	stalePublic, err := catalog.Public(context.Background(), []string{"a"})
	if err != nil || len(stalePublic) != 2 {
		t.Fatalf("stale public=%+v err=%v", stalePublic, err)
	}
	fallback, err := catalog.Public(context.Background(), nil)
	if err != nil || len(fallback) != 3 {
		t.Fatalf("fallback=%+v err=%v", fallback, err)
	}
}

func TestCatalogExcludesSearchUnsupportedModels(t *testing.T) {
	search := false
	repo := &memoryCaps{values: map[string][]store.ModelCapability{"a": {{AccountID: "a", Model: "grok-4.5", Supported: true, SupportsBackendSearch: &search}}}}
	catalog := NewCatalog(repo, nil, []string{"grok-4.5"}, map[string]string{"grok": "grok-4.5"})
	public, err := catalog.Public(context.Background(), []string{"a"})
	if err != nil || len(public) != 0 {
		t.Fatalf("public=%+v err=%v", public, err)
	}
}

func TestCatalogRejectsUnpersistedStaleState(t *testing.T) {
	discovery := &sequenceDiscovery{err: errors.New("offline")}
	for _, test := range []struct {
		name   string
		repo   *memoryCaps
		target error
	}{
		{"mark error", &memoryCaps{values: map[string][]store.ModelCapability{"a": {{AccountID: "a", Model: "grok", Supported: true}}}, markErr: errors.New("write failed")}, nil},
		{"fresh after mark", &memoryCaps{values: map[string][]store.ModelCapability{"a": {{AccountID: "a", Model: "grok", Supported: true}}}, skipMark: true}, ErrStaleState},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewCatalog(test.repo, discovery, []string{"grok"}, nil).Refresh(context.Background(), "a", "token")
			if err == nil || (test.target != nil && !errors.Is(err, test.target)) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

type blockingRefresher struct {
	calls   atomic.Int32
	started chan struct{}
}

func (r *blockingRefresher) Refresh(ctx context.Context, _, _ string) ([]Model, error) {
	if r.calls.Add(1) == 1 {
		close(r.started)
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

type modelAccounts struct{}

func (modelAccounts) ModelAccounts(context.Context) ([]Account, error) {
	return []Account{{ID: "a", AccessToken: "t", Enabled: true}}, nil
}
func TestWorkerDeduplicatesAndCancels(t *testing.T) {
	refresher := &blockingRefresher{started: make(chan struct{})}
	worker := NewWorker(modelAccounts{}, refresher, time.Hour, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 2)
	go func() { done <- worker.RefreshAccount(ctx, Account{ID: "a", AccessToken: "t", Enabled: true}) }()
	<-refresher.started
	go func() { done <- worker.RefreshAccount(ctx, Account{ID: "a", AccessToken: "t", Enabled: true}) }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	for range 2 {
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v", err)
		}
	}
	if refresher.calls.Load() != 1 {
		t.Fatalf("calls=%d", refresher.calls.Load())
	}
}

type boundedModelRefresher struct {
	active, max, calls atomic.Int32
	release            chan struct{}
}

func (r *boundedModelRefresher) Refresh(ctx context.Context, _, _ string) ([]Model, error) {
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
		return nil, ctx.Err()
	case <-r.release:
		return []Model{}, nil
	}
}
func TestExplicitModelRefreshGlobalBound(t *testing.T) {
	refresher := &boundedModelRefresher{release: make(chan struct{})}
	worker := NewWorker(modelAccounts{}, refresher, time.Hour, time.Hour, 2)
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
