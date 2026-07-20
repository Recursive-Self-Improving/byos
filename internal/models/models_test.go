package models

import (
	"context"
	"errors"
	"sync"
	"testing"

	"byos/internal/provider"
	"byos/internal/store"
)

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

func TestCatalogAllowlistAliasesAndStaleSnapshot(t *testing.T) {
	repo := &memoryCaps{values: map[string][]store.ModelCapability{}}
	catalog := NewCatalog(repo, []string{"grok-4.5", "grok-5"}, map[string]string{"grok": "grok-4.5"})
	if _, err := catalog.RefreshFromModels(context.Background(), "a", []Model{{ID: "grok-4.5"}, {ID: "not-allowed"}}, nil); err != nil {
		t.Fatal(err)
	}
	public, err := catalog.Public(context.Background(), []string{"a"})
	if err != nil || len(public) != 2 || public[0].ID != "grok" || public[1].ID != "grok-4.5" {
		t.Fatalf("public=%+v err=%v", public, err)
	}
	if resolved, ok := catalog.Resolve("grok"); !ok || resolved != "grok-4.5" {
		t.Fatalf("resolve=%s,%v", resolved, ok)
	}
	if _, err := catalog.RefreshFromModels(context.Background(), "a", nil, errors.New("offline")); err == nil {
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
	catalog := NewCatalog(repo, []string{"grok-4.5"}, map[string]string{"grok": "grok-4.5"})
	public, err := catalog.Public(context.Background(), []string{"a"})
	if err != nil || len(public) != 0 {
		t.Fatalf("public=%+v err=%v", public, err)
	}
}

func TestCatalogRejectsUnpersistedStaleState(t *testing.T) {
	for _, test := range []struct {
		name   string
		repo   *memoryCaps
		target error
	}{
		{"mark error", &memoryCaps{values: map[string][]store.ModelCapability{"a": {{AccountID: "a", Model: "grok", Supported: true}}}, markErr: errors.New("write failed")}, nil},
		{"fresh after mark", &memoryCaps{values: map[string][]store.ModelCapability{"a": {{AccountID: "a", Model: "grok", Supported: true}}}, skipMark: true}, ErrStaleState},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewCatalog(test.repo, []string{"grok"}, nil).RefreshFromModels(context.Background(), "a", nil, errors.New("offline"))
			if err == nil || (test.target != nil && !errors.Is(err, test.target)) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestCatalogApplyDiscoveryPreservesNormalizedFieldsAndSearchTriState(t *testing.T) {
	repo := &memoryCaps{values: map[string][]store.ModelCapability{}}
	catalog := NewCatalog(repo, nil, nil)
	search := false
	discovered := []provider.DiscoveredModel{
		{UpstreamName: "unknown-search", ReasoningEfforts: []string{"high"}},
		{UpstreamName: "no-search", DisplayName: "No Search", SupportsBackendSearch: &search, ContextWindow: 42, MaxOutputTokens: 7},
	}
	models, err := catalog.ApplyDiscovery(context.Background(), "a", discovered, nil)
	if err != nil {
		t.Fatal(err)
	}
	search = true
	discovered[0].ReasoningEfforts[0] = "changed"
	if len(models) != 2 || models[0].SupportsBackendSearch != nil || models[0].ReasoningEfforts[0] != "high" {
		t.Fatalf("normalized models = %+v", models)
	}
	if models[1].SupportsBackendSearch == nil || *models[1].SupportsBackendSearch || models[1].DisplayName != "No Search" || models[1].ContextWindow != 42 || models[1].MaxOutputTokens != 7 {
		t.Fatalf("normalized model = %+v", models[1])
	}
	capabilities, err := catalog.Capabilities(context.Background(), "a")
	if err != nil || len(capabilities) != 2 || capabilities[0].SupportsBackendSearch != nil || capabilities[1].SupportsBackendSearch == nil || *capabilities[1].SupportsBackendSearch {
		t.Fatalf("capabilities = %+v, error = %v", capabilities, err)
	}
}

func TestCatalogDiscoveryFreshnessSurvivesRestartAndPreservesUnknownSentinelSemantics(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	first, err := store.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, accountID := range []string{"prior", "unknown", "empty"} {
		if _, err := first.DB.ExecContext(ctx, `INSERT INTO accounts(id, identity_fingerprint, status, credentials_encrypted, created_at, updated_at) VALUES (?, ?, 'active', '{}', unixepoch(), unixepoch())`, accountID, []byte(accountID)); err != nil {
			t.Fatal(err)
		}
	}
	repository := store.NewModelCapabilityRepository(first.DB)
	catalog := NewCatalog(repository, []string{"grok"}, nil)
	if _, err := catalog.ApplyDiscovery(ctx, "prior", []provider.DiscoveredModel{{UpstreamName: "grok"}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.ApplyDiscovery(ctx, "prior", nil, context.DeadlineExceeded); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error = %v", err)
	}
	if _, err := catalog.ApplyDiscovery(ctx, "unknown", nil, context.DeadlineExceeded); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unknown timeout error = %v", err)
	}
	if _, err := catalog.ApplyDiscovery(ctx, "empty", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := store.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	restarted := NewCatalog(store.NewModelCapabilityRepository(second.DB), []string{"grok"}, nil)
	prior, err := restarted.Capabilities(ctx, "prior")
	if err != nil || len(prior) != 1 || prior[0].Model.ID != "grok" || !prior[0].Stale {
		t.Fatalf("restarted stale snapshot = %+v, %v", prior, err)
	}
	resolved := provider.ResolvedModel{UpstreamName: "grok", Provider: provider.XAI}
	unknown, err := restarted.AccountSupports(ctx, "unknown", resolved)
	if err != nil || !unknown {
		t.Fatalf("no-prior timeout should remain unknown/routable: supported=%v err=%v", unknown, err)
	}
	empty, err := restarted.AccountSupports(ctx, "empty", resolved)
	if err != nil || empty {
		t.Fatalf("successful empty sentinel should be known/unsupported: supported=%v err=%v", empty, err)
	}
}
