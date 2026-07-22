package models

import (
	"context"
	"errors"
	"testing"

	"byos/internal/config"
	"byos/internal/provider"
	"byos/internal/store"
)

func TestNewStaticCatalogFromValidatedConfig(t *testing.T) {
	cfg := config.Default()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	catalog, err := NewStaticCatalog(cfg.Models.Entries)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]provider.ResolvedModel{
		"grok":     {PublicName: "grok", UpstreamName: "grok-4.5", Provider: provider.XAI, OwnedBy: "byos", PolicyKey: "xai"},
		"glm":      {PublicName: "glm", UpstreamName: "glm-5-2", Provider: provider.Devin, OwnedBy: "byos", PolicyKey: "devin"},
		"swe":      {PublicName: "swe", UpstreamName: "swe-1-7", Provider: provider.Devin, OwnedBy: "byos", PolicyKey: "devin"},
		"grok-4.5": {PublicName: "grok-4.5", UpstreamName: "grok-4.5", Provider: provider.XAI, OwnedBy: "xai", PolicyKey: "xai"},
		"glm-5-2":  {PublicName: "glm-5-2", UpstreamName: "glm-5-2", Provider: provider.Devin, OwnedBy: "devin", PolicyKey: "devin"},
		"swe-1-6":  {PublicName: "swe-1-6", UpstreamName: "swe-1-6", Provider: provider.Devin, OwnedBy: "devin", PolicyKey: "devin"},
		"swe-1-7":  {PublicName: "swe-1-7", UpstreamName: "swe-1-7", Provider: provider.Devin, OwnedBy: "devin", PolicyKey: "devin"},
	}
	for name, expected := range want {
		got, err := catalog.Resolve(name)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", name, err)
		}
		if got != expected {
			t.Errorf("Resolve(%q) = %+v, want %+v", name, got, expected)
		}
	}
	if len(catalog.Models()) != len(want) {
		t.Fatalf("Models length = %d", len(catalog.Models()))
	}
}

func TestNewStaticCatalogRejectsInvalidConfigEntries(t *testing.T) {
	base := config.ModelEntry{PublicName: "one", UpstreamName: "shared", Provider: config.ProviderXAI, OwnedBy: "xai", PolicyKey: "xai"}
	tests := []struct {
		name    string
		entries []config.ModelEntry
		target  error
	}{
		{"duplicate", []config.ModelEntry{base, base}, provider.ErrDuplicatePublicModel},
		{"provider ambiguity", []config.ModelEntry{base, {PublicName: "two", UpstreamName: "shared", Provider: config.ProviderDevin, OwnedBy: "devin", PolicyKey: "xai"}}, provider.ErrAmbiguousUpstreamModel},
		{"policy ambiguity", []config.ModelEntry{base, {PublicName: "two", UpstreamName: "shared", Provider: config.ProviderXAI, OwnedBy: "xai", PolicyKey: "other"}}, provider.ErrAmbiguousUpstreamModel},
		{"unknown provider", []config.ModelEntry{{PublicName: "one", UpstreamName: "one", Provider: config.ProviderKind("other"), OwnedBy: "owner", PolicyKey: "policy"}}, provider.ErrInvalidKind},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewStaticCatalog(test.entries)
			if !errors.Is(err, test.target) {
				t.Fatalf("error = %v, want %v", err, test.target)
			}
		})
	}
}

func TestNewStaticCatalogUnknownDoesNotUseLegacyCatalog(t *testing.T) {
	catalog, err := NewStaticCatalog(config.Default().Models.Entries)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", " grok", "GROK", "unknown"} {
		if _, err := catalog.Resolve(name); !errors.Is(err, provider.ErrUnknownModel) {
			t.Errorf("Resolve(%q) error = %v", name, err)
		}
	}
}

func TestStaticCatalogOverlayResolvesXAIOnlyOneHop(t *testing.T) {
	static, err := NewStaticCatalog(config.Default().Models.Entries)
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := NewStaticCatalogOverlay(static, map[string]string{"grok": config.DefaultModel, "fast": config.DefaultModel})
	if err != nil {
		t.Fatal(err)
	}
	fast, err := overlay.Resolve("fast")
	if err != nil {
		t.Fatal(err)
	}
	want := provider.ResolvedModel{PublicName: config.DefaultModel, UpstreamName: config.DefaultModel, Provider: provider.XAI, OwnedBy: "xai", PolicyKey: "xai"}
	if fast != want {
		t.Fatalf("Resolve(fast) = %+v, want %+v", fast, want)
	}
	grok, err := overlay.Resolve("grok")
	if err != nil {
		t.Fatal(err)
	}
	if grok.PublicName != "grok" || grok.OwnedBy != "byos" {
		t.Fatalf("fixed grok identity changed: %+v", grok)
	}
	if len(static.Models()) != 7 {
		t.Fatalf("static projection length = %d, want 7", len(static.Models()))
	}
}

func TestStaticCatalogOverlayRejectsOwnershipRedirects(t *testing.T) {
	static, err := NewStaticCatalog(config.Default().Models.Entries)
	if err != nil {
		t.Fatal(err)
	}
	for _, aliases := range []map[string]string{
		{"glm": config.DefaultModel},
		{"fast": "glm-5-2"},
		{"fast": "unknown"},
		{"fast": "turbo", "turbo": config.DefaultModel},
	} {
		if _, err := NewStaticCatalogOverlay(static, aliases); err == nil {
			t.Fatalf("aliases %+v unexpectedly accepted", aliases)
		}
	}
}

type capabilityStoreStub struct {
	values map[string][]store.ModelCapability
}

func (s capabilityStoreStub) Replace(context.Context, string, []store.ModelCapability) error {
	return nil
}
func (s capabilityStoreStub) MarkStale(context.Context, string) error { return nil }
func (s capabilityStoreStub) List(_ context.Context, accountID string) ([]store.ModelCapability, error) {
	return append([]store.ModelCapability(nil), s.values[accountID]...), nil
}

func TestAccountSupportsPartitionsProviderCapabilitySemantics(t *testing.T) {
	searchFalse := false
	store := capabilityStoreStub{values: map[string][]store.ModelCapability{
		"xai-known":   {{Model: "grok-4.5", Supported: true, SupportsBackendSearch: &searchFalse}},
		"devin-known": {{Model: "glm-5-2", Supported: true, SupportsBackendSearch: &searchFalse}},
		"other-known": {{Model: "other", Supported: true}},
	}}
	catalog := NewCatalog(store, nil, nil)
	xai := provider.ResolvedModel{PublicName: "grok", UpstreamName: "grok-4.5", Provider: provider.XAI, OwnedBy: "byos", PolicyKey: "xai"}
	devin := provider.ResolvedModel{PublicName: "glm-5-2", UpstreamName: "glm-5-2", Provider: provider.Devin, OwnedBy: "devin", PolicyKey: "devin"}
	for _, test := range []struct {
		name, account string
		model         provider.ResolvedModel
		want          bool
	}{
		{name: "xai unknown", account: "unknown", model: xai, want: true},
		{name: "xai search false", account: "xai-known", model: xai, want: false},
		{name: "devin unknown", account: "unknown", model: devin, want: true},
		{name: "devin ignores xai search field", account: "devin-known", model: devin, want: true},
		{name: "known snapshot missing model", account: "other-known", model: devin, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := catalog.AccountSupports(context.Background(), test.account, test.model)
			if err != nil || got != test.want {
				t.Fatalf("AccountSupports() = %v, %v; want %v", got, err, test.want)
			}
		})
	}
}
