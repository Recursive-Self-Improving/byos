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
		"grok":         {PublicName: "grok", UpstreamName: "grok-4.5", Provider: provider.XAI, OwnedBy: "byos", PolicyKey: "xai"},
		"grok-4.5":     {PublicName: "grok-4.5", UpstreamName: "grok-4.5", Provider: provider.XAI, OwnedBy: "xai", PolicyKey: "xai"},
		"kimi-k2-7":    {PublicName: "kimi-k2-7", UpstreamName: "kimi-k2-7", Provider: provider.Devin, OwnedBy: "devin", PolicyKey: "devin"},
		"glm-5-2":      {PublicName: "glm-5-2", UpstreamName: "glm-5-2", Provider: provider.Devin, OwnedBy: "devin", PolicyKey: "devin"},
		"swe-1-6-slow": {PublicName: "swe-1-6-slow", UpstreamName: "swe-1-6-slow", Provider: provider.Devin, OwnedBy: "devin", PolicyKey: "devin"},
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
		"devin-known": {{Model: "kimi-k2-7", Supported: true, SupportsBackendSearch: &searchFalse}},
		"other-known": {{Model: "other", Supported: true}},
	}}
	catalog := NewCatalog(store, nil, nil, nil)
	xai := provider.ResolvedModel{PublicName: "grok", UpstreamName: "grok-4.5", Provider: provider.XAI, OwnedBy: "byos", PolicyKey: "xai"}
	devin := provider.ResolvedModel{PublicName: "kimi-k2-7", UpstreamName: "kimi-k2-7", Provider: provider.Devin, OwnedBy: "devin", PolicyKey: "devin"}
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
