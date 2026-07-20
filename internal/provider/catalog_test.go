package provider

import (
	"errors"
	"reflect"
	"testing"
)

func requiredModels() []ResolvedModel {
	return []ResolvedModel{
		{PublicName: "grok", UpstreamName: "grok-4.5", Provider: XAI, OwnedBy: "byos", PolicyKey: "xai"},
		{PublicName: "grok-4.5", UpstreamName: "grok-4.5", Provider: XAI, OwnedBy: "xai", PolicyKey: "xai"},
		{PublicName: "kimi-k2-7", UpstreamName: "kimi-k2-7", Provider: Devin, OwnedBy: "devin", PolicyKey: "devin"},
		{PublicName: "glm-5-2", UpstreamName: "glm-5-2", Provider: Devin, OwnedBy: "devin", PolicyKey: "devin"},
		{PublicName: "swe-1-6-slow", UpstreamName: "swe-1-6-slow", Provider: Devin, OwnedBy: "devin", PolicyKey: "devin"},
	}
}

func TestStaticModelCatalogResolvesRequiredModels(t *testing.T) {
	catalog, err := NewStaticModelCatalog(requiredModels())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range requiredModels() {
		t.Run(want.PublicName, func(t *testing.T) {
			got, err := catalog.Resolve(want.PublicName)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("Resolve() = %+v, want %+v", got, want)
			}
		})
	}
}

func TestStaticModelCatalogAllowsCanonicalAliases(t *testing.T) {
	entries := requiredModels()[:2]
	catalog, err := NewStaticModelCatalog(entries)
	if err != nil {
		t.Fatal(err)
	}
	grok, _ := catalog.Resolve("grok")
	canonical, _ := catalog.Resolve("grok-4.5")
	if grok.UpstreamName != canonical.UpstreamName || grok.Provider != canonical.Provider || grok.PolicyKey != canonical.PolicyKey {
		t.Fatalf("aliases do not share canonical identity: %+v %+v", grok, canonical)
	}
	if grok.OwnedBy == canonical.OwnedBy {
		t.Fatal("owned_by should remain per-public-name metadata")
	}
}

func TestStaticModelCatalogRejectsDuplicateAndAmbiguousRegistrations(t *testing.T) {
	base := ResolvedModel{PublicName: "one", UpstreamName: "shared", Provider: XAI, OwnedBy: "xai", PolicyKey: "xai"}
	tests := []struct {
		name    string
		entries []ResolvedModel
		target  error
	}{
		{"identical duplicate public", []ResolvedModel{base, base}, ErrDuplicatePublicModel},
		{"changed duplicate public", []ResolvedModel{base, {PublicName: "one", UpstreamName: "other", Provider: Devin, OwnedBy: "devin", PolicyKey: "devin"}}, ErrDuplicatePublicModel},
		{"different provider", []ResolvedModel{base, {PublicName: "two", UpstreamName: "shared", Provider: Devin, OwnedBy: "devin", PolicyKey: "xai"}}, ErrAmbiguousUpstreamModel},
		{"different policy", []ResolvedModel{base, {PublicName: "two", UpstreamName: "shared", Provider: XAI, OwnedBy: "xai", PolicyKey: "other"}}, ErrAmbiguousUpstreamModel},
		{"different provider and policy", []ResolvedModel{base, {PublicName: "two", UpstreamName: "shared", Provider: Devin, OwnedBy: "devin", PolicyKey: "devin"}}, ErrAmbiguousUpstreamModel},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewStaticModelCatalog(test.entries)
			if !errors.Is(err, test.target) {
				t.Fatalf("error = %v, want %v", err, test.target)
			}
		})
	}
}

func TestStaticModelCatalogRejectsIncompleteEntries(t *testing.T) {
	valid := ResolvedModel{PublicName: "public", UpstreamName: "upstream", Provider: XAI, OwnedBy: "owner", PolicyKey: "policy"}
	tests := []ResolvedModel{
		{UpstreamName: valid.UpstreamName, Provider: valid.Provider, OwnedBy: valid.OwnedBy, PolicyKey: valid.PolicyKey},
		{PublicName: valid.PublicName, Provider: valid.Provider, OwnedBy: valid.OwnedBy, PolicyKey: valid.PolicyKey},
		{PublicName: valid.PublicName, UpstreamName: valid.UpstreamName, Provider: valid.Provider, PolicyKey: valid.PolicyKey},
		{PublicName: valid.PublicName, UpstreamName: valid.UpstreamName, Provider: valid.Provider, OwnedBy: valid.OwnedBy},
		{PublicName: valid.PublicName, UpstreamName: valid.UpstreamName, Provider: Kind("other"), OwnedBy: valid.OwnedBy, PolicyKey: valid.PolicyKey},
		{PublicName: " public", UpstreamName: valid.UpstreamName, Provider: valid.Provider, OwnedBy: valid.OwnedBy, PolicyKey: valid.PolicyKey},
	}
	for i, entry := range tests {
		if _, err := NewStaticModelCatalog([]ResolvedModel{entry}); !errors.Is(err, ErrInvalidModel) {
			t.Errorf("case %d error = %v", i, err)
		}
	}
}

func TestStaticModelCatalogUnknownAndImmutable(t *testing.T) {
	entries := requiredModels()
	catalog, err := NewStaticModelCatalog(entries)
	if err != nil {
		t.Fatal(err)
	}
	entries[0] = ResolvedModel{PublicName: "changed", UpstreamName: "changed", Provider: Devin, OwnedBy: "changed", PolicyKey: "changed"}
	listed := catalog.Models()
	listed[0] = ResolvedModel{}
	want, _ := catalog.Resolve("grok")
	if want.PublicName != "grok" || len(catalog.Models()) != 5 {
		t.Fatal("catalog changed through external slice")
	}
	if _, err := catalog.Resolve("unknown"); !errors.Is(err, ErrUnknownModel) {
		t.Fatalf("error = %v", err)
	}
	if _, err := catalog.Resolve(""); !errors.Is(err, ErrUnknownModel) {
		t.Fatalf("blank error = %v", err)
	}
	if _, err := catalog.Resolve("GROK"); !errors.Is(err, ErrUnknownModel) {
		t.Fatalf("case error = %v", err)
	}
	if got := catalog.Models(); !reflect.DeepEqual(got, []ResolvedModel{requiredModels()[3], requiredModels()[0], requiredModels()[1], requiredModels()[2], requiredModels()[4]}) {
		t.Fatalf("Models() = %+v", got)
	}
}
