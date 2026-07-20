package provider

import (
	"context"
	"errors"
	"testing"
	"time"
)

type registryTestPolicy struct{ id string }

func (*registryTestPolicy) Prepare(context.Context, ResolvedModel, CanonicalRequest) error {
	return nil
}

type registryTestClient struct{}

func (registryTestClient) Execute(context.Context, GenerationRequest) ([]Event, error) {
	return nil, nil
}
func (registryTestClient) Stream(context.Context, GenerationRequest) (Stream, error) { return nil, nil }

type registryTestCredentials struct{}

func (registryTestCredentials) Credential(context.Context, string) (Credential, error) {
	return Credential{}, nil
}
func (registryTestCredentials) AuthenticationFailed(context.Context, string, *UpstreamError) error {
	return nil
}

func generationCapabilities(policy RequestPolicy) Capabilities {
	return Capabilities{Policy: policy, Generation: registryTestClient{}, Credentials: registryTestCredentials{}}
}

type registryTestLifecycle struct{}

func (registryTestLifecycle) Start(context.Context) (Authorization, error) {
	return Authorization{Ref: AuthorizationRef{Provider: XAI}}, nil
}
func (registryTestLifecycle) Status(context.Context, AuthorizationRef) (AuthorizationSession, error) {
	return AuthorizationSession{}, nil
}
func (registryTestLifecycle) Complete(context.Context, AuthorizationRef, AuthorizationCompletion) (AccountResult, error) {
	return AccountResult{Provider: XAI}, nil
}
func (registryTestLifecycle) Cancel(context.Context, AuthorizationRef) error         { return nil }
func (registryTestLifecycle) Resume(context.Context) ([]AuthorizationSession, error) { return nil, nil }

type registryTestRefresher struct{}

func (registryTestRefresher) NeedsRefresh(context.Context, string, time.Time) (bool, error) {
	return false, nil
}
func (registryTestRefresher) Refresh(context.Context, string) error { return nil }

type registryTestDiscoverer struct{}

func (registryTestDiscoverer) Discover(context.Context, Credential) ([]DiscoveredModel, error) {
	return nil, nil
}

func TestCapabilityRegistryResolvesProviderAndPolicyKey(t *testing.T) {
	xaiPolicy := &registryTestPolicy{id: "xai"}
	devinPolicy := &registryTestPolicy{id: "devin"}
	registrations := []CapabilityRegistration{
		{Provider: XAI, PolicyKey: "generation", Capabilities: generationCapabilities(xaiPolicy)},
		{Provider: Devin, PolicyKey: "generation", Capabilities: generationCapabilities(devinPolicy)},
	}
	registry, err := NewCapabilityRegistry(registrations)
	if err != nil {
		t.Fatal(err)
	}

	registrations[0] = CapabilityRegistration{}
	got, ok := registry.Capabilities(XAI, "generation")
	if !ok || got.Policy != xaiPolicy {
		t.Fatalf("xAI capabilities = %#v, %v", got, ok)
	}
	got, ok = registry.Capabilities(Devin, "generation")
	if !ok || got.Policy != devinPolicy {
		t.Fatalf("Devin capabilities = %#v, %v", got, ok)
	}
	if _, ok := registry.Capabilities(XAI, "missing"); ok {
		t.Fatal("unregistered policy key resolved")
	}
	if _, ok := registry.Capabilities(Kind("other"), "generation"); ok {
		t.Fatal("unregistered provider resolved")
	}
}

func TestCapabilityRegistryRejectsMissingKeys(t *testing.T) {
	tests := []CapabilityRegistration{
		{PolicyKey: "xai"},
		{Provider: XAI},
		{Provider: XAI, PolicyKey: " "},
		{Provider: XAI, PolicyKey: " xai"},
		{Provider: Kind("other"), PolicyKey: "xai"},
	}
	for _, registration := range tests {
		if _, err := NewCapabilityRegistry([]CapabilityRegistration{registration}); !errors.Is(err, ErrInvalidCapabilityKey) {
			t.Fatalf("registration %#v: error = %v, want %v", registration, err, ErrInvalidCapabilityKey)
		}
	}
}

func TestCapabilityRegistryRejectsDuplicateKeys(t *testing.T) {
	registrations := []CapabilityRegistration{
		{Provider: XAI, PolicyKey: "xai", Capabilities: generationCapabilities(&registryTestPolicy{id: "first"})},
		{Provider: XAI, PolicyKey: "xai", Capabilities: generationCapabilities(&registryTestPolicy{id: "second"})},
	}
	if _, err := NewCapabilityRegistry(registrations); !errors.Is(err, ErrDuplicateCapabilityKey) {
		t.Fatalf("error = %v, want %v", err, ErrDuplicateCapabilityKey)
	}
}

func TestCapabilityRegistryRejectsEmptyAndPartialCapabilities(t *testing.T) {
	policy := &registryTestPolicy{id: "xai"}
	tests := []Capabilities{
		{},
		{Policy: policy},
		{Generation: registryTestClient{}},
		{Credentials: registryTestCredentials{}},
		{Policy: policy, Generation: registryTestClient{}},
		{Policy: policy, Credentials: registryTestCredentials{}},
		{Generation: registryTestClient{}, Credentials: registryTestCredentials{}},
	}
	for _, capabilities := range tests {
		registration := CapabilityRegistration{Provider: XAI, PolicyKey: "xai", Capabilities: capabilities}
		if _, err := NewCapabilityRegistry([]CapabilityRegistration{registration}); !errors.Is(err, ErrInvalidCapabilities) {
			t.Fatalf("capabilities %#v: error = %v, want %v", capabilities, err, ErrInvalidCapabilities)
		}
	}
}

func TestCredentialRefreshRegistryAcceptsAndBindsRefreshOnlyRegistration(t *testing.T) {
	refresher := registryTestRefresher{}
	registry, err := NewCapabilityRegistry([]CapabilityRegistration{
		{Provider: XAI, PolicyKey: "xai", Capabilities: Capabilities{CredentialRefresher: refresher}},
		{Provider: Devin, PolicyKey: "devin", Capabilities: generationCapabilities(&registryTestPolicy{id: "devin"})},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := registry.CredentialRefresher(XAI, "xai")
	if !ok || got != refresher {
		t.Fatalf("credential refresher = %#v, %v", got, ok)
	}
	for _, key := range []struct {
		provider Kind
		policy   string
	}{{Devin, "xai"}, {XAI, "devin"}, {Devin, "devin"}} {
		if got, ok := registry.CredentialRefresher(key.provider, key.policy); ok || got != nil {
			t.Fatalf("unexpected credential refresher for (%s,%s): %#v, %v", key.provider, key.policy, got, ok)
		}
	}
}

func TestCapabilityRegistryAcceptsDiscoveryOnlyRegistration(t *testing.T) {
	registry, err := NewCapabilityRegistry([]CapabilityRegistration{{
		Provider: XAI, PolicyKey: "discovery", Capabilities: Capabilities{ModelDiscoverer: registryTestDiscoverer{}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.Capabilities(XAI, "discovery"); !ok {
		t.Fatal("discovery-only registration missing")
	}
}

func TestLifecycleRegistryAcceptsAndBindsLifecycleOnlyRegistration(t *testing.T) {
	lifecycle := registryTestLifecycle{}
	registry, err := NewCapabilityRegistry([]CapabilityRegistration{
		{Provider: XAI, PolicyKey: "account", Capabilities: Capabilities{Lifecycle: lifecycle}},
		{Provider: Devin, PolicyKey: "generation", Capabilities: generationCapabilities(&registryTestPolicy{id: "devin"})},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := registry.Lifecycle(XAI, "account")
	if !ok || got != lifecycle {
		t.Fatalf("lifecycle = %#v, %v", got, ok)
	}
	for _, key := range []struct {
		provider Kind
		policy   string
	}{{Devin, "account"}, {XAI, "generation"}, {Devin, "generation"}} {
		if got, ok := registry.Lifecycle(key.provider, key.policy); ok || got != nil {
			t.Fatalf("unexpected lifecycle for (%s,%s): %#v, %v", key.provider, key.policy, got, ok)
		}
	}
}

func TestLifecycleRegistryAcceptsLifecycleAlongsideGeneration(t *testing.T) {
	capabilities := generationCapabilities(&registryTestPolicy{id: "xai"})
	capabilities.Lifecycle = registryTestLifecycle{}
	registry, err := NewCapabilityRegistry([]CapabilityRegistration{{Provider: XAI, PolicyKey: "xai", Capabilities: capabilities}})
	if err != nil {
		t.Fatal(err)
	}
	if lifecycle, ok := registry.Lifecycle(XAI, "xai"); !ok || lifecycle == nil {
		t.Fatal("combined generation and lifecycle registration did not resolve lifecycle")
	}
}

func TestNilRuntimeCapabilityRegistryDoesNotResolveOptionalInterfaces(t *testing.T) {
	var registry *RuntimeCapabilityRegistry
	if _, ok := registry.Capabilities(XAI, "xai"); ok {
		t.Fatal("nil registry resolved capabilities")
	}
	if lifecycle, ok := registry.Lifecycle(XAI, "xai"); ok || lifecycle != nil {
		t.Fatal("nil registry resolved lifecycle")
	}
	if refresher, ok := registry.CredentialRefresher(XAI, "xai"); ok || refresher != nil {
		t.Fatal("nil registry resolved credential refresher")
	}
}
