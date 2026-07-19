package provider

import (
	"context"
	"errors"
	"testing"
)

// registryTestUsability is a pointer-receiver CredentialUsability so a zero
// *registryTestUsability can model a typed-nil interface value.
type registryTestUsability struct{}

func (*registryTestUsability) CredentialUsable(context.Context, string) (bool, error) {
	return true, nil
}

func TestCredentialUsabilityRegistryAcceptsValidRegistrationAndResolvesExactKind(t *testing.T) {
	usable := fakeCredentials{}
	registry, err := NewCredentialUsabilityRegistry([]CredentialUsabilityRegistration{
		{Provider: XAI, Usability: usable},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, ok := registry.CredentialUsability(XAI)
	if !ok {
		t.Fatal("registered provider not resolved")
	}
	if got != usable {
		t.Fatalf("resolved usability = %#v, want %#v", got, usable)
	}
	if _, ok := registry.CredentialUsability(Devin); ok {
		t.Fatal("unregistered provider resolved")
	}
}

func TestCredentialUsabilityRegistryRejectsPlainNilUsability(t *testing.T) {
	registration := CredentialUsabilityRegistration{Provider: XAI, Usability: nil}
	if _, err := NewCredentialUsabilityRegistry([]CredentialUsabilityRegistration{registration}); !errors.Is(err, ErrInvalidCapabilities) {
		t.Fatalf("plain nil usability: error = %v, want %v", err, ErrInvalidCapabilities)
	}
}

func TestCredentialUsabilityRegistryRejectsTypedNilUsability(t *testing.T) {
	var typedNilUsability *registryTestUsability
	registration := CredentialUsabilityRegistration{Provider: XAI, Usability: typedNilUsability}
	if registration.Usability == nil {
		t.Fatal("typed nil usability must not equal plain nil interface")
	}
	if _, err := NewCredentialUsabilityRegistry([]CredentialUsabilityRegistration{registration}); !errors.Is(err, ErrInvalidCapabilities) {
		t.Fatalf("typed nil usability: error = %v, want %v", err, ErrInvalidCapabilities)
	}
}

func TestCredentialUsabilityRegistryRejectsDuplicateProviderKind(t *testing.T) {
	registrations := []CredentialUsabilityRegistration{
		{Provider: XAI, Usability: fakeCredentials{}},
		{Provider: XAI, Usability: fakeCredentials{}},
	}
	if _, err := NewCredentialUsabilityRegistry(registrations); !errors.Is(err, ErrDuplicateCapabilityKey) {
		t.Fatalf("duplicate kind: error = %v, want %v", err, ErrDuplicateCapabilityKey)
	}
}

func TestCredentialUsabilityRegistryRejectsInvalidProviderKind(t *testing.T) {
	registration := CredentialUsabilityRegistration{Provider: Kind("other"), Usability: fakeCredentials{}}
	if _, err := NewCredentialUsabilityRegistry([]CredentialUsabilityRegistration{registration}); !errors.Is(err, ErrInvalidCapabilityKey) {
		t.Fatalf("invalid kind: error = %v, want %v", err, ErrInvalidCapabilityKey)
	}
}
