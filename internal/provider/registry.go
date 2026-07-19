package provider

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrInvalidCapabilityKey   = errors.New("invalid capability key")
	ErrInvalidCapabilities    = errors.New("invalid capabilities")
	ErrDuplicateCapabilityKey = errors.New("duplicate capability key")
)

// CapabilityRegistration binds one provider and policy key to its runtime
// implementations. Registrations are copied into CapabilityRegistry at
// construction time and cannot be changed afterward.
type CapabilityRegistration struct {
	Provider     Kind
	PolicyKey    string
	Capabilities Capabilities
}

type capabilityKey struct {
	provider  Kind
	policyKey string
}

// RuntimeCapabilityRegistry is an immutable registry of runtime provider
// behavior. Its contents are fully constructed before publication.
type RuntimeCapabilityRegistry struct {
	byKey map[capabilityKey]Capabilities
}

// NewCapabilityRegistry validates and copies all runtime registrations.
func NewCapabilityRegistry(registrations []CapabilityRegistration) (*RuntimeCapabilityRegistry, error) {
	byKey := make(map[capabilityKey]Capabilities, len(registrations))
	for _, registration := range registrations {
		if !registration.Provider.Valid() {
			return nil, fmt.Errorf("%w: %w: %q", ErrInvalidCapabilityKey, ErrInvalidKind, registration.Provider)
		}
		if registration.PolicyKey == "" || registration.PolicyKey != strings.TrimSpace(registration.PolicyKey) {
			return nil, fmt.Errorf("%w: policy key must be nonblank and unpadded", ErrInvalidCapabilityKey)
		}
		if err := validateCapabilities(registration.Capabilities); err != nil {
			return nil, err
		}
		key := capabilityKey{provider: registration.Provider, policyKey: registration.PolicyKey}
		if _, exists := byKey[key]; exists {
			return nil, fmt.Errorf("%w: (%s,%s)", ErrDuplicateCapabilityKey, key.provider, key.policyKey)
		}
		byKey[key] = registration.Capabilities
	}
	return &RuntimeCapabilityRegistry{byKey: byKey}, nil
}

func validateCapabilities(capabilities Capabilities) error {
	hasPolicy := capabilities.Policy != nil
	hasGeneration := capabilities.Generation != nil
	hasCredentials := capabilities.Credentials != nil
	hasGenerationCapability := hasPolicy || hasGeneration || hasCredentials
	if hasGenerationCapability && !(hasPolicy && hasGeneration && hasCredentials) {
		return fmt.Errorf("%w: policy, generation client, and credentials must be registered together", ErrInvalidCapabilities)
	}
	if !hasGenerationCapability && capabilities.ModelDiscoverer == nil && capabilities.UsageFetcher == nil {
		return fmt.Errorf("%w: registration must contain at least one capability", ErrInvalidCapabilities)
	}
	return nil
}

// Capabilities returns the runtime implementations registered for provider and
// policyKey. The returned value is a copy of the registry entry.
func (r *RuntimeCapabilityRegistry) Capabilities(provider Kind, policyKey string) (Capabilities, bool) {
	if r == nil {
		return Capabilities{}, false
	}
	capabilities, ok := r.byKey[capabilityKey{provider: provider, policyKey: policyKey}]
	return capabilities, ok
}

var _ CapabilityRegistry = (*RuntimeCapabilityRegistry)(nil)
