package provider

import (
	"fmt"
	"reflect"
)

// CredentialUsabilityRegistration binds a provider kind to its credential
// usability projection for maintenance workers. Registrations are copied into
// RuntimeCredentialUsabilityRegistry at construction time and cannot be changed
// afterward.
type CredentialUsabilityRegistration struct {
	Provider  Kind
	Usability CredentialUsability
}

// RuntimeCredentialUsabilityRegistry is an immutable, purpose-specific
// registry of provider-bound credential usability projections. It is separate
// from RuntimeCapabilityRegistry: it holds no generation, policy, or lifecycle
// capabilities, so a provider whose runtime capability registration is
// lifecycle-only (e.g. Devin until full generation composition) can still
// project credential usability to the refresh worker without registering
// placeholder generation capabilities or violating CapabilityRegistry's
// all-or-none generation trio.
type RuntimeCredentialUsabilityRegistry struct {
	byProvider map[Kind]CredentialUsability
}

// isNilCredentialUsability reports whether value is an untyped nil interface
// or a typed nil (a non-nil interface wrapping a zero pointer, channel, map,
// slice, func, or interface). It mirrors the nil-capable kinds reflect can
// inspect without panicking and is safe to call on any CredentialUsability.
func isNilCredentialUsability(value CredentialUsability) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	}
	return false
}

// NewCredentialUsabilityRegistry validates and copies all usability
// registrations. Each registration must reference a valid provider kind and a
// non-nil usability projection; duplicate provider kinds are rejected. A
// typed-nil usability (a non-nil interface wrapping a zero pointer) is treated
// as nil and rejected.
func NewCredentialUsabilityRegistry(registrations []CredentialUsabilityRegistration) (*RuntimeCredentialUsabilityRegistry, error) {
	byProvider := make(map[Kind]CredentialUsability, len(registrations))
	for _, registration := range registrations {
		if !registration.Provider.Valid() {
			return nil, fmt.Errorf("%w: %w: %q", ErrInvalidCapabilityKey, ErrInvalidKind, registration.Provider)
		}
		if isNilCredentialUsability(registration.Usability) {
			return nil, fmt.Errorf("%w: credential usability must be non-nil for %q", ErrInvalidCapabilities, registration.Provider)
		}
		if _, exists := byProvider[registration.Provider]; exists {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateCapabilityKey, registration.Provider)
		}
		byProvider[registration.Provider] = registration.Usability
	}
	return &RuntimeCredentialUsabilityRegistry{byProvider: byProvider}, nil
}

// CredentialUsability returns the usability projection registered for the exact
// provider kind. An absent registration returns nil, false; callers must not
// substitute another provider's projection.
func (r *RuntimeCredentialUsabilityRegistry) CredentialUsability(provider Kind) (CredentialUsability, bool) {
	if r == nil {
		return nil, false
	}
	usability, ok := r.byProvider[provider]
	return usability, ok
}

var _ CredentialUsabilityRegistry = (*RuntimeCredentialUsabilityRegistry)(nil)
