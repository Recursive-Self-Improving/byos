package provider

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

var (
	ErrUnknownModel           = errors.New("unknown model")
	ErrInvalidModel           = errors.New("invalid model registration")
	ErrDuplicatePublicModel   = errors.New("duplicate public model")
	ErrAmbiguousUpstreamModel = errors.New("ambiguous upstream model registration")
)

type canonicalModel struct {
	provider  Kind
	policyKey string
}

// StaticModelCatalog is an immutable catalog of validated static model identities.
// Construction copies every entry and exposes no mutation operation.
type StaticModelCatalog struct {
	byPublic map[string]ResolvedModel
	models   []ResolvedModel
}

// NewStaticModelCatalog validates and copies entries into an immutable catalog.
func NewStaticModelCatalog(entries []ResolvedModel) (*StaticModelCatalog, error) {
	byPublic := make(map[string]ResolvedModel, len(entries))
	byUpstream := make(map[string]canonicalModel, len(entries))
	models := make([]ResolvedModel, 0, len(entries))

	for _, entry := range entries {
		if err := validateResolvedModel(entry); err != nil {
			return nil, err
		}
		if _, exists := byPublic[entry.PublicName]; exists {
			return nil, fmt.Errorf("%w: %q", ErrDuplicatePublicModel, entry.PublicName)
		}
		canonical := canonicalModel{provider: entry.Provider, policyKey: entry.PolicyKey}
		if existing, exists := byUpstream[entry.UpstreamName]; exists && existing != canonical {
			return nil, fmt.Errorf("%w: upstream %q is registered as (%s,%s) and (%s,%s)", ErrAmbiguousUpstreamModel, entry.UpstreamName, existing.provider, existing.policyKey, canonical.provider, canonical.policyKey)
		}
		byPublic[entry.PublicName] = entry
		byUpstream[entry.UpstreamName] = canonical
		models = append(models, entry)
	}

	sort.Slice(models, func(i, j int) bool { return models[i].PublicName < models[j].PublicName })
	return &StaticModelCatalog{byPublic: byPublic, models: models}, nil
}

func validateResolvedModel(model ResolvedModel) error {
	fields := []struct {
		name  string
		value string
	}{
		{"public name", model.PublicName},
		{"upstream name", model.UpstreamName},
		{"owned_by", model.OwnedBy},
		{"policy key", model.PolicyKey},
	}
	for _, field := range fields {
		if field.value == "" || field.value != strings.TrimSpace(field.value) {
			return fmt.Errorf("%w: %s must be nonblank and unpadded", ErrInvalidModel, field.name)
		}
	}
	if !model.Provider.Valid() {
		return fmt.Errorf("%w: %w: %q", ErrInvalidModel, ErrInvalidKind, model.Provider)
	}
	return nil
}

// Resolve returns the static identity registered for publicName.
func (c *StaticModelCatalog) Resolve(publicName string) (ResolvedModel, error) {
	if c == nil {
		return ResolvedModel{}, fmt.Errorf("%w: %q", ErrUnknownModel, publicName)
	}
	model, ok := c.byPublic[publicName]
	if !ok {
		return ResolvedModel{}, fmt.Errorf("%w: %q", ErrUnknownModel, publicName)
	}
	return model, nil
}

// Models returns a deterministic defensive copy of all public registrations.
func (c *StaticModelCatalog) Models() []ResolvedModel {
	if c == nil {
		return nil
	}
	return append([]ResolvedModel(nil), c.models...)
}

var _ ModelCatalog = (*StaticModelCatalog)(nil)
