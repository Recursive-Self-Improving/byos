package models

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"time"

	"byos/internal/store"
)

type CapabilityStore interface {
	Replace(context.Context, string, []store.ModelCapability) error
	List(context.Context, string) ([]store.ModelCapability, error)
	MarkStale(context.Context, string) error
}

type Discoverer interface {
	Discover(context.Context, string) ([]Model, error)
}

type Catalog struct {
	repository CapabilityStore
	discoverer Discoverer
	allowlist  []string
	allowed    map[string]struct{}
	aliases    map[string]string
	now        func() time.Time
}

func NewCatalog(repository CapabilityStore, discoverer Discoverer, allowlist []string, aliases map[string]string) *Catalog {
	copyAllowlist := append([]string(nil), allowlist...)
	allowed := make(map[string]struct{}, len(copyAllowlist))
	for _, model := range copyAllowlist {
		allowed[model] = struct{}{}
	}
	copyAliases := make(map[string]string, len(aliases))
	for alias, target := range aliases {
		copyAliases[alias] = target
	}
	return &Catalog{repository: repository, discoverer: discoverer, allowlist: copyAllowlist, allowed: allowed, aliases: copyAliases, now: time.Now}
}

func (c *Catalog) Resolve(model string) (string, bool) {
	if target, ok := c.aliases[model]; ok {
		model = target
	}
	_, ok := c.allowed[model]
	return model, ok
}

func (c *Catalog) Refresh(ctx context.Context, accountID, token string) ([]Model, error) {
	models, err := c.discoverer.Discover(ctx, token)
	if err != nil {
		if staleErr := c.repository.MarkStale(ctx, accountID); staleErr != nil {
			return nil, errors.Join(err, staleErr)
		}
		stale, staleErr := c.Capabilities(ctx, accountID)
		if staleErr != nil {
			return nil, errors.Join(err, staleErr)
		}
		models := make([]Model, 0, len(stale))
		for _, capability := range stale {
			if !capability.Stale {
				return nil, errors.Join(err, ErrStaleState)
			}
			if capability.Supported {
				models = append(models, capability.Model)
			}
		}
		return models, err
	}
	now := c.now().UTC()
	values := make([]store.ModelCapability, 0, len(models))
	for _, model := range models {
		values = append(values, store.ModelCapability{AccountID: accountID, Model: model.ID, DisplayName: model.DisplayName, Supported: true, SupportsBackendSearch: model.SupportsBackendSearch, ContextWindow: model.ContextWindow, MaxOutputTokens: model.MaxOutputTokens, ReasoningEfforts: append([]string(nil), model.ReasoningEfforts...), DiscoveredAt: now})
	}
	if len(values) == 0 {
		values = append(values, store.ModelCapability{AccountID: accountID, Model: "", Supported: false, DiscoveredAt: now})
	}
	if err := c.repository.Replace(ctx, accountID, values); err != nil {
		return nil, err
	}
	return models, nil
}

func (c *Catalog) Capabilities(ctx context.Context, accountID string) ([]Capability, error) {
	values, err := c.repository.List(ctx, accountID)
	if err != nil {
		return nil, err
	}
	result := make([]Capability, 0, len(values))
	for _, value := range values {
		if value.Model == "" {
			continue
		}
		result = append(result, Capability{Model: Model{ID: value.Model, DisplayName: value.DisplayName, ContextWindow: value.ContextWindow, MaxOutputTokens: value.MaxOutputTokens, ReasoningEfforts: append([]string(nil), value.ReasoningEfforts...), SupportsBackendSearch: value.SupportsBackendSearch}, Supported: value.Supported, DiscoveredAt: value.DiscoveredAt, Stale: value.Stale})
	}
	return result, nil
}

// Public returns the configured allowlist intersected with at least one enabled
// account snapshot. If no enabled account has any snapshot, it returns the
// allowlist so startup and temporary discovery outages remain routable.
func (c *Catalog) Public(ctx context.Context, enabledAccountIDs []string) ([]PublicModel, error) {
	supported := make(map[string]bool)
	hasSnapshot := false
	for _, accountID := range enabledAccountIDs {
		values, err := c.repository.List(ctx, accountID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return nil, err
		}
		if len(values) > 0 {
			hasSnapshot = true
		}
		for _, value := range values {
			if value.Supported && (value.SupportsBackendSearch == nil || *value.SupportsBackendSearch) {
				supported[value.Model] = true
			}
		}
	}
	result := make([]PublicModel, 0, len(c.allowlist)+len(c.aliases))
	for _, model := range c.allowlist {
		if !hasSnapshot || supported[model] {
			result = append(result, PublicModel{ID: model, Object: "model", OwnedBy: "xai"})
		}
	}
	for alias, target := range c.aliases {
		if _, allowed := c.allowed[target]; allowed && (!hasSnapshot || supported[target]) {
			result = append(result, PublicModel{ID: alias, Object: "model", OwnedBy: "byos", AliasOf: target})
		}
	}
	sort.Slice(result, func(i, j int) bool { return strings.Compare(result[i].ID, result[j].ID) < 0 })
	return result, nil
}
