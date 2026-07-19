package models

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"time"

	"byos/internal/config"
	"byos/internal/provider"
	"byos/internal/store"
)

// NewStaticCatalog converts validated configuration entries into the single
// immutable provider model catalog used for static model resolution.
func NewStaticCatalog(entries []config.ModelEntry) (*provider.StaticModelCatalog, error) {
	resolved := make([]provider.ResolvedModel, len(entries))
	for i, entry := range entries {
		kind, err := provider.ParseKind(string(entry.Provider))
		if err != nil {
			return nil, err
		}
		resolved[i] = provider.ResolvedModel{
			PublicName: entry.PublicName, UpstreamName: entry.UpstreamName,
			Provider: kind, OwnedBy: entry.OwnedBy, PolicyKey: entry.PolicyKey,
		}
	}
	return provider.NewStaticModelCatalog(resolved)
}

// StaticCatalogOverlay adds configured one-hop aliases to an immutable static
// catalog without changing its advertised model projection.
type StaticCatalogOverlay struct {
	static  *provider.StaticModelCatalog
	aliases map[string]provider.ResolvedModel
}

// NewStaticCatalogOverlay validates aliases against fixed static ownership.
// Fixed public names always resolve directly; the sole permitted fixed-name
// alias is an identity mapping to the same xAI upstream model.
func NewStaticCatalogOverlay(static *provider.StaticModelCatalog, aliases map[string]string) (*StaticCatalogOverlay, error) {
	if static == nil {
		return nil, errors.New("static model catalog is required")
	}
	overlay := &StaticCatalogOverlay{static: static, aliases: make(map[string]provider.ResolvedModel, len(aliases))}
	for alias, target := range aliases {
		if fixed, err := static.Resolve(alias); err == nil {
			if fixed.Provider == provider.XAI && fixed.UpstreamName == target {
				continue
			}
			return nil, errors.New("model alias conflicts with fixed public model ownership")
		}
		canonical, err := static.Resolve(target)
		if err != nil {
			return nil, provider.ErrUnknownModel
		}
		if canonical.Provider != provider.XAI {
			return nil, errors.New("model alias cannot redirect fixed provider ownership")
		}
		overlay.aliases[alias] = canonical
	}
	return overlay, nil
}

func (c *StaticCatalogOverlay) Resolve(name string) (provider.ResolvedModel, error) {
	if resolved, err := c.static.Resolve(name); err == nil {
		return resolved, nil
	}
	if resolved, ok := c.aliases[name]; ok {
		return resolved, nil
	}
	return provider.ResolvedModel{}, provider.ErrUnknownModel
}

type CapabilityStore interface {
	Replace(context.Context, string, []store.ModelCapability) error
	List(context.Context, string) ([]store.ModelCapability, error)
	MarkStale(context.Context, string) error
}

type Catalog struct {
	repository CapabilityStore
	allowlist  []string
	allowed    map[string]struct{}
	aliases    map[string]string
	now        func() time.Time
}

func NewCatalog(repository CapabilityStore, allowlist []string, aliases map[string]string) *Catalog {
	copyAllowlist := append([]string(nil), allowlist...)
	allowed := make(map[string]struct{}, len(copyAllowlist))
	for _, model := range copyAllowlist {
		allowed[model] = struct{}{}
	}
	copyAliases := make(map[string]string, len(aliases))
	for alias, target := range aliases {
		copyAliases[alias] = target
	}
	return &Catalog{repository: repository, allowlist: copyAllowlist, allowed: allowed, aliases: copyAliases, now: time.Now}
}

func (c *Catalog) Resolve(model string) (string, bool) {
	if target, ok := c.aliases[model]; ok {
		model = target
	}
	_, ok := c.allowed[model]
	return model, ok
}

// ApplyDiscovery normalizes a provider discovery result before persisting it.
func (c *Catalog) ApplyDiscovery(ctx context.Context, accountID string, discovered []provider.DiscoveredModel, discoveryErr error) ([]Model, error) {
	models := make([]Model, 0, len(discovered))
	for _, model := range discovered {
		var supportsSearch *bool
		if model.SupportsBackendSearch != nil {
			value := *model.SupportsBackendSearch
			supportsSearch = &value
		}
		models = append(models, Model{
			ID: model.UpstreamName, DisplayName: model.DisplayName,
			SupportsBackendSearch: supportsSearch, ContextWindow: model.ContextWindow,
			MaxOutputTokens:  model.MaxOutputTokens,
			ReasoningEfforts: append([]string(nil), model.ReasoningEfforts...),
		})
	}
	return c.RefreshFromModels(ctx, accountID, models, discoveryErr)
}

// RefreshFromModels applies a normalized discovery result. Failed discovery
// retains the previous snapshot, marks it stale, and returns that snapshot
// together with the discovery error.
func (c *Catalog) RefreshFromModels(ctx context.Context, accountID string, models []Model, discoveryErr error) ([]Model, error) {
	err := discoveryErr
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

// AccountSupports reports whether an account's capability snapshot permits the
// resolved model. An absent snapshot is unknown and therefore routable. Search
// capability is an xAI-only requirement; other providers keep their own
// capability semantics independent of xAI discovery.
func (c *Catalog) AccountSupports(ctx context.Context, accountID string, resolved provider.ResolvedModel) (bool, error) {
	values, err := c.repository.List(ctx, accountID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return true, nil
		}
		return false, err
	}
	if len(values) == 0 {
		return true, nil
	}
	for _, value := range values {
		if value.Model != resolved.UpstreamName || !value.Supported {
			continue
		}
		if resolved.Provider == provider.XAI && value.SupportsBackendSearch != nil && !*value.SupportsBackendSearch {
			return false, nil
		}
		return true, nil
	}
	return false, nil
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
