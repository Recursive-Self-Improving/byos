// Routing semantics adapted from CLIProxyAPI/v7 sdk/cliproxy/auth/selector.go and scheduler.go (MIT).
// Upstream: https://github.com/router-for-me/CLIProxyAPI/tree/v7.2.71/sdk/cliproxy/auth

package routing

import (
	"errors"
	"sync"
	"time"

	"byos/internal/provider"
)

var ErrNoAvailableAccounts = errors.New("no available accounts")
var ErrModelUnavailable = errors.New("requested model is unavailable")

type Candidate struct {
	ID                string
	Provider          provider.Kind
	Enabled, Valid    bool
	Capabilities      map[string]bool
	CapabilitiesKnown bool
	CooldownUntil     map[string]time.Time
}
type Scheduler struct {
	mu      sync.Mutex
	cursors map[string]uint64
}

func NewScheduler() *Scheduler { return &Scheduler{cursors: make(map[string]uint64)} }

// Order retains the provider-agnostic unit-test seam. Production routing uses OrderForProvider.
func (s *Scheduler) Order(model string, accounts []Candidate, preferred string, now time.Time) ([]Candidate, error) {
	return s.order("", model, accounts, preferred, now)
}

// OrderForProvider defensively removes candidates from other providers before capability
// fallback, cooldown checks, affinity, or round-robin cursor mutation.
func (s *Scheduler) OrderForProvider(kind provider.Kind, model string, accounts []Candidate, preferred string, now time.Time) ([]Candidate, error) {
	return s.order(kind, model, accounts, preferred, now)
}

func (s *Scheduler) order(kind provider.Kind, model string, accounts []Candidate, preferred string, now time.Time) ([]Candidate, error) {
	known := make([]Candidate, 0, len(accounts))
	unknown := make([]Candidate, 0, len(accounts))
	for _, account := range accounts {
		if kind.Valid() && account.Provider != kind {
			continue
		}
		if !account.Enabled || !account.Valid {
			continue
		}
		if until := account.CooldownUntil[model]; until.After(now) {
			continue
		}
		if until := account.CooldownUntil["*"]; until.After(now) {
			continue
		}
		if account.CapabilitiesKnown {
			if account.Capabilities[model] {
				known = append(known, account)
			}
		} else {
			unknown = append(unknown, account)
		}
	}
	eligible := known
	if len(eligible) == 0 {
		eligible = unknown
	}
	if len(eligible) == 0 {
		return nil, ErrNoAvailableAccounts
	}
	preferredIndex := -1
	for index, account := range eligible {
		if account.ID == preferred {
			preferredIndex = index
			break
		}
	}
	cursorKey := model
	if kind.Valid() {
		cursorKey = kind.String() + "\x00" + model
	}
	s.mu.Lock()
	cursor := s.cursors[cursorKey] % uint64(len(eligible))
	s.cursors[cursorKey]++
	s.mu.Unlock()
	ordered := make([]Candidate, 0, len(eligible))
	if preferredIndex >= 0 {
		ordered = append(ordered, eligible[preferredIndex])
	}
	for offset := range len(eligible) {
		index := (int(cursor) + offset) % len(eligible)
		if index == preferredIndex {
			continue
		}
		ordered = append(ordered, eligible[index])
	}
	return ordered, nil
}
