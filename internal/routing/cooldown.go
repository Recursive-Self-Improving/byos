// Cooldown transitions adapted from CLIProxyAPI/v7 sdk/cliproxy/auth/conductor.go (MIT).
// Upstream: https://github.com/router-for-me/CLIProxyAPI/blob/v7.2.71/sdk/cliproxy/auth/conductor.go

package routing

import (
	"context"
	"time"

	"byos/internal/store"
)

type CooldownManager struct {
	states   *store.CooldownRepository
	accounts *store.AccountRepository
	now      func() time.Time
}

func NewCooldownManager(states *store.CooldownRepository, accounts *store.AccountRepository) *CooldownManager {
	return &CooldownManager{states: states, accounts: accounts, now: func() time.Time { return time.Now().UTC() }}
}
func (m *CooldownManager) Apply(ctx context.Context, accountID, model string, classified ClassifiedError) error {
	now := m.now()
	if classified.DisableAccount {
		account, err := m.accounts.Get(ctx, accountID)
		if err != nil {
			return err
		}
		return m.accounts.Update(ctx, accountID, account.Label, false)
	}
	if classified.Cooldown <= 0 && classified.Class != ClassRateLimit {
		return nil
	}
	scope := model
	if classified.AccountWide {
		scope = "*"
	}
	backoff := 0
	duration := classified.Cooldown
	if classified.Class == ClassRateLimit && classified.ExplicitRetryAfter && duration <= 0 {
		return nil
	}
	if classified.Class == ClassRateLimit && !classified.ExplicitRetryAfter {
		_, err := m.states.AdvanceRateLimit(ctx, accountID, scope, string(classified.Class), now)
		return err
	}
	until := now.Add(duration)
	last := now
	return m.states.Put(ctx, store.Cooldown{AccountID: accountID, Model: scope, Until: &until, BackoffLevel: backoff, LastErrorClass: string(classified.Class), LastErrorAt: &last})
}
func (m *CooldownManager) Success(ctx context.Context, accountID, model string) error {
	return m.states.Ready(ctx, accountID, model)
}
