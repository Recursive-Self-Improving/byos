package devin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"byos/internal/provider"
	"byos/internal/store"
)

// ProviderCredentialManager adapts stored Devin opaque tokens to the
// provider-neutral credential contract. Devin credentials cannot be refreshed;
// an authentication failure requires the account to be authorized again.
type ProviderCredentialManager struct {
	accounts *store.AccountRepository
	now      func() time.Time
}

func NewProviderCredentialManager(accounts *store.AccountRepository) *ProviderCredentialManager {
	return &ProviderCredentialManager{accounts: accounts, now: func() time.Time { return time.Now().UTC() }}
}

// CredentialUsable reports whether the stored account can yield a credential
// without returning the opaque token.
func (m *ProviderCredentialManager) CredentialUsable(ctx context.Context, accountID string) (bool, error) {
	_, usable, err := m.usableCredential(ctx, accountID)
	return usable, err
}

func (m *ProviderCredentialManager) Credential(ctx context.Context, accountID string) (provider.Credential, error) {
	account, usable, err := m.usableCredential(ctx, accountID)
	if err != nil {
		return provider.Credential{}, err
	}
	if !usable {
		return provider.Credential{}, errors.New("Devin credential is unavailable or expired")
	}
	return provider.Credential{Value: account.Credentials.OpaqueToken}, nil
}

func (m *ProviderCredentialManager) AuthenticationFailed(ctx context.Context, accountID string, upstream *provider.UpstreamError) error {
	if upstream == nil || (upstream.Status != http.StatusUnauthorized && upstream.Status != http.StatusForbidden) {
		return nil
	}
	if upstream.Provider != provider.Devin {
		return fmt.Errorf("Devin authentication recovery: %w", provider.ErrProviderMismatch)
	}
	if _, err := m.devinAccount(ctx, accountID); err != nil {
		return err
	}
	if err := m.accounts.MarkReloginRequired(ctx, accountID, provider.Devin); err != nil {
		return errors.New("Devin account could not be marked for login")
	}
	return &provider.UpstreamError{
		Provider: provider.Devin,
		Status:   upstream.Status,
		Classification: provider.ErrorClassification{
			Class:           provider.ClassUnauthorized,
			RetryNext:       true,
			DisableAccount:  true,
			ReloginRequired: true,
			CooldownScope:   provider.CooldownAccount,
			PublicStatus:    http.StatusUnauthorized,
			PublicCode:      "provider_authentication_error",
			PublicMessage:   "account requires login",
		},
	}
}

func (m *ProviderCredentialManager) usableCredential(ctx context.Context, accountID string) (store.Account, bool, error) {
	account, err := m.devinAccount(ctx, accountID)
	if err != nil {
		return store.Account{}, false, err
	}
	if !account.Enabled || account.Status != "ready" {
		return account, false, nil
	}
	if devinCredentialUsable(account, m.now()) {
		return account, true, nil
	}
	if err := m.accounts.MarkReloginRequired(ctx, accountID, provider.Devin); err != nil {
		return store.Account{}, false, errors.New("Devin account could not be marked for login")
	}
	return account, false, nil
}

func (m *ProviderCredentialManager) devinAccount(ctx context.Context, accountID string) (store.Account, error) {
	if m == nil || m.accounts == nil {
		return store.Account{}, errors.New("Devin credentials are unavailable")
	}
	account, err := m.accounts.Get(ctx, accountID)
	if err != nil {
		return store.Account{}, errors.New("Devin account could not be loaded")
	}
	if account.Provider != provider.Devin {
		return store.Account{}, fmt.Errorf("account is not a Devin account: %w", provider.ErrProviderMismatch)
	}
	return account, nil
}

func devinCredentialUsable(account store.Account, now time.Time) bool {
	token := strings.TrimSpace(account.Credentials.OpaqueToken)
	if token == "" || account.ExpiresAt == nil {
		return false
	}
	return Usable(*account.ExpiresAt, now)
}

var _ provider.CredentialManager = (*ProviderCredentialManager)(nil)
var _ provider.CredentialUsability = (*ProviderCredentialManager)(nil)
