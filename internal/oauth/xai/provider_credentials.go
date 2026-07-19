package xai

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"byos/internal/provider"
	"byos/internal/store"
)

// AccountRefresher is the generation credential lifecycle operation supplied by
// RefreshService. It is intentionally narrower than the OAuth flow.
type AccountRefresher interface {
	Refresh(context.Context, string) (store.Account, error)
}

// ProviderCredentialManager adapts stored xAI OAuth credentials to the
// provider-neutral generation credential contract.
type ProviderCredentialManager struct {
	accounts  *store.AccountRepository
	refresher AccountRefresher
	now       func() time.Time
}

func NewProviderCredentialManager(accounts *store.AccountRepository, refresher AccountRefresher) *ProviderCredentialManager {
	return &ProviderCredentialManager{accounts: accounts, refresher: refresher, now: func() time.Time { return time.Now().UTC() }}
}

// CredentialUsable reports whether the stored account can produce a credential
// if selected. It neither returns credential material nor refreshes the account.
func (m *ProviderCredentialManager) CredentialUsable(ctx context.Context, accountID string) (bool, error) {
	account, err := m.accounts.Get(ctx, accountID)
	if err != nil {
		return false, err
	}
	if account.Provider != provider.XAI {
		return false, fmt.Errorf("account %q is not an xAI account", accountID)
	}
	if !account.Enabled || account.Status != "ready" {
		return false, nil
	}
	return CredentialsUsable(account, m.now()), nil
}

func (m *ProviderCredentialManager) Credential(ctx context.Context, accountID string) (provider.Credential, error) {
	account, err := m.accounts.Get(ctx, accountID)
	if err != nil {
		return provider.Credential{}, err
	}
	if account.Provider != provider.XAI {
		return provider.Credential{}, fmt.Errorf("account %q is not an xAI account", accountID)
	}
	if !account.Enabled || account.Status != "ready" {
		return provider.Credential{}, errors.New("xAI account is not ready")
	}
	if NeedsRefresh(account, m.now()) {
		if m.refresher == nil {
			return provider.Credential{}, errors.New("xAI credential refresh is unavailable")
		}
		account, err = m.refresher.Refresh(ctx, accountID)
		if err != nil {
			return provider.Credential{}, providerCredentialError(err)
		}
	}
	token := strings.TrimSpace(account.Credentials.AccessToken)
	if token == "" {
		return provider.Credential{}, errors.New("xAI account has no access token")
	}
	return provider.Credential{Value: token}, nil
}

func (m *ProviderCredentialManager) AuthenticationFailed(ctx context.Context, accountID string, upstream *provider.UpstreamError) error {
	if upstream == nil || upstream.Provider != provider.XAI || upstream.Classification.Class != provider.ClassUnauthorized {
		return errors.New("xAI authentication recovery requires an unauthorized xAI error")
	}
	if m.refresher == nil {
		return errors.New("xAI credential refresh is unavailable")
	}
	_, err := m.refresher.Refresh(ctx, accountID)
	return providerCredentialError(err)
}

func providerCredentialError(err error) error {
	if err == nil {
		return nil
	}
	var oauthErr *OAuthError
	if errors.As(err, &oauthErr) && oauthErr.Code == "invalid_grant" {
		return &provider.UpstreamError{Provider: provider.XAI, Status: 401, Classification: provider.ErrorClassification{
			Class: provider.ClassInvalidGrant, RetryNext: true, DisableAccount: true, ReloginRequired: true,
			CooldownScope: provider.CooldownAccount, PublicStatus: 401, PublicCode: "provider_authentication_error", PublicMessage: "account requires login",
		}}
	}
	return err
}

var _ provider.CredentialManager = (*ProviderCredentialManager)(nil)
var _ provider.CredentialUsability = (*ProviderCredentialManager)(nil)
