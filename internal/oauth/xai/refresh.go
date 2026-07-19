// Portions adapted from CLIProxyAPI/v7 internal/auth/xai/xai.go (MIT): refresh-token exchange and invalid-grant handling.
// Upstream: https://github.com/router-for-me/CLIProxyAPI/blob/v7.2.71/internal/auth/xai/xai.go

package xai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"

	"byos/internal/provider"
	"byos/internal/store"
)

type RefreshService struct {
	http     *http.Client
	accounts *store.AccountRepository
	options  Options
	now      func() time.Time
	group    singleflight.Group
}

func NewRefreshService(client *http.Client, accounts *store.AccountRepository, options Options) *RefreshService {
	client = secureOAuthClient(client)
	return &RefreshService{http: client, accounts: accounts, options: options.withDefaults(), now: func() time.Time { return time.Now().UTC() }}
}
func CredentialsUsable(account store.Account, now time.Time) bool {
	if strings.TrimSpace(account.Credentials.AccessToken) == "" {
		return false
	}
	if !NeedsRefresh(account, now) {
		return true
	}
	return strings.TrimSpace(account.Credentials.RefreshToken) != "" && strings.TrimSpace(account.Credentials.TokenEndpoint) != ""
}

func (s *RefreshService) Refresh(ctx context.Context, accountID string) (store.Account, error) {
	value, err, _ := s.group.Do(accountID, func() (any, error) { return s.refresh(ctx, accountID) })
	if err != nil {
		return store.Account{}, err
	}
	return value.(store.Account), nil
}
func (s *RefreshService) refresh(ctx context.Context, accountID string) (store.Account, error) {
	account, err := s.accounts.Get(ctx, accountID)
	if err != nil {
		return store.Account{}, err
	}
	if account.Provider != provider.XAI {
		return store.Account{}, fmt.Errorf("account %q is not an xAI account: %w", accountID, provider.ErrProviderMismatch)
	}
	credentials := account.Credentials
	if strings.TrimSpace(credentials.RefreshToken) == "" {
		return store.Account{}, errors.New("account has no refresh token")
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {credentials.RefreshToken}, "client_id": {s.options.ClientID}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, credentials.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return store.Account{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := s.http.Do(request)
	if err != nil {
		return store.Account{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return store.Account{}, err
	}
	var payload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int    `json:"expires_in"`
		Error        string `json:"error"`
		Description  string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return store.Account{}, errors.New("invalid xAI refresh response")
	}
	if payload.Error == "invalid_grant" {
		oauthErr := &OAuthError{Code: "invalid_grant", Description: payload.Description}
		return store.Account{}, errors.Join(oauthErr, s.accounts.MarkReloginRequired(ctx, account.ID, provider.XAI))
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || payload.AccessToken == "" {
		return store.Account{}, fmt.Errorf("xAI refresh returned HTTP %d", response.StatusCode)
	}
	credentials.AccessToken = payload.AccessToken
	if payload.RefreshToken != "" {
		credentials.RefreshToken = payload.RefreshToken
	}
	if payload.IDToken != "" {
		credentials.IDToken = payload.IDToken
	}
	now := s.now()
	expires := now.Add(time.Duration(payload.ExpiresIn) * time.Second)
	account.Credentials = credentials
	account.ExpiresAt = &expires
	account.LastRefreshAt = &now
	account.Status = "ready"
	return s.accounts.UpsertLogin(ctx, account)
}
func NeedsRefresh(account store.Account, now time.Time) bool {
	return account.ExpiresAt != nil && !account.ExpiresAt.After(now.Add(RefreshLead))
}
