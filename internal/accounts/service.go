package accounts

import (
	"context"
	"encoding/json"
	"time"

	oauthxai "supergrok-api/internal/oauth/xai"
	"supergrok-api/internal/store"
)

type CapabilityRefresher interface {
	Refresh(context.Context, string) error
}
type UsageRefresher interface {
	Refresh(context.Context, string) error
}
type Service struct {
	accounts     *store.AccountRepository
	oauth        *oauthxai.Service
	identity     *oauthxai.IdentityVerifier
	refresh      *oauthxai.RefreshService
	capabilities CapabilityRefresher
	usage        UsageRefresher
	now          func() time.Time
}

func NewService(accounts *store.AccountRepository, oauth *oauthxai.Service, identity *oauthxai.IdentityVerifier, refresh *oauthxai.RefreshService, capabilities CapabilityRefresher, usage UsageRefresher) *Service {
	return &Service{accounts: accounts, oauth: oauth, identity: identity, refresh: refresh, capabilities: capabilities, usage: usage, now: func() time.Time { return time.Now().UTC() }}
}
func (s *Service) StartLogin(ctx context.Context) (oauthxai.DeviceAuthorization, error) {
	return s.oauth.StartDevice(ctx)
}
func (s *Service) CompleteLogin(ctx context.Context, state string) (store.Account, error) {
	token, err := s.oauth.Poll(ctx, state)
	if err != nil {
		return store.Account{}, err
	}
	identity, err := s.identity.Verify(ctx, token.IDToken)
	if err != nil {
		return store.Account{}, err
	}
	claims, _ := json.Marshal(identity.Claims)
	expires := s.now().Add(time.Duration(token.ExpiresIn) * time.Second)
	account, err := s.accounts.UpsertLogin(ctx, store.Account{Status: "ready", Credentials: store.AccountCredentials{Issuer: identity.Issuer, Subject: identity.Subject, Email: identity.Email, AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, IDToken: token.IDToken, TokenEndpoint: token.TokenEndpoint, RawIdentity: claims}, ExpiresAt: &expires})
	if err != nil {
		return store.Account{}, err
	}
	if s.capabilities != nil {
		_ = s.capabilities.Refresh(ctx, account.ID)
	}
	if s.usage != nil {
		_ = s.usage.Refresh(ctx, account.ID)
	}
	return account, nil
}
func (s *Service) List(ctx context.Context) ([]store.Account, error) { return s.accounts.List(ctx) }
func (s *Service) Update(ctx context.Context, id, label string, enabled bool) error {
	return s.accounts.Update(ctx, id, label, enabled)
}
func (s *Service) Delete(ctx context.Context, id string) error { return s.accounts.Delete(ctx, id) }
func (s *Service) Refresh(ctx context.Context, id string) (store.Account, error) {
	account, err := s.refresh.Refresh(ctx, id)
	if err == nil && s.capabilities != nil {
		_ = s.capabilities.Refresh(ctx, id)
	}
	if err == nil && s.usage != nil {
		_ = s.usage.Refresh(ctx, id)
	}
	return account, err
}
