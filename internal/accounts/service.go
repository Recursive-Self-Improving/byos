package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"golang.org/x/sync/singleflight"

	oauthxai "byoo/internal/oauth/xai"
	"byoo/internal/store"
)

type CapabilityRefresher interface {
	Refresh(context.Context, string) error
}
type UsageRefresher interface {
	Refresh(context.Context, string) error
}
type IdentityVerifier interface {
	Verify(context.Context, string) (oauthxai.Identity, error)
}
type Service struct {
	accounts     *store.AccountRepository
	oauth        *oauthxai.Service
	identity     IdentityVerifier
	refresh      *oauthxai.RefreshService
	capabilities CapabilityRefresher
	usage        UsageRefresher
	now          func() time.Time
	completions  singleflight.Group
}

func NewService(accounts *store.AccountRepository, oauth *oauthxai.Service, identity IdentityVerifier, refresh *oauthxai.RefreshService, capabilities CapabilityRefresher, usage UsageRefresher) *Service {
	return &Service{accounts: accounts, oauth: oauth, identity: identity, refresh: refresh, capabilities: capabilities, usage: usage, now: func() time.Time { return time.Now().UTC() }}
}
func (s *Service) StartLogin(ctx context.Context) (oauthxai.DeviceAuthorization, error) {
	return s.oauth.StartDevice(ctx)
}
func (s *Service) CompleteLogin(ctx context.Context, state string) (store.Account, error) {
	value, err, _ := s.completions.Do(state, func() (any, error) {
		return s.completeLogin(ctx, state)
	})
	if err != nil {
		return store.Account{}, err
	}
	return value.(store.Account), nil
}

func (s *Service) completeLogin(ctx context.Context, state string) (store.Account, error) {
	session, err := s.oauth.Session(ctx, state)
	if err != nil {
		return store.Account{}, err
	}
	if session.Status == "completed" {
		if session.AccountID == "" {
			return store.Account{}, errors.New("completed oauth session is missing its account")
		}
		return s.accounts.Get(ctx, session.AccountID)
	}
	token, err := s.oauth.Poll(ctx, state)
	if err != nil {
		return store.Account{}, err
	}
	identity, err := s.identity.Verify(ctx, token.IDToken)
	if err != nil {
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			_ = s.oauth.Fail(context.Background(), state, "The identity token could not be verified.")
		}
		return store.Account{}, err
	}
	claims, err := json.Marshal(identity.Claims)
	if err != nil {
		_ = s.oauth.Fail(context.Background(), state, "The identity token could not be verified.")
		return store.Account{}, err
	}
	expires := token.ExpiresAt
	if expires.IsZero() {
		expires = s.now().Add(time.Duration(token.ExpiresIn) * time.Second)
	}
	account, err := s.accounts.UpsertLogin(ctx, store.Account{Status: "ready", Credentials: store.AccountCredentials{Issuer: identity.Issuer, Subject: identity.Subject, Email: identity.Email, AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, IDToken: token.IDToken, TokenEndpoint: token.TokenEndpoint, RawIdentity: claims}, ExpiresAt: &expires})
	if err != nil {
		return store.Account{}, err
	}
	if err := s.oauth.Complete(ctx, state, account.ID); err != nil {
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
func (s *Service) Get(ctx context.Context, id string) (store.Account, error) {
	return s.accounts.Get(ctx, id)
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
