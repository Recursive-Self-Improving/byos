package xai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"

	"byos/internal/provider"
	"byos/internal/store"
)

type lifecycleService interface {
	Start(context.Context) (DeviceAuthorization, error)
	Get(context.Context, string) (store.OAuthSession, error)
	ListResumable(context.Context) ([]store.OAuthSession, error)
	Poll(context.Context, string) (TokenResponse, error)
	Complete(context.Context, string, string) error
	Fail(context.Context, string, string) error
	Cancel(context.Context, string) error
	Stop(string)
}

type lifecycleAccounts interface {
	Get(context.Context, string) (store.Account, error)
	UpsertLogin(context.Context, store.Account) (store.Account, error)
}

// AccountIdentityVerifier verifies xAI OIDC identity without exposing the raw
// token or verified claims outside the provider lifecycle implementation.
type AccountIdentityVerifier interface {
	Verify(context.Context, string) (Identity, error)
}

// ProviderLifecycle adapts the xAI device flow to the provider-neutral account
// lifecycle. Protocol state, credentials, and identity claims remain internal.
type ProviderLifecycle struct {
	service     lifecycleService
	accounts    lifecycleAccounts
	identity    AccountIdentityVerifier
	now         func() time.Time
	completions singleflight.Group
}

func NewProviderLifecycle(service lifecycleService, accounts lifecycleAccounts, identity AccountIdentityVerifier) *ProviderLifecycle {
	return &ProviderLifecycle{service: service, accounts: accounts, identity: identity, now: func() time.Time { return time.Now().UTC() }}
}

func (l *ProviderLifecycle) Start(ctx context.Context) (provider.Authorization, error) {
	flow, err := l.service.Start(ctx)
	if err != nil {
		return provider.Authorization{}, err
	}
	return authorizationProjection(flow.State, flow.UserCode, flow.VerificationURI, flow.VerificationURIComplete, flow.ExpiresAt, flow.PollInterval), nil
}

func (l *ProviderLifecycle) Status(ctx context.Context, ref provider.AuthorizationRef) (provider.AuthorizationSession, error) {
	if err := requireXAIRef(ref); err != nil {
		return provider.AuthorizationSession{}, err
	}
	session, err := l.service.Get(ctx, ref.State)
	if err != nil {
		return provider.AuthorizationSession{}, err
	}
	return sessionProjection(session)
}

func (l *ProviderLifecycle) Complete(ctx context.Context, ref provider.AuthorizationRef, completion provider.AuthorizationCompletion) (provider.AccountResult, error) {
	if err := requireXAIRef(ref); err != nil {
		return provider.AccountResult{}, err
	}
	if completion.Code != "" {
		return provider.AccountResult{}, errors.New("xAI authorization does not accept a callback code")
	}
	result := l.completions.DoChan(ref.State, func() (any, error) {
		return l.complete(ctx, ref.State)
	})
	select {
	case <-ctx.Done():
		return provider.AccountResult{}, ctx.Err()
	case value := <-result:
		if value.Err != nil {
			return provider.AccountResult{}, value.Err
		}
		return value.Val.(provider.AccountResult), nil
	}
}

func (l *ProviderLifecycle) complete(ctx context.Context, state string) (provider.AccountResult, error) {
	session, err := l.service.Get(ctx, state)
	if err != nil {
		return provider.AccountResult{}, err
	}
	if session.Status == string(provider.AuthorizationCompleted) {
		if strings.TrimSpace(session.AccountID) == "" {
			return provider.AccountResult{}, errors.New("completed xAI authorization is missing its account")
		}
		if _, err := l.accounts.Get(ctx, session.AccountID); err != nil {
			return provider.AccountResult{}, err
		}
		return provider.AccountResult{Provider: provider.XAI, AccountID: session.AccountID}, nil
	}

	token, err := l.service.Poll(ctx, state)
	if err != nil {
		return provider.AccountResult{}, err
	}
	identity, err := l.identity.Verify(ctx, token.IDToken)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return provider.AccountResult{}, err
		}
		_ = l.service.Fail(context.Background(), state, "The identity token could not be verified.")
		return provider.AccountResult{}, errors.New("xAI identity token could not be verified")
	}
	claims, err := json.Marshal(identity.Claims)
	if err != nil {
		_ = l.service.Fail(context.Background(), state, "The identity token could not be verified.")
		return provider.AccountResult{}, errors.New("xAI identity token could not be verified")
	}
	expires := token.ExpiresAt
	if expires.IsZero() {
		expires = l.now().Add(time.Duration(token.ExpiresIn) * time.Second)
	}
	account, err := l.accounts.UpsertLogin(ctx, store.Account{
		Provider: provider.XAI,
		Status:   "ready",
		Credentials: store.AccountCredentials{
			Issuer: identity.Issuer, Subject: identity.Subject, Email: identity.Email,
			AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, IDToken: token.IDToken,
			TokenEndpoint: token.TokenEndpoint, RawIdentity: claims,
		},
		ExpiresAt: &expires,
	})
	if err != nil {
		return provider.AccountResult{}, errors.New("xAI account could not be saved")
	}
	if err := l.service.Complete(ctx, state, account.ID); err != nil {
		return provider.AccountResult{}, err
	}
	return provider.AccountResult{Provider: provider.XAI, AccountID: account.ID}, nil
}

func (l *ProviderLifecycle) Cancel(ctx context.Context, ref provider.AuthorizationRef) error {
	if err := requireXAIRef(ref); err != nil {
		return err
	}
	return l.service.Cancel(ctx, ref.State)
}

func (l *ProviderLifecycle) Resume(ctx context.Context) ([]provider.AuthorizationSession, error) {
	sessions, err := l.service.ListResumable(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]provider.AuthorizationSession, 0, len(sessions))
	for _, session := range sessions {
		projected, err := sessionProjection(session)
		if err != nil {
			return nil, err
		}
		result = append(result, projected)
	}
	return result, nil
}

func requireXAIRef(ref provider.AuthorizationRef) error {
	if ref.Provider != provider.XAI {
		return fmt.Errorf("xAI authorization reference: %w", provider.ErrProviderMismatch)
	}
	return nil
}

func authorizationProjection(state, userCode, verificationURL, completeURL string, expiresAt time.Time, interval time.Duration) provider.Authorization {
	preferredURL := strings.TrimSpace(completeURL)
	if preferredURL == "" {
		preferredURL = strings.TrimSpace(verificationURL)
	}
	return provider.Authorization{
		Ref:                     provider.AuthorizationRef{Provider: provider.XAI, State: state},
		UserCode:                userCode,
		VerificationURL:         preferredURL,
		VerificationURLComplete: strings.TrimSpace(completeURL),
		ExpiresAt:               expiresAt,
		PollInterval:            interval,
	}
}

func sessionProjection(session store.OAuthSession) (provider.AuthorizationSession, error) {
	status := provider.AuthorizationStatus(session.Status)
	switch status {
	case provider.AuthorizationPending, provider.AuthorizationAuthorized, provider.AuthorizationConsumed,
		provider.AuthorizationCompleted, provider.AuthorizationFailed, provider.AuthorizationExpired,
		provider.AuthorizationCancelled:
	default:
		return provider.AuthorizationSession{}, errors.New("xAI authorization has an invalid status")
	}
	return provider.AuthorizationSession{
		Authorization: authorizationProjection(session.State, session.UserCode, session.VerificationURI, session.VerificationURIComplete, session.ExpiresAt, session.PollInterval),
		Status:        status, AccountID: session.AccountID, SanitizedMessage: session.SanitizedError,
	}, nil
}

var _ provider.AccountLifecycle = (*ProviderLifecycle)(nil)
