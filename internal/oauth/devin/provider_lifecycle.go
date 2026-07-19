package devin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"

	"byos/internal/provider"
	"byos/internal/store"
)

const (
	pendingSessionTTL          = 5 * time.Minute
	failureFinalizationTimeout = 5 * time.Second
	failedMessage              = "Devin authorization failed."
	cancelledMessage           = "Devin authorization was cancelled."
	corruptMessage             = "Devin authorization could not be completed."
	restartMessage             = "Devin authorization was interrupted."
	expiredMessage             = "Devin authorization expired."
)

type lifecycleExchange interface {
	Exchange(context.Context, string, string) (string, error)
}

type lifecycleTransaction interface {
	Complete(context.Context, string, store.Account, time.Time) (store.Account, error)
}

// ProviderLifecycle adapts Devin's callback-PKCE flow to the provider-neutral
// account lifecycle. Callback codes, verifiers, and opaque tokens never leave
// this implementation or its encrypted stores.
type ProviderLifecycle struct {
	sessions    *store.OAuthSessionRepository
	client      lifecycleExchange
	transaction lifecycleTransaction
	config      OAuthConfig
	now         func() time.Time
	completions singleflight.Group
}

func NewProviderLifecycle(sessions *store.OAuthSessionRepository, client *Client, transaction *store.DevinOAuthTransaction, config OAuthConfig) *ProviderLifecycle {
	return &ProviderLifecycle{
		sessions: sessions, client: client, transaction: transaction, config: config,
		now: func() time.Time { return time.Now().UTC() },
	}
}

func (l *ProviderLifecycle) Start(ctx context.Context) (provider.Authorization, error) {
	if l == nil || l.sessions == nil {
		return provider.Authorization{}, errors.New("Devin authorization is unavailable")
	}
	verificationURL, state, verifier, err := BuildAuthorization(l.config)
	if err != nil {
		return provider.Authorization{}, err
	}
	redirectURI, err := CallbackURL(l.config)
	if err != nil {
		return provider.Authorization{}, err
	}
	expiresAt := l.now().Add(pendingSessionTTL)
	if err := l.sessions.Create(ctx, store.OAuthSession{
		Provider: provider.Devin, FlowType: store.OAuthFlowCallbackPKCE, State: state,
		Pending:   &store.OAuthPendingPayload{Verifier: verifier, RedirectURI: redirectURI, ExpiresAt: expiresAt},
		ExpiresAt: expiresAt,
	}); err != nil {
		return provider.Authorization{}, errors.New("Devin authorization could not be started")
	}
	return provider.Authorization{
		Ref:             provider.AuthorizationRef{Provider: provider.Devin, State: state},
		VerificationURL: verificationURL, VerificationURLComplete: verificationURL, ExpiresAt: expiresAt,
	}, nil
}

func (l *ProviderLifecycle) Status(ctx context.Context, ref provider.AuthorizationRef) (provider.AuthorizationSession, error) {
	if err := requireDevinRef(ref); err != nil {
		return provider.AuthorizationSession{}, err
	}
	now := l.now()
	session, err := l.sessionWithExpiry(ctx, ref.State, now)
	if err != nil {
		return provider.AuthorizationSession{}, sanitizedLookupError(err)
	}
	return devinSessionProjection(session, ref.State)
}

func (l *ProviderLifecycle) Complete(ctx context.Context, ref provider.AuthorizationRef, completion provider.AuthorizationCompletion) (provider.AccountResult, error) {
	if err := requireDevinRef(ref); err != nil {
		return provider.AccountResult{}, err
	}
	result := l.completions.DoChan(ref.State, func() (any, error) {
		now := l.now()
		session, err := l.sessionWithExpiry(ctx, ref.State, now)
		if err != nil {
			return provider.AccountResult{}, sanitizedLookupError(err)
		}
		if session.Status == string(provider.AuthorizationExpired) {
			return provider.AccountResult{}, errors.New("Devin authorization has expired")
		}
		if strings.TrimSpace(completion.Code) == "" {
			return provider.AccountResult{}, errors.New("Devin authorization code is required")
		}
		if l.client == nil || l.transaction == nil || l.sessions == nil {
			return provider.AccountResult{}, errors.New("Devin authorization is unavailable")
		}
		return l.complete(ctx, ref.State, completion.Code)
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

func (l *ProviderLifecycle) complete(ctx context.Context, state, code string) (provider.AccountResult, error) {
	now := l.now()

	pending, err := l.sessions.Consume(ctx, provider.Devin, store.OAuthFlowCallbackPKCE, state, now)
	if err != nil {
		session, lookupErr := l.sessionWithExpiry(ctx, state, l.now())
		if lookupErr == nil && session.Status == string(provider.AuthorizationExpired) {
			return provider.AccountResult{}, errors.New("Devin authorization has expired")
		}
		l.failCorruptPending(state, l.now())
		return provider.AccountResult{}, errors.New("Devin authorization is invalid or has already been used")
	}
	token, err := l.client.Exchange(ctx, code, pending.Verifier)
	code = ""
	if err != nil {
		l.failDetached(state, failedMessage, now)
		return provider.AccountResult{}, err
	}
	expiresAt := ExpiresAt(token, now)
	usable := Usable(expiresAt, now)
	account := store.Account{
		Provider: provider.Devin, Label: AccountLabel, Enabled: usable, Status: "ready",
		Credentials: Credentials(token, now), ExpiresAt: &expiresAt,
	}
	if !usable {
		account.Status = "relogin_required"
		account.LastError = "authentication expired; reconnect required"
	}
	created, err := l.transaction.Complete(ctx, state, account, now)
	token = ""
	if err != nil {
		return provider.AccountResult{}, errors.New("Devin account could not be saved")
	}
	return provider.AccountResult{Provider: provider.Devin, AccountID: created.ID}, nil
}

func (l *ProviderLifecycle) Cancel(ctx context.Context, ref provider.AuthorizationRef) error {
	if err := requireDevinRef(ref); err != nil {
		return err
	}
	now := l.now()
	session, err := l.sessionWithExpiry(ctx, ref.State, now)
	if err != nil {
		return sanitizedLookupError(err)
	}
	if session.Status == string(provider.AuthorizationExpired) {
		return errors.New("Devin authorization has expired")
	}
	if err := l.sessions.Cancel(ctx, provider.Devin, store.OAuthFlowCallbackPKCE, ref.State, cancelledMessage, now); err != nil {
		session, lookupErr := l.sessionWithExpiry(ctx, ref.State, l.now())
		if lookupErr == nil && session.Status == string(provider.AuthorizationExpired) {
			return errors.New("Devin authorization has expired")
		}
		return sanitizedLookupError(err)
	}
	return nil
}

func (l *ProviderLifecycle) Resume(ctx context.Context) ([]provider.AuthorizationSession, error) {
	if l == nil || l.sessions == nil {
		return nil, errors.New("Devin authorization is unavailable")
	}
	now := l.now()
	if _, err := l.sessions.ExpirePendingBefore(ctx, provider.Devin, store.OAuthFlowCallbackPKCE, now); err != nil {
		return nil, errors.New("Devin authorizations could not be resumed")
	}
	sessions, err := l.sessions.ListResumable(ctx, provider.Devin, store.OAuthFlowCallbackPKCE, now)
	if err != nil {
		return nil, errors.New("Devin authorizations could not be resumed")
	}
	result := make([]provider.AuthorizationSession, 0, len(sessions))
	for _, session := range sessions {
		if session.Status == string(provider.AuthorizationConsumed) {
			if err := l.sessions.FailConsumedByHash(ctx, provider.Devin, store.OAuthFlowCallbackPKCE, session.StateHash, restartMessage, now); err != nil && !errors.Is(err, sql.ErrNoRows) {
				return nil, errors.New("Devin authorization recovery failed")
			}
			continue
		}
		projected, err := devinSessionProjection(session, "")
		if err != nil {
			return nil, err
		}
		result = append(result, projected)
	}
	return result, nil
}

func (l *ProviderLifecycle) sessionWithExpiry(ctx context.Context, state string, now time.Time) (store.OAuthSession, error) {
	if l == nil || l.sessions == nil {
		return store.OAuthSession{}, errors.New("Devin authorization is unavailable")
	}
	session, err := l.sessions.Get(ctx, provider.Devin, store.OAuthFlowCallbackPKCE, state)
	if err != nil {
		return store.OAuthSession{}, err
	}
	if session.Status != string(provider.AuthorizationPending) || now.Before(session.ExpiresAt) {
		return session, nil
	}
	if err := l.sessions.Expire(ctx, provider.Devin, store.OAuthFlowCallbackPKCE, state, expiredMessage, now); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return store.OAuthSession{}, err
	}
	return l.sessions.Get(ctx, provider.Devin, store.OAuthFlowCallbackPKCE, state)
}

func (l *ProviderLifecycle) failCorruptPending(state string, now time.Time) {
	session, err := l.sessions.Get(context.Background(), provider.Devin, store.OAuthFlowCallbackPKCE, state)
	if err == nil && session.Status == string(provider.AuthorizationPending) {
		_ = l.sessions.Cancel(context.Background(), provider.Devin, store.OAuthFlowCallbackPKCE, state, corruptMessage, now)
	}
}

func (l *ProviderLifecycle) failDetached(state, message string, now time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), failureFinalizationTimeout)
	defer cancel()
	_ = l.sessions.Fail(ctx, provider.Devin, store.OAuthFlowCallbackPKCE, state, message, now)
}

func requireDevinRef(ref provider.AuthorizationRef) error {
	if ref.Provider != provider.Devin {
		return fmt.Errorf("Devin authorization reference: %w", provider.ErrProviderMismatch)
	}
	if strings.TrimSpace(ref.State) == "" {
		return errors.New("Devin authorization state is required")
	}
	return nil
}

func devinSessionProjection(session store.OAuthSession, rawState string) (provider.AuthorizationSession, error) {
	if session.Provider != provider.Devin || session.FlowType != store.OAuthFlowCallbackPKCE {
		return provider.AuthorizationSession{}, fmt.Errorf("Devin authorization session: %w", provider.ErrProviderMismatch)
	}
	status := provider.AuthorizationStatus(session.Status)
	switch status {
	case provider.AuthorizationPending, provider.AuthorizationConsumed, provider.AuthorizationCompleted,
		provider.AuthorizationFailed, provider.AuthorizationExpired, provider.AuthorizationCancelled:
	default:
		return provider.AuthorizationSession{}, errors.New("Devin authorization has an invalid status")
	}
	return provider.AuthorizationSession{
		Authorization: provider.Authorization{Ref: provider.AuthorizationRef{Provider: provider.Devin, State: rawState}, ExpiresAt: session.ExpiresAt},
		Status:        status, AccountID: session.AccountID, SanitizedMessage: session.SanitizedError,
	}, nil
}

func sanitizedLookupError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return errors.New("Devin authorization was not found")
}

var _ provider.AccountLifecycle = (*ProviderLifecycle)(nil)
