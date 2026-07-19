// Portions adapted from CLIProxyAPI/v7 internal/auth/xai/xai.go (MIT): RFC 8628 device authorization setup.
// Upstream: https://github.com/router-for-me/CLIProxyAPI/blob/v7.2.71/internal/auth/xai/xai.go

package xai

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"byos/internal/store"
)

type Service struct {
	discovery   *DiscoveryClient
	http        *http.Client
	sessions    *store.OAuthSessionRepository
	options     Options
	now         func() time.Time
	wait        func(context.Context, time.Duration) error
	polls       singleflight.Group
	pollMu      sync.Mutex
	pollCancels map[string]context.CancelFunc
}
type DeviceAuthorization struct {
	State, UserCode, VerificationURI, VerificationURIComplete string
	ExpiresAt                                                 time.Time
	PollInterval                                              time.Duration
}
type devicePayload struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

func NewService(discovery *DiscoveryClient, client *http.Client, sessions *store.OAuthSessionRepository, options Options) *Service {
	client = secureOAuthClient(client)
	return &Service{discovery: discovery, http: client, sessions: sessions, options: options.withDefaults(), now: func() time.Time { return time.Now().UTC() }, wait: waitContext, pollCancels: make(map[string]context.CancelFunc)}
}

func (s *Service) Session(ctx context.Context, state string) (store.OAuthSession, error) {
	return s.sessions.Get(ctx, state)
}

func (s *Service) Resumable(ctx context.Context) ([]store.OAuthSession, error) {
	return s.sessions.ListResumable(ctx, s.now())
}

func (s *Service) Complete(ctx context.Context, state, accountID string) error {
	return s.sessions.Complete(ctx, state, accountID, s.now())
}

func (s *Service) Fail(ctx context.Context, state, sanitized string) error {
	return s.sessions.Transition(ctx, state, "failed", sanitized)
}
func (s *Service) StartDevice(ctx context.Context) (DeviceAuthorization, error) {
	discovery, err := s.discovery.Discover(ctx)
	if err != nil {
		return DeviceAuthorization{}, err
	}
	form := url.Values{"client_id": {s.options.ClientID}, "scope": {s.options.Scopes}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, discovery.DeviceAuthorizationEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return DeviceAuthorization{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := s.http.Do(request)
	if err != nil {
		return DeviceAuthorization{}, fmt.Errorf("xAI device authorization: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return DeviceAuthorization{}, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return DeviceAuthorization{}, fmt.Errorf("xAI device authorization returned HTTP %d", response.StatusCode)
	}
	var payload devicePayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return DeviceAuthorization{}, errors.New("invalid xAI device authorization response")
	}
	if strings.TrimSpace(payload.DeviceCode) == "" || strings.TrimSpace(payload.UserCode) == "" || (strings.TrimSpace(payload.VerificationURI) == "" && strings.TrimSpace(payload.VerificationURIComplete) == "") || payload.ExpiresIn <= 0 {
		return DeviceAuthorization{}, errors.New("incomplete xAI device authorization response")
	}
	state, err := randomState()
	if err != nil {
		return DeviceAuthorization{}, err
	}
	interval := time.Duration(payload.Interval) * time.Second
	if interval < MinimumPollInterval {
		interval = MinimumPollInterval
	}
	now := s.now()
	expires := now.Add(time.Duration(payload.ExpiresIn) * time.Second)
	max := now.Add(MaximumFlowDuration)
	if expires.After(max) {
		expires = max
	}
	session := store.OAuthSession{State: state, DeviceCode: payload.DeviceCode, UserCode: payload.UserCode, VerificationURI: payload.VerificationURI, VerificationURIComplete: payload.VerificationURIComplete, TokenEndpoint: discovery.TokenEndpoint, PollInterval: interval, ExpiresAt: expires}
	if err := s.sessions.Create(ctx, session); err != nil {
		return DeviceAuthorization{}, err
	}
	return DeviceAuthorization{State: state, UserCode: payload.UserCode, VerificationURI: payload.VerificationURI, VerificationURIComplete: payload.VerificationURIComplete, ExpiresAt: expires, PollInterval: interval}, nil
}
func randomState() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
func waitContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
