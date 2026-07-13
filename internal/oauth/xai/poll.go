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
)

type TokenResponse struct {
	AccessToken, RefreshToken, IDToken, TokenType, TokenEndpoint string
	ExpiresIn                                                    int
}
type OAuthError struct{ Code, Description string }

func (e *OAuthError) Error() string {
	if e.Description != "" {
		return "xAI OAuth " + e.Code + ": " + e.Description
	}
	return "xAI OAuth " + e.Code
}
func (s *Service) Poll(ctx context.Context, state string) (TokenResponse, error) {
	result := s.polls.DoChan(state, func() (any, error) {
		pollCtx, cancel := context.WithCancel(context.Background())
		s.pollMu.Lock()
		s.pollCancels[state] = cancel
		s.pollMu.Unlock()
		defer func() {
			cancel()
			s.pollMu.Lock()
			delete(s.pollCancels, state)
			s.pollMu.Unlock()
		}()
		return s.poll(pollCtx, state)
	})
	select {
	case <-ctx.Done():
		return TokenResponse{}, ctx.Err()
	case value := <-result:
		if value.Err != nil {
			return TokenResponse{}, value.Err
		}
		return value.Val.(TokenResponse), nil
	}
}
func (s *Service) poll(ctx context.Context, state string) (TokenResponse, error) {
	session, err := s.sessions.GetPending(ctx, state, s.now())
	if err != nil {
		return TokenResponse{}, err
	}
	interval := session.PollInterval
	if interval < MinimumPollInterval {
		interval = MinimumPollInterval
	}
	first := true
	for {
		now := s.now()
		if !now.Before(session.ExpiresAt) {
			_ = s.sessions.Transition(context.Background(), state, "expired", "device code expired")
			return TokenResponse{}, &OAuthError{Code: "expired_token"}
		}
		if !first {
			waitFor := interval
			if remaining := session.ExpiresAt.Sub(now); remaining < waitFor {
				waitFor = remaining
			}
			if err := s.wait(ctx, waitFor); err != nil {
				return TokenResponse{}, err
			}
			now = s.now()
			if !now.Before(session.ExpiresAt) {
				_ = s.sessions.Transition(context.Background(), state, "expired", "device code expired")
				return TokenResponse{}, &OAuthError{Code: "expired_token"}
			}
			if _, err := s.sessions.GetPending(ctx, state, now); err != nil {
				return TokenResponse{}, err
			}
		}
		first = false
		token, code, description, err := s.exchange(ctx, session.TokenEndpoint, session.DeviceCode)
		if err != nil {
			return TokenResponse{}, err
		}
		switch code {
		case "":
			if strings.TrimSpace(token.AccessToken) == "" {
				return TokenResponse{}, errors.New("xAI token response missing access_token")
			}
			if err := s.sessions.Transition(ctx, state, "completed", ""); err != nil {
				return TokenResponse{}, err
			}
			token.TokenEndpoint = session.TokenEndpoint
			return token, nil
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		case "access_denied", "expired_token":
			_ = s.sessions.Transition(context.Background(), state, map[string]string{"access_denied": "failed", "expired_token": "expired"}[code], description)
			return TokenResponse{}, &OAuthError{Code: code, Description: description}
		default:
			_ = s.sessions.Transition(context.Background(), state, "failed", description)
			return TokenResponse{}, &OAuthError{Code: code, Description: description}
		}
	}
}
func (s *Service) exchange(ctx context.Context, endpoint, deviceCode string) (TokenResponse, string, string, error) {
	form := url.Values{"grant_type": {DeviceCodeGrantType}, "device_code": {deviceCode}, "client_id": {s.options.ClientID}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenResponse{}, "", "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := s.http.Do(request)
	if err != nil {
		return TokenResponse{}, "", "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return TokenResponse{}, "", "", err
	}
	var payload struct {
		Error, ErrorDescription, AccessToken, RefreshToken, IDToken, TokenType string
		ExpiresIn                                                              int
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return TokenResponse{}, "", "", errors.New("invalid xAI token response")
	}
	_ = json.Unmarshal(raw["error"], &payload.Error)
	_ = json.Unmarshal(raw["error_description"], &payload.ErrorDescription)
	_ = json.Unmarshal(raw["access_token"], &payload.AccessToken)
	_ = json.Unmarshal(raw["refresh_token"], &payload.RefreshToken)
	_ = json.Unmarshal(raw["id_token"], &payload.IDToken)
	_ = json.Unmarshal(raw["token_type"], &payload.TokenType)
	_ = json.Unmarshal(raw["expires_in"], &payload.ExpiresIn)
	if response.StatusCode >= 500 {
		return TokenResponse{}, "", "", fmt.Errorf("xAI token endpoint returned HTTP %d", response.StatusCode)
	}
	return TokenResponse{AccessToken: payload.AccessToken, RefreshToken: payload.RefreshToken, IDToken: payload.IDToken, TokenType: payload.TokenType, ExpiresIn: payload.ExpiresIn}, payload.Error, payload.ErrorDescription, nil
}
func (s *Service) Cancel(ctx context.Context, state string) error {
	if err := s.sessions.Transition(ctx, state, "cancelled", ""); err != nil {
		return err
	}
	s.pollMu.Lock()
	cancel := s.pollCancels[state]
	s.pollMu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}
