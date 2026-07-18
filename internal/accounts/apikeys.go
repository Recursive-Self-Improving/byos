package accounts

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"byoo/internal/store"
)

const APIKeyPrefix = "byoo_"

type CreatedAPIKey struct {
	Key       store.APIKey
	Plaintext string
}
type APIKeyService struct {
	repository *store.APIKeyRepository
	now        func() time.Time
}

func NewAPIKeyService(repository *store.APIKeyRepository) *APIKeyService {
	return &APIKeyService{repository: repository, now: func() time.Time { return time.Now().UTC() }}
}
func (s *APIKeyService) Create(ctx context.Context, label string) (CreatedAPIKey, error) {
	if strings.TrimSpace(label) == "" {
		return CreatedAPIKey{}, errors.New("api key label is required")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return CreatedAPIKey{}, err
	}
	plaintext := APIKeyPrefix + base64.RawURLEncoding.EncodeToString(raw)
	id, err := randomPublicID("key_")
	if err != nil {
		return CreatedAPIKey{}, err
	}
	prefix := plaintext[:min(len(plaintext), 12)]
	key, err := s.repository.Create(ctx, id, prefix, label, plaintext, s.now())
	if err != nil {
		return CreatedAPIKey{}, err
	}
	return CreatedAPIKey{Key: key, Plaintext: plaintext}, nil
}
func (s *APIKeyService) Authenticate(ctx context.Context, plaintext string) (store.APIKey, error) {
	if !strings.HasPrefix(plaintext, APIKeyPrefix) || len(plaintext) < 12 {
		return store.APIKey{}, errors.New("invalid api key")
	}
	return s.repository.Authenticate(ctx, plaintext[:12], plaintext, s.now())
}
func (s *APIKeyService) List(ctx context.Context) ([]store.APIKey, error) {
	return s.repository.List(ctx)
}
func (s *APIKeyService) Revoke(ctx context.Context, id string) error {
	return s.repository.Revoke(ctx, id, s.now())
}
func randomPublicID(prefix string) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}
