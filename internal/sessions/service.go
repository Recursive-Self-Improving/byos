package sessions

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"supergrok-api/internal/store"
)

const Retention = 30 * 24 * time.Hour

type Service struct {
	repo *store.ResponseRepository
	now  func() time.Time
}

func NewService(repo *store.ResponseRepository) *Service {
	return &Service{repo: repo, now: func() time.Time { return time.Now().UTC() }}
}
func (s *Service) Prepare(ctx context.Context, body []byte) (Reconstruction, error) {
	var request struct {
		Previous string `json:"previous_response_id"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		return Reconstruction{}, err
	}
	return Reconstruct(ctx, s.repo, body, request.Previous, s.now())
}

type CompletedNode struct {
	ResponseID, UpstreamResponseID, PreviousResponseID, Model, AccountID string
	CanonicalInput, TerminalOutput                                       []byte
	Store                                                                *bool
}

func (s *Service) PersistCompleted(ctx context.Context, node CompletedNode, terminal bool) error {
	storeValue := true
	if node.Store != nil {
		storeValue = *node.Store
	}
	if !terminal || !storeValue {
		return nil
	}
	if node.ResponseID == "" || len(node.TerminalOutput) == 0 {
		return errors.New("completed response data is required")
	}
	now := s.now()
	return s.repo.Put(ctx, store.ResponseSession{ResponseID: node.ResponseID, UpstreamResponseID: node.UpstreamResponseID, PreviousResponseID: node.PreviousResponseID, Model: node.Model, PreferredAccountID: node.AccountID, Input: node.CanonicalInput, Output: node.TerminalOutput, Store: true, CreatedAt: now, ExpiresAt: now.Add(Retention)})
}
func (s *Service) Cleanup(ctx context.Context) (int64, error) { return s.repo.Cleanup(ctx, s.now()) }
