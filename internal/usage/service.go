package usage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"byos/internal/store"
)

type BillingFetcher interface {
	Fetch(context.Context, string) (BillingResult, error)
}
type SnapshotStore interface {
	Put(context.Context, store.UsageSnapshot) error
	Latest(context.Context, string) (store.UsageSnapshot, error)
}
type CounterStore interface {
	Add(context.Context, string, store.LocalUsageCounters) error
	Get(context.Context, string) (store.LocalUsageCounters, error)
}

type Service struct {
	billing   BillingFetcher
	snapshots SnapshotStore
	counters  CounterStore
	now       func() time.Time
}

func NewService(billing BillingFetcher, snapshots SnapshotStore, counters CounterStore) *Service {
	return &Service{billing: billing, snapshots: snapshots, counters: counters, now: time.Now}
}

func (s *Service) Refresh(ctx context.Context, accountID, token string) (Snapshot, error) {
	result, err := s.billing.Fetch(ctx, token)
	if err != nil {
		previous, previousErr := s.Latest(ctx, accountID)
		if previousErr == nil && !previous.Unknown {
			previous.Stale = true
			previous.Error = err.Error()
			normalized, marshalErr := marshalNormalized(previous)
			if marshalErr != nil {
				return previous, errors.Join(err, marshalErr)
			}
			stored := store.UsageSnapshot{AccountID: accountID, Normalized: normalized, FetchedAt: previous.FetchedAt, Stale: true, Error: previous.Error}
			if latest, latestErr := s.snapshots.Latest(ctx, accountID); latestErr == nil {
				stored.Raw = latest.Raw
			}
			if persistErr := s.snapshots.Put(ctx, stored); persistErr != nil {
				return previous, errors.Join(err, persistErr)
			}
			return previous, err
		}
		if previousErr != nil {
			return Snapshot{}, errors.Join(err, previousErr)
		}
		local, counterErr := s.Counters(ctx, accountID)
		if counterErr != nil {
			return Snapshot{}, errors.Join(err, counterErr)
		}
		return Snapshot{AccountID: accountID, Local: local, Stale: true, Unknown: true, Error: err.Error()}, err
	}
	now := s.now().UTC()
	snapshot := Snapshot{AccountID: accountID, Monthly: result.Monthly, Weekly: result.Weekly, FetchedAt: now}
	local, counterErr := s.Counters(ctx, accountID)
	if counterErr != nil {
		return Snapshot{}, counterErr
	}
	snapshot.Local = local
	normalized, err := marshalNormalized(snapshot)
	if err != nil {
		return Snapshot{}, err
	}
	if err := s.snapshots.Put(ctx, store.UsageSnapshot{AccountID: accountID, Normalized: normalized, Raw: result.Raw, FetchedAt: now}); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func (s *Service) Latest(ctx context.Context, accountID string) (Snapshot, error) {
	stored, err := s.snapshots.Latest(ctx, accountID)
	if errors.Is(err, sql.ErrNoRows) {
		local, counterErr := s.Counters(ctx, accountID)
		return Snapshot{AccountID: accountID, Local: local, Unknown: true}, counterErr
	}
	if err != nil {
		return Snapshot{}, err
	}
	var normalized struct {
		Monthly *Monthly `json:"monthly"`
		Weekly  *Weekly  `json:"weekly"`
	}
	if err := json.Unmarshal(stored.Normalized, &normalized); err != nil {
		return Snapshot{}, err
	}
	local, err := s.Counters(ctx, accountID)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{AccountID: accountID, Monthly: normalized.Monthly, Weekly: normalized.Weekly, Local: local, FetchedAt: stored.FetchedAt, Stale: stored.Stale, Error: stored.Error}, nil
}

func (s *Service) Record(ctx context.Context, accountID string, delta Delta) error {
	return s.counters.Add(ctx, accountID, store.LocalUsageCounters(delta))
}
func (s *Service) Counters(ctx context.Context, accountID string) (Counters, error) {
	value, err := s.counters.Get(ctx, accountID)
	return Counters(value), err
}

func marshalNormalized(snapshot Snapshot) ([]byte, error) {
	return json.Marshal(struct {
		Monthly *Monthly `json:"monthly"`
		Weekly  *Weekly  `json:"weekly"`
	}{snapshot.Monthly, snapshot.Weekly})
}
