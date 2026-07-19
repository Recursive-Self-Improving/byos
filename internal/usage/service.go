package usage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"byos/internal/provider"
	"byos/internal/store"
)

type SnapshotStore interface {
	Put(context.Context, store.UsageSnapshot) error
	Latest(context.Context, string) (store.UsageSnapshot, error)
}
type CounterStore interface {
	Add(context.Context, string, store.LocalUsageCounters) error
	Get(context.Context, string) (store.LocalUsageCounters, error)
}

type Service struct {
	snapshots SnapshotStore
	counters  CounterStore
}

func NewService(snapshots SnapshotStore, counters CounterStore) *Service {
	return &Service{snapshots: snapshots, counters: counters}
}

// ApplyUsage persists a provider-neutral usage observation. fetchErr is applied
// through the same stale/unknown path so workers never need provider-specific
// billing compatibility or persistence behavior.
func (s *Service) ApplyUsage(ctx context.Context, accountID string, observation provider.UsageSnapshot, fetchErr error) (Snapshot, error) {
	if fetchErr != nil {
		previous, previousErr := s.Latest(ctx, accountID)
		if previousErr == nil && !previous.Unknown {
			previous.Stale = true
			previous.Error = fetchErr.Error()
			normalized, marshalErr := marshalNormalized(previous)
			if marshalErr != nil {
				return previous, errors.Join(fetchErr, marshalErr)
			}
			stored := store.UsageSnapshot{AccountID: accountID, Normalized: normalized, FetchedAt: previous.FetchedAt, Stale: true, Error: previous.Error}
			if latest, latestErr := s.snapshots.Latest(ctx, accountID); latestErr == nil {
				stored.Raw = latest.Raw
			}
			if persistErr := s.snapshots.Put(ctx, stored); persistErr != nil {
				return previous, errors.Join(fetchErr, persistErr)
			}
			return previous, fetchErr
		}
		if previousErr != nil {
			return Snapshot{}, errors.Join(fetchErr, previousErr)
		}
		fetchedAt := observation.FetchedAt.UTC()
		if fetchedAt.IsZero() {
			fetchedAt = time.Now().UTC()
		}
		unknown := Snapshot{AccountID: accountID, Local: previous.Local, FetchedAt: fetchedAt, Stale: true, Unknown: true, Error: fetchErr.Error()}
		normalized, marshalErr := marshalNormalized(unknown)
		if marshalErr != nil {
			return unknown, errors.Join(fetchErr, marshalErr)
		}
		if persistErr := s.snapshots.Put(ctx, store.UsageSnapshot{AccountID: accountID, Normalized: normalized, FetchedAt: fetchedAt, Stale: true, Error: unknown.Error}); persistErr != nil {
			return unknown, errors.Join(fetchErr, persistErr)
		}
		return unknown, fetchErr
	}

	snapshot := Snapshot{AccountID: accountID, Monthly: monthlyFromProvider(observation.Monthly), Weekly: weeklyFromProvider(observation.Weekly), FetchedAt: observation.FetchedAt.UTC()}
	local, err := s.Counters(ctx, accountID)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.Local = local
	normalized, err := marshalNormalized(snapshot)
	if err != nil {
		return Snapshot{}, err
	}
	if err := s.snapshots.Put(ctx, store.UsageSnapshot{AccountID: accountID, Normalized: normalized, Raw: append([]byte(nil), observation.Raw...), FetchedAt: snapshot.FetchedAt}); err != nil {
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
		Unknown bool     `json:"unknown,omitempty"`
	}
	if err := json.Unmarshal(stored.Normalized, &normalized); err != nil {
		return Snapshot{}, err
	}
	local, err := s.Counters(ctx, accountID)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{AccountID: accountID, Monthly: normalized.Monthly, Weekly: normalized.Weekly, Local: local, FetchedAt: stored.FetchedAt, Stale: stored.Stale, Unknown: normalized.Unknown, Error: stored.Error}, nil
}

func (s *Service) Record(ctx context.Context, accountID string, delta Delta) error {
	return s.counters.Add(ctx, accountID, store.LocalUsageCounters(delta))
}
func (s *Service) Counters(ctx context.Context, accountID string) (Counters, error) {
	value, err := s.counters.Get(ctx, accountID)
	return Counters(value), err
}

func monthlyFromProvider(value *provider.MonthlyUsage) *Monthly {
	if value == nil {
		return nil
	}
	return &Monthly{Limit: value.Limit, Used: value.Used, Remaining: value.Remaining, ResetAt: value.ResetAt}
}

func weeklyFromProvider(value *provider.WeeklyUsage) *Weekly {
	if value == nil {
		return nil
	}
	return &Weekly{UsedPercent: value.UsedPercent, RemainingPercent: value.RemainingPercent, ResetAt: value.ResetAt, OnDemand: value.OnDemand, Prepaid: value.Prepaid}
}

func marshalNormalized(snapshot Snapshot) ([]byte, error) {
	return json.Marshal(struct {
		Monthly *Monthly `json:"monthly"`
		Weekly  *Weekly  `json:"weekly"`
		Unknown bool     `json:"unknown,omitempty"`
	}{snapshot.Monthly, snapshot.Weekly, snapshot.Unknown})
}
