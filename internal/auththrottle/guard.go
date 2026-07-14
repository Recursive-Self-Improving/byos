package auththrottle

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"
)

type Disposition uint8

const (
	Authenticated Disposition = iota + 1
	Rejected
	Blocked
)

type Outcome struct {
	Disposition Disposition
	RetryAfter  time.Duration
}

type TransitionKind string

const (
	TransitionSourceCooldown TransitionKind = "source_cooldown_started"
	TransitionSourceLocked   TransitionKind = "source_locked"
	TransitionSourceUnlocked TransitionKind = "source_unlocked"
	TransitionSourceReset    TransitionKind = "source_reset"
	TransitionGlobalArmed    TransitionKind = "global_guard_armed"
	TransitionGlobalReleased TransitionKind = "global_guard_released"
)

type Transition struct {
	Kind              TransitionKind
	FailureCount      int
	PriorFailureCount int
	BlockedUntil      time.Time
	GlobalSourceLocks int
}

type Status struct {
	BlockedUntil time.Time
	Transitions  []Transition
}

type Repository interface {
	Check(context.Context, [32]byte, time.Time, Policy) (Status, error)
	RecordFailure(context.Context, [32]byte, time.Time, Policy) ([]Transition, error)
	ResetSource(context.Context, [32]byte) (Transition, bool, error)
}

type SourceHasher func(netip.Addr) [32]byte

type Guard struct {
	repository Repository
	hash       SourceHasher
	policy     Policy
	logger     *slog.Logger
	now        func() time.Time
	mu         sync.Mutex
}

func NewGuard(repository Repository, hash SourceHasher, policy Policy, logger *slog.Logger, now func() time.Time) (*Guard, error) {
	if repository == nil || hash == nil {
		return nil, errors.New("authentication throttle repository and source hasher are required")
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Guard{repository: repository, hash: hash, policy: policy, logger: logger, now: now}, nil
}

func (g *Guard) Evaluate(ctx context.Context, source netip.Addr, surface Surface, verify func() bool) (Outcome, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Unix(g.now().Unix(), 0).UTC()
	sourceHash := g.hash(source.Unmap())
	status, err := g.repository.Check(ctx, sourceHash, now, g.policy)
	if err != nil {
		return Outcome{}, err
	}
	g.logTransitions(surface, sourceHash, status.Transitions, now)
	if status.BlockedUntil.After(now) {
		return Outcome{Disposition: Blocked, RetryAfter: status.BlockedUntil.Sub(now)}, nil
	}
	if verify() {
		transition, changed, err := g.repository.ResetSource(ctx, sourceHash)
		if err != nil {
			return Outcome{}, err
		}
		if changed {
			g.logTransitions(surface, sourceHash, []Transition{transition}, now)
		}
		return Outcome{Disposition: Authenticated}, nil
	}
	transitions, err := g.repository.RecordFailure(ctx, sourceHash, now, g.policy)
	if err != nil {
		return Outcome{}, err
	}
	g.logTransitions(surface, sourceHash, transitions, now)
	return Outcome{Disposition: Rejected}, nil
}

// RecordFailure applies the normal persisted policy after a caller has already
// established that an authenticated re-login credential is invalid. The
// caller may check a valid credential first so successful session rotation can
// bypass an existing source or global block.
func (g *Guard) RecordFailure(ctx context.Context, source netip.Addr, surface Surface) (Outcome, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Unix(g.now().Unix(), 0).UTC()
	sourceHash := g.hash(source.Unmap())
	status, err := g.repository.Check(ctx, sourceHash, now, g.policy)
	if err != nil {
		return Outcome{}, err
	}
	g.logTransitions(surface, sourceHash, status.Transitions, now)
	if status.BlockedUntil.After(now) {
		return Outcome{Disposition: Blocked, RetryAfter: status.BlockedUntil.Sub(now)}, nil
	}
	transitions, err := g.repository.RecordFailure(ctx, sourceHash, now, g.policy)
	if err != nil {
		return Outcome{}, err
	}
	g.logTransitions(surface, sourceHash, transitions, now)
	return Outcome{Disposition: Rejected}, nil
}

func (g *Guard) logTransitions(surface Surface, source [32]byte, transitions []Transition, now time.Time) {
	if len(transitions) == 0 {
		return
	}
	sourceID := base64.RawURLEncoding.EncodeToString(source[:16])
	for _, transition := range transitions {
		attrs := []any{"transition", string(transition.Kind), "auth_surface", string(surface), "source_hash", sourceID}
		if transition.FailureCount != 0 {
			attrs = append(attrs, "failure_count", transition.FailureCount)
		}
		if transition.PriorFailureCount != 0 {
			attrs = append(attrs, "prior_failure_count", transition.PriorFailureCount)
		}
		if transition.GlobalSourceLocks != 0 {
			attrs = append(attrs, "source_locks", transition.GlobalSourceLocks)
		}
		if transition.BlockedUntil.After(now) {
			attrs = append(attrs, "retry_after_seconds", int64(transition.BlockedUntil.Sub(now)/time.Second), "blocked_until", transition.BlockedUntil.Format(time.RFC3339))
		}
		switch transition.Kind {
		case TransitionSourceCooldown, TransitionSourceLocked, TransitionGlobalArmed:
			g.logger.Warn("administrator authentication throttle transition", attrs...)
		default:
			g.logger.Info("administrator authentication throttle transition", attrs...)
		}
	}
}
