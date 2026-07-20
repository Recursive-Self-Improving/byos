package routing

import (
	"context"
	"errors"
	"sync"
	"time"

	"byos/internal/provider"
)

// RoutedStream owns one committed upstream stream. It never changes accounts after returning an event.
type RoutedStream struct {
	stream     provider.Stream
	first      *provider.Event
	accountID  string
	model      string
	cooldowns  *CooldownManager
	usage      UsageRecorder
	mu         sync.Mutex
	committed  bool
	terminal   bool
	recordOnce sync.Once
}

func (s *RoutedStream) AccountID() string { return s.accountID }
func (s *RoutedStream) Model() string     { return s.model }
func (s *RoutedStream) Committed() bool   { s.mu.Lock(); defer s.mu.Unlock(); return s.committed }

func (s *RoutedStream) Next(ctx context.Context) (provider.Event, error) {
	if err := ctx.Err(); err != nil {
		return provider.Event{}, s.finishFailure(ctx, err)
	}
	s.mu.Lock()
	if s.terminal {
		s.mu.Unlock()
		return provider.Event{}, errors.New("stream is closed")
	}
	if s.first != nil {
		event := *s.first
		s.first = nil
		s.committed = true
		delta, terminal := terminalUsage(event)
		if terminal {
			s.terminal = true
		}
		s.mu.Unlock()
		if terminal {
			s.finishSuccess(ctx, delta)
		}
		return event, nil
	}
	s.mu.Unlock()
	event, err := s.stream.Next(ctx)
	if err != nil {
		return provider.Event{}, s.finishFailure(ctx, err)
	}
	s.mu.Lock()
	if s.terminal {
		s.mu.Unlock()
		return provider.Event{}, errors.New("stream is closed")
	}
	s.committed = true
	delta, terminal := terminalUsage(event)
	if terminal {
		s.terminal = true
	}
	s.mu.Unlock()
	if terminal {
		s.finishSuccess(ctx, delta)
	}
	return event, nil
}
func (s *RoutedStream) finishSuccess(ctx context.Context, delta LocalUsageDelta) {
	s.record(ctx, delta)
	opCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = s.cooldowns.Success(opCtx, s.accountID, s.model)
	_ = s.stream.Close()
}
func (s *RoutedStream) finishFailure(ctx context.Context, cause error) error {
	s.mu.Lock()
	if s.terminal {
		s.mu.Unlock()
		return errors.New("stream is closed")
	}
	s.terminal = true
	s.mu.Unlock()
	_ = s.stream.Close()
	s.record(ctx, LocalUsageDelta{Requests: 1, Failures: 1})
	classified := classifyExecutionError(cause)
	if classified.Class != provider.ClassCancelled {
		opCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = s.cooldowns.Apply(opCtx, s.accountID, s.model, classified)
	}
	return &ExecutionError{Classified: classified}
}
func (s *RoutedStream) record(ctx context.Context, delta LocalUsageDelta) {
	s.recordOnce.Do(func() {
		if s.usage == nil {
			return
		}
		recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = s.usage.Record(recordCtx, s.accountID, delta)
	})
}
func (s *RoutedStream) Close() error {
	s.mu.Lock()
	shouldRecord := !s.terminal
	if shouldRecord {
		s.terminal = true
	}
	s.mu.Unlock()
	if shouldRecord {
		s.record(context.Background(), LocalUsageDelta{Requests: 1, Failures: 1})
	}
	return s.stream.Close()
}

// Stream opens an upstream stream only after buffering its first valid event. Candidate failover is
// therefore possible while this method is running, but never after the returned stream emits.
func (e *Executor) Stream(ctx context.Context, request Request) (*RoutedStream, error) {
	plan, err := e.prepare(ctx, request)
	if err != nil {
		return nil, err
	}
	ordered, err := e.candidates(ctx, plan.model, plan.capabilities.Credentials, request.PreferredAccountID)
	if err != nil {
		if errors.Is(err, ErrNoAvailableAccounts) {
			return nil, ErrModelUnavailable
		}
		return nil, err
	}
	var last error
	for _, candidate := range ordered {
		account, err := e.accounts.Get(ctx, candidate.ID)
		if err != nil {
			return nil, err
		}
		if account.Provider != plan.model.Provider {
			continue
		}
		credential, err := plan.capabilities.Credentials.Credential(ctx, account.ID)
		if err != nil {
			classified := classifyExecutionError(err)
			e.record(ctx, account.ID, LocalUsageDelta{Requests: 1, Failures: 1})
			classified, applyErr := e.applyFailure(ctx, account.ID, plan.model.UpstreamName, classified)
			if applyErr != nil {
				return nil, applyErr
			}
			last = &ExecutionError{Classified: classified}
			if classified.RetryNext {
				continue
			}
			return nil, last
		}
		stream, err := plan.capabilities.Generation.Stream(ctx, provider.GenerationRequest{Model: plan.model, Canonical: plan.canonical, Credential: credential})
		if err == nil {
			first, firstErr := stream.Next(ctx)
			if firstErr == nil {
				return newRoutedStream(stream, first, account.ID, plan.model.UpstreamName, e.cooldowns, e.usage), nil
			}
			_ = stream.Close()
			err = firstErr
		}
		classified := classifyExecutionError(err)
		if classified.RefreshSame {
			credential, recoveryClassification, retrySame := recoverAuthentication(ctx, plan.capabilities.Credentials, account.ID, err, classified)
			classified = recoveryClassification
			if retrySame {
				stream, err = plan.capabilities.Generation.Stream(ctx, provider.GenerationRequest{Model: plan.model, Canonical: plan.canonical, Credential: credential})
				if err == nil {
					first, firstErr := stream.Next(ctx)
					if firstErr == nil {
						return newRoutedStream(stream, first, account.ID, plan.model.UpstreamName, e.cooldowns, e.usage), nil
					}
					_ = stream.Close()
					err = firstErr
				}
				classified = classifyExecutionError(err)
			}
		}
		e.record(ctx, account.ID, LocalUsageDelta{Requests: 1, Failures: 1})
		classified, applyErr := e.applyFailure(ctx, account.ID, plan.model.UpstreamName, classified)
		if applyErr != nil {
			return nil, applyErr
		}
		last = &ExecutionError{Classified: classified}
		if !classified.RetryNext {
			return nil, last
		}
	}
	if last != nil {
		return nil, last
	}
	return nil, ErrNoAvailableAccounts
}
func newRoutedStream(stream provider.Stream, first provider.Event, accountID, model string, cooldowns *CooldownManager, usage UsageRecorder) *RoutedStream {
	return &RoutedStream{stream: stream, first: &first, accountID: accountID, model: model, cooldowns: cooldowns, usage: usage}
}
