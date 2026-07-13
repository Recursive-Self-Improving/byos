package routing

import (
	"context"
	"errors"
	"sync"
	"time"

	"supergrok-api/internal/store"
	"supergrok-api/internal/xai"
)

// RoutedStream owns one committed upstream stream. It never changes accounts after returning an event.
type RoutedStream struct {
	stream     *xai.Stream
	first      *xai.Event
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

func (s *RoutedStream) Next(ctx context.Context) (xai.Event, error) {
	if err := ctx.Err(); err != nil {
		return xai.Event{}, s.finishFailure(ctx, err)
	}
	s.mu.Lock()
	if s.terminal {
		s.mu.Unlock()
		return xai.Event{}, errors.New("stream is closed")
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
		return xai.Event{}, s.finishFailure(ctx, err)
	}
	s.mu.Lock()
	if s.terminal {
		s.mu.Unlock()
		return xai.Event{}, errors.New("stream is closed")
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
	classified := classifyExecutionError(cause, s.cooldowns.now())
	if classified.Class != ClassCancelled {
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
	model, body, err := e.prepare(request)
	if err != nil {
		return nil, err
	}
	ordered, err := e.candidates(ctx, model, request.PreferredAccountID)
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
		account, classified, err := e.readyAccount(ctx, account)
		if err != nil {
			e.record(ctx, candidate.ID, LocalUsageDelta{Requests: 1, Failures: 1})
			classified, applyErr := e.applyFailure(ctx, candidate.ID, model, classified)
			if applyErr != nil {
				return nil, applyErr
			}
			last = &ExecutionError{Classified: classified}
			if classified.RetryNext {
				continue
			}
			return nil, last
		}
		stream, err := e.client.Stream(ctx, account.Credentials.AccessToken, model, body)
		if err == nil {
			first, firstErr := stream.Next(ctx)
			if firstErr == nil {
				return newRoutedStream(stream, first, account, model, e.cooldowns, e.usage), nil
			}
			_ = stream.Close()
			err = firstErr
		}
		classified = classifyExecutionError(err, e.now())
		if classified.RefreshSame {
			refreshed, refreshClass, refreshErr := e.refresh(ctx, account.ID)
			if refreshErr == nil {
				stream, err = e.client.Stream(ctx, refreshed.Credentials.AccessToken, model, body)
				if err == nil {
					first, firstErr := stream.Next(ctx)
					if firstErr == nil {
						return newRoutedStream(stream, first, refreshed, model, e.cooldowns, e.usage), nil
					}
					_ = stream.Close()
					err = firstErr
				}
				classified = classifyExecutionError(err, e.now())
			} else {
				err, classified = refreshErr, refreshClass
			}
		}
		e.record(ctx, account.ID, LocalUsageDelta{Requests: 1, Failures: 1})
		classified, applyErr := e.applyFailure(ctx, account.ID, model, classified)
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

func newRoutedStream(stream *xai.Stream, first xai.Event, account store.Account, model string, cooldowns *CooldownManager, usage UsageRecorder) *RoutedStream {
	return &RoutedStream{stream: stream, first: &first, accountID: account.ID, model: model, cooldowns: cooldowns, usage: usage}
}
