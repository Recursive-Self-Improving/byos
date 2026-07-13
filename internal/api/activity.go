package api

import (
	"context"
	"net/http"
	"sync"
)

type ActivityTracker struct {
	mu     sync.Mutex
	active int
	zero   chan struct{}
}

func NewActivityTracker(next http.Handler) (http.Handler, *ActivityTracker) {
	closed := make(chan struct{})
	close(closed)
	tracker := &ActivityTracker{zero: closed}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tracker.begin()
		defer tracker.end()
		next.ServeHTTP(w, r)
	}), tracker
}
func (t *ActivityTracker) begin() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.active == 0 {
		t.zero = make(chan struct{})
	}
	t.active++
}
func (t *ActivityTracker) end() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.active--
	if t.active == 0 {
		close(t.zero)
	}
}
func (t *ActivityTracker) Wait(ctx context.Context) error {
	t.mu.Lock()
	zero := t.zero
	t.mu.Unlock()
	select {
	case <-zero:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (t *ActivityTracker) Active() int { t.mu.Lock(); defer t.mu.Unlock(); return t.active }
