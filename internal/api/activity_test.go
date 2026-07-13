package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestActivityTrackerWaitsForHandler(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	handler, tracker := NewActivityTracker(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { close(started); <-release }))
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		close(done)
	}()
	<-started
	if tracker.Active() != 1 {
		t.Fatalf("active=%d", tracker.Active())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := tracker.Wait(ctx); err == nil {
		t.Fatal("Wait succeeded while handler active")
	}
	close(release)
	<-done
	if err := tracker.Wait(context.Background()); err != nil || tracker.Active() != 0 {
		t.Fatalf("wait=%v active=%d", err, tracker.Active())
	}
}
