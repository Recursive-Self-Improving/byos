package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

type checkpointFunc func(context.Context) error

func (f checkpointFunc) Checkpoint(ctx context.Context) error { return f(ctx) }

type closeFunc func() error

func (f closeFunc) Close() error { return f() }

func TestLifecycleCancelsWorkersAndForcesBlockedHandler(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handlerStarted := make(chan struct{})
	handlerStopped := make(chan struct{})
	server := &http.Server{}
	var workerStopped atomic.Bool
	order := make(chan string, 2)
	lifecycle := &Lifecycle{
		Server: server, Listener: listener, ShutdownTimeout: 50 * time.Millisecond,
		Workers: []Worker{func(ctx context.Context) error {
			<-ctx.Done()
			workerStopped.Store(true)
			return ctx.Err()
		}},
		Checkpointer: checkpointFunc(func(context.Context) error { order <- "checkpoint"; return nil }),
		Store:        closeFunc(func() error { order <- "close"; return nil }),
	}
	server.Handler = lifecycle.TrackHandler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(handlerStarted)
		<-r.Context().Done()
		close(handlerStopped)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- lifecycle.Run(ctx) }()
	responseDone := make(chan error, 1)
	go func() {
		response, requestErr := http.Get("http://" + listener.Addr().String())
		if response != nil {
			_ = response.Body.Close()
		}
		responseDone <- requestErr
	}()
	select {
	case <-handlerStarted:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	cancel()
	err = <-done
	if err == nil || (!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)) {
		t.Fatalf("Run error = %v", err)
	}
	select {
	case <-handlerStopped:
	case <-time.After(time.Second):
		t.Fatal("forced server close did not cancel handler")
	}
	<-responseDone
	if !workerStopped.Load() {
		t.Fatal("worker was not cancelled")
	}
	if first, second := <-order, <-order; first != "checkpoint" || second != "close" {
		t.Fatalf("shutdown order = %s, %s", first, second)
	}
}
