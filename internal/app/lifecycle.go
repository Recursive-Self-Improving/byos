package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type Checkpointer interface{ Checkpoint(context.Context) error }
type Closer interface{ Close() error }
type Worker func(context.Context) error

type Lifecycle struct {
	Server          *http.Server
	Listener        net.Listener
	Workers         []Worker
	Checkpointer    Checkpointer
	Store           Closer
	ShutdownTimeout time.Duration
	admission       sync.Mutex
	closing         bool
	active          sync.WaitGroup
}

func (l *Lifecycle) TrackHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.admission.Lock()
		if l.closing {
			l.admission.Unlock()
			http.Error(w, "server shutting down", http.StatusServiceUnavailable)
			return
		}
		l.active.Add(1)
		l.admission.Unlock()
		defer l.active.Done()
		next.ServeHTTP(w, r)
	})
}

func (l *Lifecycle) Run(ctx context.Context) error {
	if l.Server == nil {
		return errors.New("http server is required")
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	workerErrors := make(chan error, len(l.Workers))
	var workers sync.WaitGroup
	for _, worker := range l.Workers {
		workers.Add(1)
		go func(run Worker) {
			defer workers.Done()
			if err := run(runCtx); err != nil && !errors.Is(err, context.Canceled) {
				workerErrors <- err
			}
		}(worker)
	}
	serverErrors := make(chan error, 1)
	go func() {
		if l.Listener != nil {
			serverErrors <- l.Server.Serve(l.Listener)
			return
		}
		serverErrors <- l.Server.ListenAndServe()
	}()
	var runErr error
	select {
	case <-runCtx.Done():
		runErr = context.Cause(runCtx)
	case err := <-workerErrors:
		runErr = err
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = err
		}
	}
	cancel()
	l.admission.Lock()
	l.closing = true
	l.admission.Unlock()

	timeout := l.ShutdownTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), timeout)
	defer shutdownCancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- l.Server.Shutdown(shutdownCtx) }()
	workersDone := make(chan struct{})
	go func() { workers.Wait(); close(workersDone) }()
	drainDone := make(chan struct{})
	go func() { l.active.Wait(); close(drainDone) }()

	serverFinished, workersFinished, drainFinished := false, false, false
	var shutdownErr error
	for !serverFinished || !workersFinished || !drainFinished {
		select {
		case err := <-serverDone:
			serverFinished = true
			shutdownErr = errors.Join(shutdownErr, err)
			serverDone = nil
		case <-workersDone:
			workersFinished = true
			workersDone = nil
		case <-drainDone:
			drainFinished = true
			drainDone = nil
		case <-shutdownCtx.Done():
			shutdownErr = errors.Join(shutdownErr, shutdownCtx.Err(), l.Server.Close())
			forceCtx, forceCancel := context.WithTimeout(context.Background(), timeout)
			defer forceCancel()
			for !workersFinished || !drainFinished {
				select {
				case <-workersDone:
					workersFinished = true
					workersDone = nil
				case <-drainDone:
					drainFinished = true
					drainDone = nil
				case <-forceCtx.Done():
					return errors.Join(runErr, shutdownErr, errors.New("shutdown left active workers or handlers; store remains open"))
				}
			}
			serverFinished = true
		}
	}

	closeCtx, closeCancel := context.WithTimeout(context.Background(), timeout)
	defer closeCancel()
	if l.Checkpointer != nil {
		shutdownErr = errors.Join(shutdownErr, l.Checkpointer.Checkpoint(closeCtx))
	}
	if l.Store != nil {
		shutdownErr = errors.Join(shutdownErr, l.Store.Close())
	}
	return errors.Join(runErr, shutdownErr)
}

func SignalContext(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}
