package routing

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"byoo/internal/xai"
)

func TestStreamFailsOverOnlyBeforeFirstEventWithoutDuplicates(t *testing.T) {
	fixture, accounts := newExecutionFixture(t, 2)
	defer fixture.close()
	recorder := &recordedUsage{values: make(map[string][]LocalUsageDelta)}
	fixture.executor.SetUsageRecorder(recorder)
	var mu sync.Mutex
	calls := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		mu.Lock()
		calls[token]++
		mu.Unlock()
		if token == "Bearer token-a" {
			w.Header().Set("Retry-After", "120")
			http.Error(w, "try another", http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"only-once\"}\n\n")
		fmt.Fprint(w, "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":3,\"output_tokens\":4}}}\n\n")
	}))
	defer server.Close()
	fixture.executor.client = xai.NewClient(xai.HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second, SSEIdleTimeout: time.Second})

	stream, err := fixture.executor.Stream(context.Background(), Request{Model: "grok-4.5", Body: []byte(`{"tools":[{"type":"x_search"}]}`), PreferredAccountID: accounts[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if stream.AccountID() != accounts[1].ID || stream.Committed() {
		t.Fatalf("stream account=%s committed=%v", stream.AccountID(), stream.Committed())
	}
	state, stateErr := fixture.states.Get(context.Background(), accounts[0].ID, "grok-4.5", time.Now().UTC())
	if stateErr != nil || state.Until == nil || time.Until(*state.Until) < 90*time.Second {
		t.Fatalf("Retry-After cooldown not preserved: state=%+v err=%v", state, stateErr)
	}
	first, err := stream.Next(context.Background())
	if err != nil || string(first.Data) != `{"type":"response.output_text.delta","delta":"only-once"}` || !stream.Committed() {
		t.Fatalf("first=%s committed=%v err=%v", first.Data, stream.Committed(), err)
	}
	completed, err := stream.Next(context.Background())
	if err != nil || !strings.Contains(string(completed.Data), `"type":"response.completed"`) {
		t.Fatalf("completed=%s err=%v", completed.Data, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls["Bearer token-a"] != 1 || calls["Bearer token-b"] != 1 {
		t.Fatalf("calls=%v", calls)
	}
	if got := recorder.latest(accounts[0].ID); got.Requests != 1 || got.Failures != 1 {
		t.Fatalf("failed delta=%+v", got)
	}
	if got := recorder.latest(accounts[1].ID); got.Requests != 1 || got.InputTokens != 3 || got.OutputTokens != 4 {
		t.Fatalf("success delta=%+v", got)
	}
}

func TestStreamFailureAfterFirstEventNeverReplays(t *testing.T) {
	fixture, accounts := newExecutionFixture(t, 2)
	defer fixture.close()
	var mu sync.Mutex
	calls := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		mu.Lock()
		calls[token]++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"not-replayed\"}\n\n")
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		// Returning closes the body before a terminal event.
	}))
	defer server.Close()
	fixture.executor.client = xai.NewClient(xai.HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second, SSEIdleTimeout: time.Second})

	stream, err := fixture.executor.Stream(context.Background(), Request{Model: "grok-4.5", Body: []byte(`{"tools":[{"type":"x_search"}]}`), PreferredAccountID: accounts[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	first, err := stream.Next(context.Background())
	if err != nil || string(first.Data) != `{"type":"response.output_text.delta","delta":"not-replayed"}` {
		t.Fatalf("first=%s err=%v", first.Data, err)
	}
	_, err = stream.Next(context.Background())
	var executionErr *ExecutionError
	if !errors.As(err, &executionErr) || !stream.Committed() {
		t.Fatalf("err=%v committed=%v", err, stream.Committed())
	}
	mu.Lock()
	defer mu.Unlock()
	if calls["Bearer token-a"] != 1 || calls["Bearer token-b"] != 0 {
		t.Fatalf("post-commit failover occurred: %v", calls)
	}
}

func TestStreamCancellationClosesActiveUpstream(t *testing.T) {
	fixture, accounts := newExecutionFixture(t, 2)
	defer fixture.close()
	upstreamClosed := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"buffered\"}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(upstreamClosed)
	}))
	defer server.Close()
	fixture.executor.client = xai.NewClient(xai.HTTPConfig{BaseURL: server.URL, RequestTimeout: 5 * time.Second, SSEIdleTimeout: 5 * time.Second})

	stream, err := fixture.executor.Stream(context.Background(), Request{Model: "grok-4.5", Body: []byte(`{"tools":[{"type":"x_search"}]}`), PreferredAccountID: accounts[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = stream.Next(ctx)
	var executionErr *ExecutionError
	if !errors.As(err, &executionErr) || executionErr.Classified.Class != ClassCancelled || stream.Committed() {
		t.Fatalf("err=%v committed=%v", err, stream.Committed())
	}
	select {
	case <-upstreamClosed:
	case <-time.After(time.Second):
		t.Fatal("active upstream stream was not closed on cancellation")
	}
}

func TestStreamToolCallCommitBoundaryNeverReplays(t *testing.T) {
	const toolEvent = `{"type":"response.output_item.added","item":{"type":"function_call","call_id":"call-1","name":"lookup","arguments":""}}`

	t.Run("failure before tool event fails over once", func(t *testing.T) {
		fixture, accounts := newExecutionFixture(t, 2)
		defer fixture.close()
		var mu sync.Mutex
		calls := make(map[string]int)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("Authorization")
			mu.Lock()
			calls[token]++
			mu.Unlock()
			if token == "Bearer token-a" {
				http.Error(w, "pre-commit failure", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "data: %s\n\n", toolEvent)
			fmt.Fprint(w, "data: {\"type\":\"response.completed\"}\n\n")
		}))
		defer server.Close()
		fixture.executor.client = xai.NewClient(xai.HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second, SSEIdleTimeout: time.Second})

		stream, err := fixture.executor.Stream(context.Background(), Request{Model: "grok-4.5", Body: []byte(`{"tools":[{"type":"x_search"}]}`), PreferredAccountID: accounts[0].ID})
		if err != nil {
			t.Fatal(err)
		}
		first, err := stream.Next(context.Background())
		if err != nil || string(first.Data) != toolEvent {
			t.Fatalf("tool event=%s err=%v", first.Data, err)
		}
		if _, err := stream.Next(context.Background()); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		if calls["Bearer token-a"] != 1 || calls["Bearer token-b"] != 1 {
			t.Fatalf("calls=%v", calls)
		}
	})

	t.Run("failure after tool event never replays", func(t *testing.T) {
		fixture, accounts := newExecutionFixture(t, 2)
		defer fixture.close()
		var mu sync.Mutex
		calls := make(map[string]int)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("Authorization")
			mu.Lock()
			calls[token]++
			mu.Unlock()
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "data: %s\n\n", toolEvent)
			w.(http.Flusher).Flush()
		}))
		defer server.Close()
		fixture.executor.client = xai.NewClient(xai.HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second, SSEIdleTimeout: time.Second})

		stream, err := fixture.executor.Stream(context.Background(), Request{Model: "grok-4.5", Body: []byte(`{"tools":[{"type":"x_search"}]}`), PreferredAccountID: accounts[0].ID})
		if err != nil {
			t.Fatal(err)
		}
		first, err := stream.Next(context.Background())
		if err != nil || string(first.Data) != toolEvent || !stream.Committed() {
			t.Fatalf("tool event=%s committed=%v err=%v", first.Data, stream.Committed(), err)
		}
		if _, err := stream.Next(context.Background()); err == nil {
			t.Fatal("truncated tool-call stream unexpectedly succeeded")
		}
		mu.Lock()
		defer mu.Unlock()
		if calls["Bearer token-a"] != 1 || calls["Bearer token-b"] != 0 {
			t.Fatalf("tool call replayed on another account: %v", calls)
		}
	})
}

func TestRoutedStreamConcurrentNextAndCloseIsRaceSafe(t *testing.T) {
	fixture, accounts := newExecutionFixture(t, 1)
	defer fixture.close()
	recorder := &recordedUsage{values: make(map[string][]LocalUsageDelta)}
	fixture.executor.SetUsageRecorder(recorder)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"first\"}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	fixture.executor.client = xai.NewClient(xai.HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second, SSEIdleTimeout: time.Second})
	stream, err := fixture.executor.Stream(context.Background(), Request{Model: "grok-4.5", Body: []byte(`{"tools":[{"type":"x_search"}]}`), PreferredAccountID: accounts[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() { close(started); _, err := stream.Next(context.Background()); done <- err }()
	<-started
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("blocked Next succeeded after Close")
	}
	if got := recorder.latest(accounts[0].ID); got.Requests != 1 || got.Failures != 1 {
		t.Fatalf("delta=%+v", got)
	}
}

func TestRoutedStreamIncompleteIsTerminalSuccess(t *testing.T) {
	fixture, accounts := newExecutionFixture(t, 1)
	defer fixture.close()
	recorder := &recordedUsage{values: make(map[string][]LocalUsageDelta)}
	fixture.executor.SetUsageRecorder(recorder)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"type\":\"response.incomplete\",\"response\":{\"usage\":{\"input_tokens\":8,\"output_tokens\":2}}}\n\n")
	}))
	defer server.Close()
	fixture.executor.client = xai.NewClient(xai.HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second, SSEIdleTimeout: time.Second})
	stream, err := fixture.executor.Stream(context.Background(), Request{Model: "grok-4.5", Body: []byte(`{"tools":[{"type":"x_search"}]}`), PreferredAccountID: accounts[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	event, err := stream.Next(context.Background())
	if err != nil || !strings.Contains(string(event.Data), "response.incomplete") {
		t.Fatalf("event=%s err=%v", event.Data, err)
	}
	_ = stream.Close()
	if got := recorder.latest(accounts[0].ID); got.Failures != 0 || got.InputTokens != 8 || got.OutputTokens != 2 {
		t.Fatalf("delta=%+v", got)
	}
}

func TestRoutedStreamTerminalClaimWinsConcurrentClose(t *testing.T) {
	for _, eventType := range []string{"response.completed", "response.incomplete"} {
		t.Run(eventType, func(t *testing.T) {
			claimed := 0
			for range 20 {
				fixture, accounts := newExecutionFixture(t, 1)
				recorder := &recordedUsage{values: make(map[string][]LocalUsageDelta)}
				fixture.executor.SetUsageRecorder(recorder)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprintf(w, "data: {\"type\":%q,\"response\":{\"usage\":{\"input_tokens\":11,\"output_tokens\":12}}}\n\n", eventType)
				}))
				fixture.executor.client = xai.NewClient(xai.HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second, SSEIdleTimeout: time.Second})
				stream, err := fixture.executor.Stream(context.Background(), Request{Model: "grok-4.5", Body: []byte(`{"tools":[{"type":"x_search"}]}`), PreferredAccountID: accounts[0].ID})
				if err != nil {
					server.Close()
					fixture.close()
					t.Fatal(err)
				}
				result := make(chan error, 1)
				go func() { _, err := stream.Next(context.Background()); result <- err }()
				runtime.Gosched()
				_ = stream.Close()
				nextErr := <-result
				if nextErr == nil {
					claimed++
					if got := recorder.latest(accounts[0].ID); got.Failures != 0 || got.InputTokens != 11 || got.OutputTokens != 12 {
						server.Close()
						fixture.close()
						t.Fatalf("claimed terminal delta=%+v", got)
					}
				}
				server.Close()
				fixture.close()
			}
			if claimed == 0 {
				t.Fatal("Close won every terminal race; test did not exercise claimed outcome")
			}
		})
	}
}
