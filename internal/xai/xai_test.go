package xai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSSEParserLargeMultilineAndCancellation(t *testing.T) {
	large := strings.Repeat("x", 70<<10)
	parser := NewSSEParser(io.NopCloser(strings.NewReader(": comment\nevent: custom\ndata: first\ndata: "+large+"\n\n")), time.Second)
	event, err := parser.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if event.Event != "custom" || !strings.HasPrefix(string(event.Data), "first\n") || len(event.Data) < 70<<10 {
		t.Fatalf("event = %q %d", event.Event, len(event.Data))
	}
	reader, writer := io.Pipe()
	blocked := NewSSEParser(reader, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := blocked.Next(ctx); err != context.Canceled {
		t.Fatalf("cancel error = %v", err)
	}
	_ = writer.Close()
}

func TestResponsesExecutorAndHeaders(t *testing.T) {
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		for name, want := range map[string]string{"Authorization": "Bearer token", "X-Xai-Token-Auth": "xai-grok-cli", "X-Grok-Client-Version": "0.2.99", "X-Grok-Model-Override": "grok-4.5", "User-Agent": "byoo/test"} {
			if got := r.Header.Get(name); got != want {
				t.Fatalf("%s=%q", name, got)
			}
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &captured); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"type\":\"response.created\"}\n\ndata: {\"type\":\"response.completed\"}\n\n")
	}))
	defer server.Close()
	client := NewClient(HTTPConfig{BaseURL: server.URL + "/v1", ClientVersion: "0.2.99", UserAgent: "byoo/test", RequestTimeout: time.Second, SSEIdleTimeout: time.Second})
	body := []byte(`{"model":"grok-4.5","stream":false,"stream":false,"store":true,"store":true,"tools":[{"type":"x_search"}]}`)
	events, err := client.Execute(context.Background(), "token", "grok-4.5", body)
	if err != nil || len(events) != 2 {
		t.Fatalf("events=%v err=%v", events, err)
	}
	if captured["stream"] != true || captured["store"] != false {
		t.Fatalf("body=%v", captured)
	}
	if _, err := client.Execute(context.Background(), "token", "grok-4.5", []byte(`{"tools":[]}`)); err == nil {
		t.Fatal("missing search reached network")
	}
	if _, err := client.Execute(context.Background(), "token", "grok-4.5", []byte(`{"tools":[{"type":"x_search"}],"tool_choice":"none"}`)); err == nil {
		t.Fatal("disabled search reached network")
	}
}

func TestPrepareDoesNotInflatePromptsWithHTMLEscaping(t *testing.T) {
	text := strings.Repeat("<system-notice>", 6000)
	body := []byte(`{"input":[{"type":"message","role":"developer","content":[{"type":"input_text","text":"` + text + `"}]}],"tools":[{"type":"x_search"}]}`)
	prepared, err := (&Client{}).prepare(body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(prepared), `\u003c`) || len(prepared) > len(body)+128 {
		t.Fatalf("request expanded from %d to %d bytes", len(body), len(prepared))
	}
}

func TestResponsesExecutorAcceptsIncompleteTerminal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"type\":\"response.incomplete\",\"response\":{\"status\":\"incomplete\"}}\n\n")
	}))
	defer server.Close()
	client := NewClient(HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second, SSEIdleTimeout: time.Second})
	events, err := client.Execute(context.Background(), "token", "grok-4.5", []byte(`{"tools":[{"type":"x_search"}]}`))
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%v err=%v", events, err)
	}
}

func TestResponsesExecutorErrors(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		stream  bool
	}{
		{"non2xx", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "secret upstream", 429) }, false},
		{"missing terminal", func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, "data: {\"type\":\"response.created\"}\n\n")
		}, false},
		{"invalid first", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "data: nope\n\n") }, true},
		{"non-object first", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "data: null\n\n") }, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()
			client := NewClient(HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second, SSEIdleTimeout: time.Second})
			body := []byte(`{"tools":[{"type":"x_search"}]}`)
			var err error
			if test.stream {
				_, err = client.Stream(context.Background(), "token", "grok-4.5", body)
			} else {
				_, err = client.Execute(context.Background(), "token", "grok-4.5", body)
			}
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestSSEIdleTimeoutTracksActivity(t *testing.T) {
	reader, writer := io.Pipe()
	parser := NewSSEParser(reader, 30*time.Millisecond)
	go func() {
		for _, chunk := range []string{"data: {", `"type":`, `"response.created"`, "}\n", "\n"} {
			_, _ = io.WriteString(writer, chunk)
			time.Sleep(10 * time.Millisecond)
		}
		_ = writer.Close()
	}()
	event, err := parser.Next(context.Background())
	if err != nil || string(event.Data) != `{"type":"response.created"}` {
		t.Fatalf("fragmented event = %q, %v", event.Data, err)
	}
}

func TestResponsesTotalTimeoutAndBufferedCancellation(t *testing.T) {
	t.Run("total timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		}))
		defer server.Close()
		client := NewClient(HTTPConfig{BaseURL: server.URL, RequestTimeout: 50 * time.Millisecond, SSEIdleTimeout: time.Second})
		_, err := client.Execute(context.Background(), "token", "grok-4.5", []byte(`{"tools":[{"type":"x_search"}]}`))
		if err == nil {
			t.Fatal("request exceeded total timeout")
		}
	})
	t.Run("buffered cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, "data: {\"type\":\"response.created\"}\n\n")
		}))
		defer server.Close()
		client := NewClient(HTTPConfig{BaseURL: server.URL, RequestTimeout: time.Second, SSEIdleTimeout: time.Second})
		ctx, cancel := context.WithCancel(context.Background())
		stream, err := client.Stream(ctx, "token", "grok-4.5", []byte(`{"tools":[{"type":"x_search"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		if _, err := stream.Next(ctx); err != context.Canceled {
			t.Fatalf("buffered event after cancellation: %v", err)
		}
	})
}
