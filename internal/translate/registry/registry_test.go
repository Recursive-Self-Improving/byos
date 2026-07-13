package registry

import "testing"

type fake struct{}

func (fake) Request(string, []byte, bool) ([]byte, error)                  { return nil, nil }
func (fake) Response(string, []byte, [][]byte) ([]byte, error)             { return nil, nil }
func (fake) Stream(string, []byte, []byte, *StreamState) ([][]byte, error) { return nil, nil }

func TestRegistryAndSSEHelpers(t *testing.T) {
	r := New()
	if err := r.Register(OpenAIChat, fake{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Get(OpenAIChat); !ok {
		t.Fatal("translator missing")
	}
	if err := r.Register(OpenAIChat, fake{}); err == nil {
		t.Fatal("duplicate accepted")
	}
	event := SSE("message_stop", []byte(`{"type":"message_stop"}`))
	if string(event) != "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n" {
		t.Fatalf("event=%q", event)
	}
	if got := string(EventData([]byte("data: {\"type\":\"x\"}\r\n"))); got != `{"type":"x"}` {
		t.Fatalf("data=%q", got)
	}
}
