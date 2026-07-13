package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type liveStub struct{ err error }

func (l liveStub) PingContext(context.Context) error { return l.err }

type readyStub bool

func (r readyStub) Ready(context.Context) bool { return bool(r) }
func TestHealthAndReadinessDoNotLeakDetails(t *testing.T) {
	for _, test := range []struct {
		name    string
		handler http.Handler
		status  int
	}{{"healthy", HealthHandler(liveStub{}), 200}, {"database down", HealthHandler(liveStub{errors.New("sqlite secret path")}), 503}, {"ready", ReadyHandler(readyStub(true)), 200}, {"not ready", ReadyHandler(readyStub(false)), 503}} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			test.handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
			if response.Code != test.status {
				t.Fatalf("status=%d", response.Code)
			}
			if strings.Contains(response.Body.String(), "sqlite") || strings.Contains(response.Body.String(), "account") {
				t.Fatalf("leak=%s", response.Body.String())
			}
		})
	}
}
