package devin

import (
	"encoding/base64"
	"errors"
	"io"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestPKCEAndStateShapes(t *testing.T) {
	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		t.Fatal(err)
	}
	decodedVerifier, err := base64.RawURLEncoding.DecodeString(verifier)
	if err != nil || len(decodedVerifier) != 96 || len(verifier) != 128 || strings.Contains(verifier, "=") {
		t.Fatalf("verifier shape len=%d decoded=%d err=%v", len(verifier), len(decodedVerifier), err)
	}
	decodedChallenge, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(decodedChallenge) != 32 || len(challenge) != 43 || challenge != ChallengeS256(verifier) {
		t.Fatalf("challenge shape len=%d decoded=%d err=%v", len(challenge), len(decodedChallenge), err)
	}
	state, err := GenerateState()
	if err != nil {
		t.Fatal(err)
	}
	decodedState, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil || len(decodedState) != 32 || len(state) != 43 || strings.Contains(state, "=") {
		t.Fatalf("state shape len=%d decoded=%d err=%v", len(state), len(decodedState), err)
	}
}

func TestChallengeS256KnownVector(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	if got, want := ChallengeS256(verifier), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"; got != want {
		t.Fatalf("challenge=%q want=%q", got, want)
	}
}

func TestAuthorizationURLExactQueryAndConfiguredCallback(t *testing.T) {
	for _, origin := range []string{"https://byos.example.test", "https://byos.example.test/"} {
		callback, err := CallbackURL(OAuthConfig{CallbackOrigin: origin, CallbackPath: "/admin/api/v1/oauth/devin/callback"})
		if err != nil {
			t.Fatal(err)
		}
		if callback != "https://byos.example.test/admin/api/v1/oauth/devin/callback" {
			t.Fatalf("callback=%q", callback)
		}
		raw, err := AuthorizationURL(callback, "state", "challenge")
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Scheme != "https" || parsed.Host != "app.devin.ai" || parsed.Path != "/auth/cli/continue" {
			t.Fatalf("endpoint=%s", parsed)
		}
		want := url.Values{"redirect_uri": {callback}, "state": {"state"}, "prompt": {"select_account"}, "code_challenge": {"challenge"}, "code_challenge_method": {"S256"}}
		if !reflect.DeepEqual(parsed.Query(), want) {
			t.Fatalf("query=%v want=%v", parsed.Query(), want)
		}
	}
}

func TestCallbackURLRejectsUnsafeConfiguration(t *testing.T) {
	for _, config := range []OAuthConfig{
		{}, {CallbackOrigin: "http://byos.example.test", CallbackPath: "/callback"},
		{CallbackOrigin: "https://user@byos.example.test", CallbackPath: "/callback"},
		{CallbackOrigin: "https://byos.example.test/base", CallbackPath: "/callback"},
		{CallbackOrigin: "https://byos.example.test", CallbackPath: "callback"},
		{CallbackOrigin: "https://byos.example.test", CallbackPath: "//evil.test/callback"},
		{CallbackOrigin: "https://byos.example.test", CallbackPath: "/callback?secret=x"},
	} {
		if _, err := CallbackURL(config); !errors.Is(err, ErrInvalidCallback) {
			t.Fatalf("config=%+v err=%v", config, err)
		}
	}
}

func TestConcurrentGenerationIsUnique(t *testing.T) {
	const count = 64
	states := make(map[string]struct{}, count)
	verifiers := make(map[string]struct{}, count)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			verifier, _, err := GeneratePKCE()
			if err != nil {
				t.Error(err)
				return
			}
			state, err := GenerateState()
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			states[state] = struct{}{}
			verifiers[verifier] = struct{}{}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(states) != count || len(verifiers) != count {
		t.Fatalf("states=%d verifiers=%d", len(states), len(verifiers))
	}
}

func TestRandomFailuresAreSanitized(t *testing.T) {
	failure := failingReader{err: errors.New("RAW-SECRET-random-source")}
	if _, _, err := generatePKCE(failure); !errors.Is(err, ErrRandomness) || strings.Contains(err.Error(), "RAW-SECRET") {
		t.Fatalf("pkce err=%v", err)
	}
	if _, err := generateState(failure); !errors.Is(err, ErrRandomness) || strings.Contains(err.Error(), "RAW-SECRET") {
		t.Fatalf("state err=%v", err)
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

var _ io.Reader = failingReader{}
