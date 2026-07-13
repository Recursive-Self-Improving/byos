package routing

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	appcrypto "supergrok-api/internal/crypto"
	"supergrok-api/internal/sessions"
	"supergrok-api/internal/store"
)

func TestSchedulerRoundRobinCapabilitiesAndAffinity(t *testing.T) {
	scheduler := NewScheduler()
	now := time.Now()
	accounts := []Candidate{{ID: "a", Enabled: true, Valid: true, CapabilitiesKnown: true, Capabilities: map[string]bool{"grok-4.5": true}}, {ID: "b", Enabled: true, Valid: true, CapabilitiesKnown: true, Capabilities: map[string]bool{"grok-4.5": true}}, {ID: "unknown", Enabled: true, Valid: true}, {ID: "cool", Enabled: true, Valid: true, CapabilitiesKnown: true, Capabilities: map[string]bool{"grok-4.5": true}, CooldownUntil: map[string]time.Time{"grok-4.5": now.Add(time.Hour)}}}
	first, _ := scheduler.Order("grok-4.5", accounts, "", now)
	second, _ := scheduler.Order("grok-4.5", accounts, "", now)
	third, _ := scheduler.Order("grok-4.5", accounts, "", now)
	if first[0].ID != "a" || second[0].ID != "b" || third[0].ID != "a" {
		t.Fatalf("round robin=%s,%s,%s", first[0].ID, second[0].ID, third[0].ID)
	}
	preferred, _ := scheduler.Order("grok-4.5", accounts, "b", now)
	if preferred[0].ID != "b" {
		t.Fatalf("preferred=%s", preferred[0].ID)
	}
	fallback, _ := scheduler.Order("other", accounts, "", now)
	if len(fallback) != 1 || fallback[0].ID != "unknown" {
		t.Fatalf("unknown fallback=%v", fallback)
	}
	globalCooling := []Candidate{{ID: "global", Enabled: true, Valid: true, CooldownUntil: map[string]time.Time{"*": now.Add(time.Hour)}}, {ID: "ready", Enabled: true, Valid: true}}
	globalOrder, err := scheduler.Order("other-model", globalCooling, "", now)
	if err != nil || len(globalOrder) != 1 || globalOrder[0].ID != "ready" {
		t.Fatalf("global cooldown order = %v, %v", globalOrder, err)
	}
}
func TestSchedulerConcurrentAccess(t *testing.T) {
	scheduler := NewScheduler()
	accounts := []Candidate{{ID: "a", Enabled: true, Valid: true}, {ID: "b", Enabled: true, Valid: true}}
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := scheduler.Order("grok", accounts, "", time.Now()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

func TestSchedulerModelCursorIsolationAndMutation(t *testing.T) {
	now := time.Now()
	scheduler := NewScheduler()
	accounts := []Candidate{{ID: "a", Enabled: true, Valid: true}, {ID: "b", Enabled: true, Valid: true}}
	firstA, _ := scheduler.Order("model-a", accounts, "", now)
	firstB, _ := scheduler.Order("model-b", accounts, "", now)
	secondA, _ := scheduler.Order("model-a", accounts, "", now)
	secondB, _ := scheduler.Order("model-b", accounts, "", now)
	if firstA[0].ID != "a" || firstB[0].ID != "a" || secondA[0].ID != "b" || secondB[0].ID != "b" {
		t.Fatalf("model cursors are coupled: %s %s %s %s", firstA[0].ID, firstB[0].ID, secondA[0].ID, secondB[0].ID)
	}
	mutated := []Candidate{{ID: "c", Enabled: true, Valid: true}, {ID: "a", Enabled: true, Valid: true}}
	ordered, err := scheduler.Order("model-a", mutated, "", now)
	if err != nil || len(ordered) != 2 || ordered[0].ID == ordered[1].ID {
		t.Fatalf("mutated candidates = %v, %v", ordered, err)
	}
}
func TestResponseAffinityFailsOverWithReconstructedTranscript(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, _ := appcrypto.DeriveKeys(bytes.Repeat([]byte{14}, 32))
	sessionService := sessions.NewService(store.NewResponseRepository(database.DB, keys))
	if err := sessionService.PersistCompleted(ctx, sessions.CompletedNode{ResponseID: "r1", Model: "grok", AccountID: "deleted", CanonicalInput: []byte(`{"input":"hello"}`), TerminalOutput: []byte(`{"output":[{"type":"message","role":"assistant","content":"hi"}]}`)}, true); err != nil {
		t.Fatal(err)
	}
	reconstructed, err := sessionService.Prepare(ctx, []byte(`{"previous_response_id":"r1","input":"again"}`))
	if err != nil {
		t.Fatal(err)
	}
	ordered, err := NewScheduler().Order("grok", []Candidate{{ID: "deleted", Enabled: false, Valid: true}, {ID: "healthy", Enabled: true, Valid: true}}, reconstructed.PreferredAccountID, time.Now())
	if err != nil || ordered[0].ID != "healthy" {
		t.Fatalf("failover=%v %v", ordered, err)
	}
	if !bytes.Contains(reconstructed.Body, []byte("hello")) || !bytes.Contains(reconstructed.Body, []byte("hi")) {
		t.Fatalf("history lost: %s", reconstructed.Body)
	}
}
