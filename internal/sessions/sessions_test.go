package sessions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	appcrypto "byoo/internal/crypto"
	"byoo/internal/store"
)

func sessionService(t *testing.T) (*Service, *store.SQLite) {
	t.Helper()
	database, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := appcrypto.DeriveKeys(bytes.Repeat([]byte{13}, 32))
	return NewService(store.NewResponseRepository(database.DB, keys)), database
}
func TestReconstructTextToolsReasoningAndAffinity(t *testing.T) {
	service, database := sessionService(t)
	defer database.Close()
	now := time.Now().UTC().Truncate(time.Second)
	service.now = func() time.Time { return now }
	first := CompletedNode{ResponseID: "r1", Model: "grok-4.5", AccountID: "acct-a", CanonicalInput: []byte(`{"input":"hello"}`), TerminalOutput: []byte(`{"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]},{"type":"reasoning","encrypted_content":"cipher"}]}`)}
	if err := service.PersistCompleted(context.Background(), first, true); err != nil {
		t.Fatal(err)
	}
	second := CompletedNode{ResponseID: "r2", PreviousResponseID: "r1", Model: "grok-4.5", AccountID: "acct-b", CanonicalInput: []byte(`{"input":[{"type":"function_call_output","call_id":"c","output":"ok"}]}`), TerminalOutput: []byte(`{"output":[{"type":"function_call","call_id":"next","name":"tool","arguments":"{}"}]}`)}
	if err := service.PersistCompleted(context.Background(), second, true); err != nil {
		t.Fatal(err)
	}
	result, err := service.Prepare(context.Background(), []byte(`{"previous_response_id":"r2","input":"current","store":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if result.PreferredAccountID != "acct-b" {
		t.Fatalf("affinity=%q", result.PreferredAccountID)
	}
	if strings.Contains(string(result.Body), "previous_response_id") {
		t.Fatal("previous ID sent upstream")
	}
	var body map[string]any
	if err := json.Unmarshal(result.Body, &body); err != nil {
		t.Fatal(err)
	}
	items := body["input"].([]any)
	if len(items) != 6 || body["store"] != false {
		t.Fatalf("body=%s items=%d", result.Body, len(items))
	}
	wantTypes := []string{"message", "message", "reasoning", "function_call_output", "function_call", "message"}
	for index, want := range wantTypes {
		item := items[index].(map[string]any)
		if item["type"] != want {
			t.Fatalf("item %d type = %v, want %s", index, item["type"], want)
		}
	}
}
func TestStoreFalseFailureExpiryAndRestart(t *testing.T) {
	ctx := context.Background()
	service, database := sessionService(t)
	dataDir := database.Path()
	_ = dataDir
	now := time.Now().UTC().Truncate(time.Second)
	service.now = func() time.Time { return now }
	no := false
	if err := service.PersistCompleted(ctx, CompletedNode{ResponseID: "nostore", CanonicalInput: []byte(`{"input":"x"}`), TerminalOutput: []byte(`{"output":[]}`), Store: &no}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Prepare(ctx, []byte(`{"previous_response_id":"nostore","input":"x"}`)); !errors.Is(err, ErrPreviousResponseNotFound) {
		t.Fatalf("store false error=%v", err)
	}
	if err := service.PersistCompleted(ctx, CompletedNode{ResponseID: "failed", CanonicalInput: []byte(`{"input":"x"}`), TerminalOutput: []byte(`{"output":[]}`)}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Prepare(ctx, []byte(`{"previous_response_id":"failed","input":"x"}`)); !errors.Is(err, ErrPreviousResponseNotFound) {
		t.Fatalf("failed error=%v", err)
	}
	if err := service.PersistCompleted(ctx, CompletedNode{ResponseID: "stored", CanonicalInput: []byte(`{"input":"x"}`), TerminalOutput: []byte(`{"output":[]}`)}, true); err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now.Add(Retention + time.Second) }
	if _, err := service.Prepare(ctx, []byte(`{"previous_response_id":"stored","input":"x"}`)); !errors.Is(err, ErrPreviousResponseNotFound) {
		t.Fatalf("expired error=%v", err)
	}
	if count, err := service.Cleanup(ctx); err != nil || count != 1 {
		t.Fatalf("cleanup=%d %v", count, err)
	}
}
func TestReconstructLimitsCycleAndMissingParent(t *testing.T) {
	ctx := context.Background()
	service, database := sessionService(t)
	defer database.Close()
	now := time.Now().UTC()
	service.now = func() time.Time { return now }
	repo := service.repo
	if err := repo.Put(ctx, store.ResponseSession{ResponseID: "cycle-a", PreviousResponseID: "cycle-b", Model: "grok", Input: []byte(`{"input":[]}`), Output: []byte(`{"output":[]}`), Store: true, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Put(ctx, store.ResponseSession{ResponseID: "cycle-b", PreviousResponseID: "cycle-a", Model: "grok", Input: []byte(`{"input":[]}`), Output: []byte(`{"output":[]}`), Store: true, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Prepare(ctx, []byte(`{"previous_response_id":"cycle-a","input":[]}`)); !errors.Is(err, ErrContextLengthExceeded) {
		t.Fatalf("cycle error=%v", err)
	}
	if err := repo.Put(ctx, store.ResponseSession{ResponseID: "orphan", PreviousResponseID: "missing", Model: "grok", Input: []byte(`{"input":[]}`), Output: []byte(`{"output":[]}`), Store: true, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Prepare(ctx, []byte(`{"previous_response_id":"orphan","input":[]}`)); !errors.Is(err, ErrPreviousResponseNotFound) {
		t.Fatalf("missing error=%v", err)
	}
	huge := strings.Repeat("x", MaxChainBytes)
	if err := repo.Put(ctx, store.ResponseSession{ResponseID: "huge", Model: "grok", Input: []byte(`{"input":"` + huge + `"}`), Output: []byte(`{"output":[]}`), Store: true, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Prepare(ctx, []byte(`{"previous_response_id":"huge","input":[]}`)); !errors.Is(err, ErrContextLengthExceeded) {
		t.Fatalf("size error=%v", err)
	}
}

func TestReconstructNodeLimit(t *testing.T) {
	ctx := context.Background()
	service, database := sessionService(t)
	defer database.Close()
	now := time.Now().UTC()
	service.now = func() time.Time { return now }
	previous := ""
	for index := 1; index <= MaxChainNodes+1; index++ {
		id := fmt.Sprintf("node-%03d", index)
		if err := service.repo.Put(ctx, store.ResponseSession{ResponseID: id, PreviousResponseID: previous, Model: "grok", Input: []byte(`{"input":[]}`), Output: []byte(`{"output":[]}`), Store: true, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		previous = id
		if index == MaxChainNodes {
			if _, err := service.Prepare(ctx, []byte(`{"previous_response_id":"`+id+`","input":[]}`)); err != nil {
				t.Fatalf("%d-node chain rejected: %v", MaxChainNodes, err)
			}
		}
	}
	if _, err := service.Prepare(ctx, []byte(`{"previous_response_id":"`+previous+`","input":[]}`)); !errors.Is(err, ErrContextLengthExceeded) {
		t.Fatalf("%d-node chain error = %v", MaxChainNodes+1, err)
	}
}

func TestReconstructResolvesItemReferencesAndIgnoresServerTools(t *testing.T) {
	ctx := context.Background()
	service, database := sessionService(t)
	defer database.Close()
	if err := service.PersistCompleted(ctx, CompletedNode{ResponseID: "reference-root", AccountID: "old", CanonicalInput: []byte(`{"input":"question"}`), TerminalOutput: []byte(`{"output":[{"type":"x_search_call","id":"search"},{"type":"message","id":"msg-1","role":"assistant","content":"answer"}]}`)}, true); err != nil {
		t.Fatal(err)
	}
	if err := service.PersistCompleted(ctx, CompletedNode{ResponseID: "reference-child", PreviousResponseID: "reference-root", AccountID: "old", CanonicalInput: []byte(`{"input":[{"type":"item_reference","item_id":"msg-1"}]}`), TerminalOutput: []byte(`{"output":[]}`)}, true); err != nil {
		t.Fatal(err)
	}
	result, err := service.Prepare(ctx, []byte(`{"previous_response_id":"reference-child","input":"next"}`))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(result.Body, []byte("item_reference")) || bytes.Contains(result.Body, []byte("x_search_call")) {
		t.Fatalf("reconstruction is not self-contained: %s", result.Body)
	}
	if count := bytes.Count(result.Body, []byte(`"id":"msg-1"`)); count != 2 {
		t.Fatalf("resolved message count = %d body=%s", count, result.Body)
	}
}
