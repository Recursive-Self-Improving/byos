package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"byos/internal/api"
	apiopenai "byos/internal/api/openai"
	"byos/internal/config"
	appcrypto "byos/internal/crypto"
	"byos/internal/models"
	oauthdevin "byos/internal/oauth/devin"
	oauthxai "byos/internal/oauth/xai"
	"byos/internal/provider"
	"byos/internal/routing"
	"byos/internal/sessions"
	"byos/internal/store"
	"byos/internal/translate"
	"byos/internal/translate/registry"
	"byos/internal/usage"
	"byos/internal/xai"
)

// c9persistenceKeys derives a fixed key set for a deterministic master key so
// the same encrypted transcripts/cooldowns/usage rows can be read after reopen.
func c9persistenceKeys(t *testing.T) appcrypto.Keys {
	t.Helper()
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{77}, 32))
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	return keys
}

// c9xAIUpstream is a deterministic xAI upstream that emits one terminal
// response.completed event for every successful responses request, and returns
// HTTP 429 with a raw Retry-After header when rateLimited is set. The response
// id and token usage are fixed so persistence assertions are deterministic.
// It records the Authorization bearer token (the credential sentinel) for
// every upstream request so tests can assert the exact selected xAI
// credential reached the wire, pre and post reopen, and that no Devin
// credential ever appears here.
type c9xAIUpstream struct {
	rateLimited  int32 // atomic-ish counter; tests are single-goroutine
	retryAfter   string
	successCount int32    // increments per successful response for unique IDs
	bearers      []string // Authorization bearer tokens, one per request, in order
}

func (u *c9xAIUpstream) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/responses" || r.Method != http.MethodPost {
			t.Errorf("unexpected xAI upstream request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		// Record the credential sentinel that reached the wire. The xAI
		// client sets Authorization: Bearer <token>; the token is the
		// per-account sentinel injected by c9credentialLedger, so this
		// proves which account's credential served each upstream request.
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		u.bearers = append(u.bearers, bearer)
		if u.rateLimited > 0 {
			u.rateLimited--
			w.Header().Set("Retry-After", u.retryAfter)
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limited"}`))
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		u.successCount++
		responseID := "resp_c9_persisted"
		if u.successCount > 1 {
			responseID = fmt.Sprintf("resp_c9_persisted_%d", u.successCount)
		}
		completed := map[string]any{
			"type": "response.completed",
			"response": map[string]any{
				"id":     responseID,
				"status": "completed",
				"model":  "grok-4.5",
				"usage":  map[string]any{"input_tokens": 31, "output_tokens": 47, "input_tokens_details": map[string]any{"cached_tokens": 12}},
				"output": []any{map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": "persisted"}}}},
			},
		}
		payload, _ := json.Marshal(completed)
		fmt.Fprintf(w, "data: %s\n\n", payload)
		if flusher != nil {
			flusher.Flush()
		}
	})
}

// lastBearer returns the most recent Authorization bearer token recorded by
// the upstream, or the empty string if no request has been served.
func (u *c9xAIUpstream) lastBearer() string {
	if len(u.bearers) == 0 {
		return ""
	}
	return u.bearers[len(u.bearers)-1]
}

// c9runtime bundles the real, SQLite-backed components rebuilt after reopen.
type c9runtime struct {
	database        *store.SQLite
	keys            appcrypto.Keys
	accounts        *store.AccountRepository
	states          *store.CooldownRepository
	responses       *store.ResponseRepository
	localUsage      *store.LocalUsageRepository
	usageService    *usage.Service
	cooldowns       *routing.CooldownManager
	executor        *routing.Executor
	sessionService  *sessions.Service
	xaiCreds        *oauthxai.ProviderCredentialManager
	devinCreds      *oauthdevin.ProviderCredentialManager
	xaiLedger       *c9credentialLedger
	devinLedger     *c9credentialLedger
	devinGeneration *c9noOpDevinGeneration
	upstream        *c9xAIUpstream
}

// c9buildRuntime constructs the real component graph against a SQLite data
// directory. xAI generation uses the real xai.ProviderClient pointed at a
// deterministic httptest upstream; Devin generation is wired with a real
// credential manager but a fake generation client (Devin has no public
// generation endpoint in this test surface, and C9.4 only requires that a
func c9buildRuntime(t *testing.T, dataDir string, keys appcrypto.Keys, upstream *c9xAIUpstream, sentinels map[string]string) *c9runtime {
	t.Helper()
	ctx := context.Background()
	database, err := store.Open(ctx, dataDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	accountRepo := store.NewAccountRepository(database.DB, keys)
	capabilityRepo := store.NewModelCapabilityRepository(database.DB)
	cooldownRepo := store.NewCooldownRepository(database.DB)
	responseRepo := store.NewResponseRepository(database.DB, keys)
	localUsageRepo := store.NewLocalUsageRepository(database.DB)
	usageRepo := store.NewUsageRepository(database.DB, keys)
	usageService := usage.NewService(usageRepo, localUsageRepo)
	cooldowns := routing.NewCooldownManager(cooldownRepo, accountRepo)
	xaiCreds := oauthxai.NewProviderCredentialManager(accountRepo, nil)
	devinCreds := oauthdevin.NewProviderCredentialManager(accountRepo)
	xaiLedger := newC9CredentialLedger(xaiCreds, sentinels)
	devinLedger := newC9CredentialLedger(devinCreds, sentinels)
	devinGeneration := &c9noOpDevinGeneration{}
	xaiClient := xai.NewClient(xai.HTTPConfig{BaseURL: upstream.serverURL(t), RequestTimeout: 5 * time.Second, SSEIdleTimeout: 5 * time.Second})
	registry, err := provider.NewCapabilityRegistry([]provider.CapabilityRegistration{
		{Provider: provider.XAI, PolicyKey: "xai", Capabilities: provider.Capabilities{
			Policy:      xai.RequestPolicy{},
			Generation:  xai.NewProviderClient(xaiClient),
			Credentials: xaiLedger,
		}},
		{Provider: provider.Devin, PolicyKey: "devin", Capabilities: provider.Capabilities{
			Policy:      c9devinPassthroughPolicy{},
			Generation:  devinGeneration,
			Credentials: devinLedger,
		}},
	})
	if err != nil {
		t.Fatalf("build capability registry: %v", err)
	}
	executor := routing.NewExecutor(routing.NewScheduler(), c9newStaticCatalog(t), registry, cooldowns, accountRepo, capabilityRepo, cooldownRepo)
	executor.SetUsageRecorder(c9usageRecorder{service: usageService})
	sessionService := sessions.NewService(responseRepo)
	return &c9runtime{database: database, keys: keys, accounts: accountRepo, states: cooldownRepo, responses: responseRepo, localUsage: localUsageRepo, usageService: usageService, cooldowns: cooldowns, executor: executor, sessionService: sessionService, xaiCreds: xaiCreds, devinCreds: devinCreds, xaiLedger: xaiLedger, devinLedger: devinLedger, devinGeneration: devinGeneration, upstream: upstream}
}

func (u *c9xAIUpstream) serverURL(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(u.handler(t))
	t.Cleanup(server.Close)
	return server.URL
}

// c9newStaticCatalog builds the same immutable static catalog and alias overlay
// used by production so persistence coverage follows the configured identities.
func c9newStaticCatalog(t *testing.T) provider.ModelCatalog {
	t.Helper()
	cfg := config.Default()
	static, err := models.NewStaticCatalog(cfg.Models.Entries)
	if err != nil {
		t.Fatalf("build static catalog: %v", err)
	}
	overlay, err := models.NewStaticCatalogOverlay(static, cfg.Models.Aliases)
	if err != nil {
		t.Fatalf("build static catalog overlay: %v", err)
	}
	return overlay
}

type c9devinPassthroughPolicy struct{}

func (c9devinPassthroughPolicy) Prepare(context.Context, provider.ResolvedModel, provider.CanonicalRequest) error {
	return nil
}

// c9noOpDevinGeneration is a fake Devin generation client. It records each
// request (Credential value + model) so tests can assert a wrong-provider
// preferred account never reaches it, and emits a unique terminal
// response.completed event per call so the handler can persist a distinct
// child node whose id is parsed from the recorder body rather than hardcoded.
type c9noOpDevinGeneration struct {
	requests []provider.GenerationRequest
	calls    int32
}

func (g *c9noOpDevinGeneration) Execute(_ context.Context, r provider.GenerationRequest) ([]provider.Event, error) {
	g.requests = append(g.requests, r)
	g.calls++
	responseID := fmt.Sprintf("resp_c9_devin_%d", g.calls)
	completed := fmt.Sprintf(`{"type":"response.completed","response":{"id":%q,"status":"completed","model":%q,"usage":{"input_tokens":0,"output_tokens":0},"output":[]}}`, responseID, r.Model.UpstreamName)
	return []provider.Event{{Data: []byte(completed)}}, nil
}
func (g *c9noOpDevinGeneration) Stream(context.Context, provider.GenerationRequest) (provider.Stream, error) {
	panic("c9 Devin stream not used")
}

type c9usageRecorder struct{ service *usage.Service }

func (r c9usageRecorder) Record(ctx context.Context, accountID string, delta routing.LocalUsageDelta) error {
	return r.service.Record(ctx, accountID, usage.Delta{Requests: delta.Requests, Failures: delta.Failures, InputTokens: delta.InputTokens, OutputTokens: delta.OutputTokens, CacheReadTokens: delta.CacheReadTokens})
}

// c9credentialLedger records per-account Credential() calls so tests can
// assert exactly which account's credentials were materialized for each
// handler request. The sentinel is returned in place of the real token so the
// generation layer (xAI upstream Authorization header / Devin
// GenerationRequest.Credential) carries a per-account marker that proves the
// correct account served the request and the wrong-provider account was never
// contacted.
type c9credentialLedger struct {
	inner       provider.CredentialManager
	usability   provider.CredentialUsability
	sentinels   map[string]string // accountID -> sentinel token
	calls       map[string]int    // accountID -> Credential() call count
	usableCalls map[string]int    // accountID -> CredentialUsable() call count
}

func newC9CredentialLedger(inner provider.CredentialManager, sentinels map[string]string) *c9credentialLedger {
	return &c9credentialLedger{inner: inner, sentinels: sentinels, calls: make(map[string]int), usableCalls: make(map[string]int)}
}

func (l *c9credentialLedger) Credential(ctx context.Context, accountID string) (provider.Credential, error) {
	l.calls[accountID]++
	cred, err := l.inner.Credential(ctx, accountID)
	if err != nil {
		return cred, err
	}
	if sentinel, ok := l.sentinels[accountID]; ok {
		return provider.Credential{Value: sentinel}, nil
	}
	return cred, nil
}

func (l *c9credentialLedger) AuthenticationFailed(ctx context.Context, accountID string, upstream *provider.UpstreamError) error {
	return l.inner.AuthenticationFailed(ctx, accountID, upstream)
}

func (l *c9credentialLedger) CredentialUsable(ctx context.Context, accountID string) (bool, error) {
	l.usableCalls[accountID]++
	if l.usability == nil {
		if u, ok := l.inner.(provider.CredentialUsability); ok {
			l.usability = u
		} else {
			return true, nil
		}
	}
	return l.usability.CredentialUsable(ctx, accountID)
}

func (l *c9credentialLedger) callCount(accountID string) int   { return l.calls[accountID] }
func (l *c9credentialLedger) usableCount(accountID string) int { return l.usableCalls[accountID] }

// c9responsesHandler builds the public OpenAI Responses handler wired to the
// real executor and session service, exactly as the production runtime does.
// The transform is the real translate.NewRegistry Responses transformer, so
// the canonical request shape (input normalization, previous_response_id
// handling) matches production.
func c9responsesHandler(rt *c9runtime) apiopenai.ResponsesHandler {
	transforms := translate.NewRegistry()
	responsesTransform, ok := transforms.Get(registry.OpenAIResponses)
	if !ok {
		panic("OpenAI Responses translator is not registered")
	}
	return apiopenai.ResponsesHandler{
		Transform: responsesTransform,
		Execute:   rt.executor.Execute,
		OpenStream: func(ctx context.Context, request routing.Request) (api.RoutedStream, error) {
			return rt.executor.Stream(ctx, request)
		},
		Sessions: rt.sessionService,
	}
}

// c9postResponses issues a non-stream OpenAI Responses request through the
// public handler and returns the recorded response.
func c9postResponses(t *testing.T, handler apiopenai.ResponsesHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// c9responsesID parses the OpenAI Responses non-stream body and returns the
// response id. Tests use this to inspect the actually-persisted child node
// rather than hardcoding upstream-generated id sequences.
func c9responsesID(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var parsed struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("parse responses body: %v body=%s", err, rec.Body.String())
	}
	if parsed.ID == "" {
		t.Fatalf("responses body has no id: %s", rec.Body.String())
	}
	return parsed.ID
}

// TestC9Persistence_ManagedResponsesContinuationPersistsPreferredAccountAcrossReopen
// asserts C9.4 handler/session affinity across a SQLite reopen. Two routable
// xAI accounts (A, B) are seeded; B is created first so the round-robin
// baseline (absent affinity) prefers B. B is seeded with a far-future
// persisted absolute cooldown deadline that forces the initial public
// ResponsesHandler request onto A, whose completed response the real
// sessions.Service persists with PreferredAccountID=A. After closing and
// reopening the data directory with a fresh repos/service/executor graph and
// B's persisted cooldown_until rewritten to a past absolute timestamp, a
// baseline handler request (no affinity)
// selects B, proving the scheduler baseline prefers B. A continuation request
// carrying previous_response_id is reconstructed by the real
// sessions.Reconstruct, which injects PreferredAccountID=A, and the reopened
// executor selects A over the baseline-preferred B. The newly persisted child
// node is inspected (PreferredAccountID=A, PreviousResponseID=root) and the
// real usage.Service call ledger is read back proving A was charged and B was
// untouched by the continuation. A separate wrong-provider continuation
// (Devin model) carrying a stored xAI preferred account proves affinity cannot
// cross providers: the executor selects the Devin account, the Devin
// generation client is called once, and the xAI upstream is not contacted.
func TestC9Persistence_ManagedResponsesContinuationPersistsPreferredAccountAcrossReopen(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	keys := c9persistenceKeys(t)
	upstream := &c9xAIUpstream{}
	// B is cooled with a far-future absolute deadline so the initial public
	// request is forced onto A (the sole eligible xAI account). Between
	// phases the persisted cooldown_until is rewritten to a past absolute
	// timestamp via a direct DB update so B becomes eligible for the
	// reopened runtimes; no production clock seam is involved. created_at is
	// pinned to a fixed instant so ORDER BY deterministically yields B
	// before A.
	now := time.Now().UTC().Truncate(time.Second)

	// Per-account sentinel tokens populated after account creation. The
	// credential ledgers are wired at construction time with this map (a Go
	// map reference), so later inserts are visible to the ledgers without
	// rebuilding the runtime.
	sentinels := make(map[string]string)

	first := c9buildRuntime(t, dataDir, keys, upstream, sentinels)

	// B is created first so accounts.List (ORDER BY created_at, id) yields B
	// before A; with a fresh scheduler cursor the no-affinity baseline therefore
	// prefers B. A is created second. UpsertLogin records created_at at second
	// granularity (time.Now().Unix()), so two accounts inserted within the same
	// second tie on created_at and List falls back to the random account id,
	// making baseline selection non-deterministic. Pin B's created_at strictly
	// before A's so ORDER BY created_at, id deterministically yields B before A
	// and the fresh phase-2 scheduler cursor (0) selects B for any baseline
	// request. The continuation overrides this via PreferredAccountID=A.
	xaiB, err := first.accounts.UpsertLogin(ctx, store.Account{Provider: provider.XAI, Label: "c9-xai-b", Status: "ready", Credentials: store.AccountCredentials{Issuer: "issuer", Subject: "c9-persist-xai-b", AccessToken: "xai-b-token"}})
	if err != nil {
		t.Fatalf("upsert xai B: %v", err)
	}
	xaiA, err := first.accounts.UpsertLogin(ctx, store.Account{Provider: provider.XAI, Label: "c9-xai-a", Status: "ready", Credentials: store.AccountCredentials{Issuer: "issuer", Subject: "c9-persist-xai-a", AccessToken: "xai-a-token"}})
	if err != nil {
		t.Fatalf("upsert xai A: %v", err)
	}
	if _, err := first.database.DB.ExecContext(ctx, `UPDATE accounts SET created_at=?, updated_at=? WHERE id=?`, now.Add(-2*time.Second).Unix(), now.Add(-2*time.Second).Unix(), xaiB.ID); err != nil {
		t.Fatalf("pin xaiB created_at: %v", err)
	}
	if _, err := first.database.DB.ExecContext(ctx, `UPDATE accounts SET created_at=?, updated_at=? WHERE id=?`, now.Add(-1*time.Second).Unix(), now.Add(-1*time.Second).Unix(), xaiA.ID); err != nil {
		t.Fatalf("pin xaiA created_at: %v", err)
	}
	// resolved upstream model "grok-4.5" through the real CooldownRepository so
	// the executor's candidates() excludes B and only A is eligible.
	cooldownUntil := now.Add(30 * 24 * time.Hour)
	if err := first.states.Put(ctx, store.Cooldown{AccountID: xaiB.ID, Model: "grok-4.5", Until: &cooldownUntil, LastErrorClass: "rate_limit", LastErrorAt: ptrTime(now)}); err != nil {
		t.Fatalf("seed B cooldown: %v", err)
	}
	// Seed a Devin account so the wrong-provider skip path is observable.
	devinAccount, err := first.accounts.UpsertLogin(ctx, store.Account{Provider: provider.Devin, Label: "c9-devin", Status: "ready", ExpiresAt: ptrTime(time.Now().Add(time.Hour)), Credentials: store.AccountCredentials{OpaqueToken: "devin-token", OpaqueTokenExpiresAt: ptrTime(time.Now().Add(time.Hour))}})
	if err != nil {
		t.Fatalf("upsert devin account: %v", err)
	}
	// Populate sentinel tokens for each account. The credential ledgers
	// reference this map, so the sentinels are visible to all runtimes
	// without rebuilding. Each sentinel is a unique per-account marker that
	// replaces the real token in the credential returned to the generation
	// layer, proving which account served each request.
	sentinels[xaiA.ID] = "sentinel-xai-a"
	sentinels[xaiB.ID] = "sentinel-xai-b"
	sentinels[devinAccount.ID] = "sentinel-devin"

	// Initial public request through the real ResponsesHandler. No
	// previous_response_id, so PreferredAccountID is empty and the scheduler
	// picks the sole eligible account A. The handler persists the completed
	// response with PreferredAccountID=A via the real sessions.Service.
	initial := c9postResponses(t, c9responsesHandler(first), `{"model":"grok","input":"hello","store":true,"stream":false}`)
	if initial.Code != http.StatusOK {
		t.Fatalf("initial responses status=%d body=%s", initial.Code, initial.Body.String())
	}
	rootID := c9responsesID(t, initial)
	root, err := first.responses.Get(ctx, rootID, time.Now().UTC())
	if err != nil {
		t.Fatalf("persisted root response session: %v", err)
	}
	if root.PreferredAccountID != xaiA.ID {
		t.Fatalf("root preferred account=%q want A=%q", root.PreferredAccountID, xaiA.ID)
	}
	if root.PreviousResponseID != "" {
		t.Fatalf("root node has previous=%q", root.PreviousResponseID)
	}
	if upstream.successCount != 1 {
		t.Fatalf("upstream success count after initial=%d want 1", upstream.successCount)
	}
	// Wire sentinel: the initial request reached the xAI upstream with A's
	// credential sentinel in the Authorization header, proving the exact
	// selected xAI credential was materialized on the wire (not just that
	// Credential() was called).
	if got := upstream.lastBearer(); got != "sentinel-xai-a" {
		t.Fatalf("initial upstream bearer=%q want sentinel-xai-a (exact selected xAI credential on the wire)", got)
	}
	// Close the database and reopen the same path with the same keys and a
	// fresh component graph (fresh scheduler cursor = 0). No in-memory state
	// carries over. Phase-2 clock advances past B's stored cooldown so both
	// xAI accounts are eligible. The continuation runs on this runtime so its
	// fresh scheduler cursor cannot contaminate the baseline control.
	if err := first.database.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	second := c9buildRuntime(t, dataDir, keys, upstream, sentinels)
	defer second.database.Close()
	// Rewrite B's persisted cooldown_until to a past absolute timestamp so B
	// is eligible for the reopened runtime; both xAI accounts are now
	// selectable and the continuation's PreferredAccountID=A overrides the
	// baseline. No production clock seam is involved.
	if _, err := second.database.DB.ExecContext(ctx, `UPDATE account_model_states SET cooldown_until=? WHERE account_id=? AND model=?`, now.Add(-time.Hour).Unix(), xaiB.ID, "grok-4.5"); err != nil {
		t.Fatalf("clear B cooldown after reopen: %v", err)
	}
	// The reopened session service must read the persisted root back from
	// SQLite with PreferredAccountID=A.
	reopenedRoot, err := second.responses.Get(ctx, rootID, time.Now().UTC())
	if err != nil {
		t.Fatalf("reopen root response session: %v", err)
	}
	if reopenedRoot.PreferredAccountID != xaiA.ID {
		t.Fatalf("reopen root preferred account=%q want A=%q", reopenedRoot.PreferredAccountID, xaiA.ID)
	}

	// Snapshot credential-ledger counts before the continuation. The initial
	// request was served by first's ledgers (now closed); second's ledgers
	// start at zero.
	xaiALedgerBefore := second.xaiLedger.callCount(xaiA.ID)
	xaiBLedgerBefore := second.xaiLedger.callCount(xaiB.ID)
	devinLedgerBefore := second.devinLedger.callCount(devinAccount.ID)

	// Continuation through the public handler with previous_response_id. The
	// real sessions.Reconstruct walks the persisted chain, injects
	// PreferredAccountID=A into the routing request, and the reopened executor
	// (fresh scheduler cursor 0) must select A over the baseline-preferred B.
	// This runs before the baseline control so the continuation's scheduler
	// cursor cannot be shifted by a prior baseline request.
	continuationBody := fmt.Sprintf(`{"model":"grok","input":"next","previous_response_id":%q,"store":true,"stream":false}`, rootID)
	continuation := c9postResponses(t, c9responsesHandler(second), continuationBody)
	if continuation.Code != http.StatusOK {
		t.Fatalf("continuation status=%d body=%s", continuation.Code, continuation.Body.String())
	}
	childID := c9responsesID(t, continuation)
	child, err := second.responses.Get(ctx, childID, time.Now().UTC())
	if err != nil {
		t.Fatalf("persisted child response session: %v", err)
	}
	if child.PreferredAccountID != xaiA.ID {
		t.Fatalf("continuation child preferred account=%q want A=%q (affinity must override baseline-preferred B=%q)", child.PreferredAccountID, xaiA.ID, xaiB.ID)
	}
	if child.PreviousResponseID != rootID {
		t.Fatalf("continuation child previous=%q want root=%q", child.PreviousResponseID, rootID)
	}
	// Credential ledger: only A's credentials were materialized for the
	// continuation; B and Devin were not contacted.
	if second.xaiLedger.callCount(xaiA.ID) != xaiALedgerBefore+1 {
		t.Fatalf("xAI A credential calls=%d want %d (continuation must materialize A only)", second.xaiLedger.callCount(xaiA.ID), xaiALedgerBefore+1)
	}
	if second.xaiLedger.callCount(xaiB.ID) != xaiBLedgerBefore {
		t.Fatalf("xAI B credential calls changed by continuation: before=%d after=%d", xaiBLedgerBefore, second.xaiLedger.callCount(xaiB.ID))
	}
	if second.devinLedger.callCount(devinAccount.ID) != devinLedgerBefore {
		t.Fatalf("Devin credential calls changed by xAI continuation: before=%d after=%d", devinLedgerBefore, second.devinLedger.callCount(devinAccount.ID))
	}
	// Wire sentinel: the continuation reached the xAI upstream with A's
	// credential sentinel, proving the persisted affinity selected the same
	// xAI credential on the wire after reopen (not B's).
	if got := upstream.lastBearer(); got != "sentinel-xai-a" {
		t.Fatalf("continuation upstream bearer=%q want sentinel-xai-a (exact selected xAI credential on the wire post-reopen)", got)
	}
	// Usage ledger: A is charged for the continuation, B is untouched by it.
	aAfterCont, err := second.usageService.Counters(ctx, xaiA.ID)
	if err != nil {
		t.Fatalf("counters A after continuation: %v", err)
	}
	bAfterCont, err := second.usageService.Counters(ctx, xaiB.ID)
	if err != nil {
		t.Fatalf("counters B after continuation: %v", err)
	}
	if aAfterCont != (usage.Counters{Requests: 2, Failures: 0, InputTokens: 62, OutputTokens: 94, CacheReadTokens: 24}) {
		t.Fatalf("A counters after continuation=%+v want {Requests:2, Failures:0, InputTokens:62, OutputTokens:94, CacheReadTokens:24} (initial+continuation, terminal token delta accumulated)", aAfterCont)
	}
	if bAfterCont != (usage.Counters{}) {
		t.Fatalf("B counters changed by continuation=%+v want zero (continuation must attribute to A only)", bAfterCont)
	}

	// Close second and open a third runtime for the baseline control. This
	// gives the baseline its own fresh scheduler cursor (0), uncontaminated by
	// the continuation's cursor advance. With B created before A (pinned
	// created_at), the no-affinity baseline must select B.
	if err := second.database.Close(); err != nil {
		t.Fatalf("close second database: %v", err)
	}
	third := c9buildRuntime(t, dataDir, keys, upstream, sentinels)
	defer third.database.Close()

	baseline := c9postResponses(t, c9responsesHandler(third), `{"model":"grok","input":"baseline","store":true,"stream":false}`)
	if baseline.Code != http.StatusOK {
		t.Fatalf("baseline responses status=%d body=%s", baseline.Code, baseline.Body.String())
	}
	baselineID := c9responsesID(t, baseline)
	baselineNode, err := third.responses.Get(ctx, baselineID, time.Now().UTC())
	if err != nil {
		t.Fatalf("baseline response session: %v", err)
	}
	if baselineNode.PreferredAccountID != xaiB.ID {
		t.Fatalf("baseline preferred account=%q want B=%q (proves baseline prefers B absent affinity, fresh cursor 0)", baselineNode.PreferredAccountID, xaiB.ID)
	}
	// Credential ledger: baseline materialized B's credentials, not A's.
	if third.xaiLedger.callCount(xaiB.ID) != 1 {
		t.Fatalf("baseline xAI B credential calls=%d want 1", third.xaiLedger.callCount(xaiB.ID))
	}
	if third.xaiLedger.callCount(xaiA.ID) != 0 {
		t.Fatalf("baseline xAI A credential calls=%d want 0 (baseline must not touch A)", third.xaiLedger.callCount(xaiA.ID))
	}
	// Wire sentinel: the no-affinity baseline reached the xAI upstream with
	// B's credential sentinel, proving the baseline selects B on the wire
	// (the control the continuation overrides).
	if got := upstream.lastBearer(); got != "sentinel-xai-b" {
		t.Fatalf("baseline upstream bearer=%q want sentinel-xai-b (exact selected xAI credential on the wire for baseline)", got)
	}
	// No Devin sentinel ever reached the xAI upstream across all xAI-model
	// requests so far.
	for i, bearer := range upstream.bearers {
		if bearer == "sentinel-devin" {
			t.Fatalf("Devin sentinel reached xAI upstream at request %d (provider isolation violated)", i)
		}
	}

	// The xAI upstream served exactly three successful xAI requests so far
	// (initial, continuation, baseline) and no rate-limited responses.
	if upstream.successCount != 3 {
		t.Fatalf("upstream success count=%d want 3", upstream.successCount)
	}
	if upstream.rateLimited != 0 {
		t.Fatalf("upstream rate-limit counter unexpected=%d", upstream.rateLimited)
	}

	// Cross-provider negative: a continuation whose persisted preferred
	// account is xAI A but whose requested model resolves to Devin must not
	// cross onto xAI. This goes through the public ResponsesHandler with
	// previous_response_id=rootID (the persisted xAI root) and model glm
	// (Devin). sessions.Reconstruct injects PreferredAccountID=A
	// from the root, but the executor's candidates() filters to Devin accounts
	// only, so A is skipped (provider mismatch) and the Devin account is
	// selected. The Devin generation client is called once with the Devin
	// sentinel; the xAI credential ledger and xAI upstream are not contacted.
	xaiUpstreamBeforeCross := upstream.successCount
	xaiALedgerBeforeCross := third.xaiLedger.callCount(xaiA.ID)
	xaiBLedgerBeforeCross := third.xaiLedger.callCount(xaiB.ID)
	devinLedgerBeforeCross := third.devinLedger.callCount(devinAccount.ID)
	devinCallsBeforeCross := len(third.devinGeneration.requests)

	crossBody := fmt.Sprintf(`{"model":"glm","input":"cross-provider followup","previous_response_id":%q,"store":true,"stream":false}`, rootID)
	cross := c9postResponses(t, c9responsesHandler(third), crossBody)
	if cross.Code != http.StatusOK {
		t.Fatalf("cross-provider continuation status=%d body=%s", cross.Code, cross.Body.String())
	}
	crossID := c9responsesID(t, cross)
	crossChild, err := third.responses.Get(ctx, crossID, time.Now().UTC())
	if err != nil {
		t.Fatalf("persisted cross-provider child response session: %v", err)
	}
	if crossChild.PreferredAccountID != devinAccount.ID {
		t.Fatalf("cross-provider child preferred account=%q want Devin=%q (stored xAI affinity must not cross providers)", crossChild.PreferredAccountID, devinAccount.ID)
	}
	if crossChild.PreviousResponseID != rootID {
		t.Fatalf("cross-provider child previous=%q want root=%q", crossChild.PreviousResponseID, rootID)
	}
	if crossChild.Model != "glm-5-2" {
		t.Fatalf("cross-provider child model=%q want glm-5-2", crossChild.Model)
	}
	// Devin generation client called exactly once with the Devin sentinel.
	if len(third.devinGeneration.requests) != devinCallsBeforeCross+1 {
		t.Fatalf("devin generation calls=%d want %d (Devin client must serve the cross-provider continuation)", len(third.devinGeneration.requests), devinCallsBeforeCross+1)
	}
	if got := third.devinGeneration.requests[len(third.devinGeneration.requests)-1].Credential.Value; got != "sentinel-devin" {
		t.Fatalf("cross-provider Devin credential=%q want sentinel-devin", got)
	}
	// xAI credential ledger unchanged: neither A nor B was contacted for the
	// Devin-model continuation.
	if third.xaiLedger.callCount(xaiA.ID) != xaiALedgerBeforeCross {
		t.Fatalf("xAI A credential calls changed by Devin continuation: before=%d after=%d", xaiALedgerBeforeCross, third.xaiLedger.callCount(xaiA.ID))
	}
	if third.xaiLedger.callCount(xaiB.ID) != xaiBLedgerBeforeCross {
		t.Fatalf("xAI B credential calls changed by Devin continuation: before=%d after=%d", xaiBLedgerBeforeCross, third.xaiLedger.callCount(xaiB.ID))
	}
	// Devin credential ledger called exactly once.
	if third.devinLedger.callCount(devinAccount.ID) != devinLedgerBeforeCross+1 {
		t.Fatalf("Devin credential calls=%d want %d", third.devinLedger.callCount(devinAccount.ID), devinLedgerBeforeCross+1)
	}
	// xAI upstream not contacted for the Devin-model continuation.
	if upstream.successCount != xaiUpstreamBeforeCross {
		t.Fatalf("xAI upstream success count changed by Devin continuation: before=%d after=%d (xAI client must not be called for a Devin model)", xaiUpstreamBeforeCross, upstream.successCount)
	}

	// Expired-account affinity failover: the persisted preferred xAI account
	// A becomes unusable through the real oauthxai expiry path
	// (CredentialUsable=false) after reopen, and a handler continuation
	// carrying A as preferred must fail over to the eligible xAI account B
	// without materializing A's credentials or contacting A's client. The
	// production xAI credential manager's CredentialsUsable (refresh.go:35-43)
	// returns false when NeedsRefresh is true (ExpiresAt in the past) and the
	// account has no usable RefreshToken/TokenEndpoint. We re-upsert A with
	// Status="ready", Enabled=true, ExpiresAt in the past, AccessToken present,
	// but no RefreshToken or TokenEndpoint, so CredentialUsable returns
	// false, nil (not an error) and the executor's candidates() filters A as
	// !Valid. The continuation's PreferredAccountID=A is dropped (A is not in
	// the eligible set) and the scheduler selects B.
	expiredAt := time.Now().UTC().Add(-time.Hour)
	if _, err := third.accounts.UpsertLogin(ctx, store.Account{ID: xaiA.ID, Provider: provider.XAI, Label: "c9-xai-a", Status: "ready", ExpiresAt: &expiredAt, Credentials: store.AccountCredentials{Issuer: "issuer", Subject: "c9-persist-xai-a", AccessToken: "xai-a-token"}}); err != nil {
		t.Fatalf("re-upsert xAI A as expired: %v", err)
	}
	// Close and reopen so the fourth runtime reads the expired account state
	// from SQLite, proving the failover survives reopen.
	if err := third.database.Close(); err != nil {
		t.Fatalf("close third database: %v", err)
	}
	fourth := c9buildRuntime(t, dataDir, keys, upstream, sentinels)
	defer fourth.database.Close()

	// Confirm A is now unusable through the real production credential
	// manager's CredentialUsable path: Status="ready" but ExpiresAt in the
	// past with no refresh token/endpoint, so CredentialsUsable returns false.
	aUsable, err := fourth.xaiCreds.CredentialUsable(ctx, xaiA.ID)
	if err != nil {
		t.Fatalf("CredentialUsable A after expiry: %v", err)
	}
	if aUsable {
		t.Fatal("xAI A must be CredentialUsable=false after expiry (ExpiresAt past, no refresh token/endpoint)")
	}
	// B is still usable.
	bUsable, err := fourth.xaiCreds.CredentialUsable(ctx, xaiB.ID)
	if err != nil {
		t.Fatalf("CredentialUsable B: %v", err)
	}
	if !bUsable {
		t.Fatal("xAI B must be CredentialUsable=true")
	}

	// Snapshot all three ledgers immediately before the continuation so
	// earlier root selection / usability checks cannot mask zero-delta
	// assertions.
	xaiACredBefore := fourth.xaiLedger.callCount(xaiA.ID)
	xaiBCredBefore := fourth.xaiLedger.callCount(xaiB.ID)
	xaiAUsableBefore := fourth.xaiLedger.usableCount(xaiA.ID)
	xaiBUsableBefore := fourth.xaiLedger.usableCount(xaiB.ID)
	devinCredBefore := fourth.devinLedger.callCount(devinAccount.ID)
	devinUsableBefore := fourth.devinLedger.usableCount(devinAccount.ID)

	expiredBody := fmt.Sprintf(`{"model":"grok","input":"after-expiry","previous_response_id":%q,"store":true,"stream":false}`, rootID)
	expired := c9postResponses(t, c9responsesHandler(fourth), expiredBody)
	if expired.Code != http.StatusOK {
		t.Fatalf("expired-account continuation status=%d body=%s", expired.Code, expired.Body.String())
	}
	expiredID := c9responsesID(t, expired)
	expiredChild, err := fourth.responses.Get(ctx, expiredID, time.Now().UTC())
	if err != nil {
		t.Fatalf("persisted expired-account child response session: %v", err)
	}
	if expiredChild.PreferredAccountID != xaiB.ID {
		t.Fatalf("expired-account continuation account=%q want B=%q (must fail over from expired A to eligible B)", expiredChild.PreferredAccountID, xaiB.ID)
	}
	if expiredChild.PreviousResponseID != rootID {
		t.Fatalf("expired-account child previous=%q want root=%q", expiredChild.PreviousResponseID, rootID)
	}
	// Credential ledger: B was materialized (delta +1), A was not (delta 0).
	// A's CredentialUsable was inspected (delta +1) but A's Credential was
	// never called — the executor filtered A as !Valid before reaching
	// Credential().
	if fourth.xaiLedger.callCount(xaiB.ID) != xaiBCredBefore+1 {
		t.Fatalf("expired-account continuation xAI B credential calls=%d want %d (delta +1)", fourth.xaiLedger.callCount(xaiB.ID), xaiBCredBefore+1)
	}
	if fourth.xaiLedger.callCount(xaiA.ID) != xaiACredBefore {
		t.Fatalf("expired-account continuation xAI A credential calls=%d want %d (delta 0, expired account must not be materialized)", fourth.xaiLedger.callCount(xaiA.ID), xaiACredBefore)
	}
	if fourth.xaiLedger.usableCount(xaiA.ID) != xaiAUsableBefore+1 {
		t.Fatalf("expired-account continuation xAI A usable calls=%d want %d (delta +1, expiry must be inspected)", fourth.xaiLedger.usableCount(xaiA.ID), xaiAUsableBefore+1)
	}
	if fourth.xaiLedger.usableCount(xaiB.ID) != xaiBUsableBefore+1 {
		t.Fatalf("expired-account continuation xAI B usable calls=%d want %d (delta +1)", fourth.xaiLedger.usableCount(xaiB.ID), xaiBUsableBefore+1)
	}
	// Devin ledger unchanged.
	if fourth.devinLedger.callCount(devinAccount.ID) != devinCredBefore {
		t.Fatalf("Devin credential calls=%d want %d (xAI continuation must not touch Devin)", fourth.devinLedger.callCount(devinAccount.ID), devinCredBefore)
	}
	if fourth.devinLedger.usableCount(devinAccount.ID) != devinUsableBefore {
		t.Fatalf("Devin usable calls=%d want %d (xAI continuation must not touch Devin)", fourth.devinLedger.usableCount(devinAccount.ID), devinUsableBefore)
	}
	// Wire sentinel: the expired-account failover reached the xAI upstream
	// with B's credential sentinel (not A's), proving the expired preferred
	// account's credential never reached the wire and B served the request.
	if got := upstream.lastBearer(); got != "sentinel-xai-b" {
		t.Fatalf("expired-account upstream bearer=%q want sentinel-xai-b (expired A's credential must not reach the wire)", got)
	}
}

// TestC9Persistence_RetryAfterCooldownPersistsAcrossReopen asserts C9.4: a 429
// with a raw Retry-After header traverses the real xAI adapter (parseRetryAfter
// → classifyUpstream → ExplicitRetryAfter), through the Executor's
// applyFailure into the real CooldownManager and SQLite account_model_states.
// After closing and reopening the database, a fresh executor skips the cooled
// account before the deadline and selects it again once the persisted
// cooldown_until is rewritten to a past absolute timestamp. Direct repo
// Put/Get alone does not count: the 429
// classification is produced by the real xai.ProviderClient from an HTTP 429
// response with the Retry-After header.
func TestC9Persistence_RetryAfterCooldownPersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	keys := c9persistenceKeys(t)

	// A single shared upstream accumulates Authorization bearers across both
	// runtimes so the exact selected xAI credential can be asserted on the
	// wire pre and post reopen. The first request is rate-limited (429 +
	// Retry-After: 3600) so the cooldown is classified by the real xAI
	// adapter; subsequent requests succeed. The large Retry-After window
	// keeps the stored Until far in the future at real now, so the
	// before-deadline skip holds deterministically without any sleep or
	// seconds-scale boundary; the after-deadline recovery rewrites the
	// persisted cooldown_until to a past absolute timestamp via a direct DB
	// update. No production clock seam is involved.
	upstream := &c9xAIUpstream{rateLimited: 1, retryAfter: "3600"}
	sentinels := make(map[string]string)

	first := c9buildRuntime(t, dataDir, keys, upstream, sentinels)

	xaiPrimary, err := first.accounts.UpsertLogin(ctx, store.Account{Provider: provider.XAI, Label: "c9-cooldown-primary", Status: "ready", Credentials: store.AccountCredentials{Issuer: "issuer", Subject: "c9-cooldown-a", AccessToken: "xai-a"}})
	if err != nil {
		t.Fatalf("upsert primary: %v", err)
	}
	// Seed a mixed-pool Devin account so the cooldown test asserts provider
	// isolation: the xAI cooldown never touches the Devin account, and the
	// Devin credential/client ledger stays at zero across every xAI dispatch.
	devinExpiry := time.Now().UTC().Add(time.Hour)
	devinAccount, err := first.accounts.UpsertLogin(ctx, store.Account{Provider: provider.Devin, Label: "c9-cooldown-devin", Status: "ready", ExpiresAt: &devinExpiry, Credentials: store.AccountCredentials{OpaqueToken: "devin-token", OpaqueTokenExpiresAt: &devinExpiry}})
	if err != nil {
		t.Fatalf("upsert devin account: %v", err)
	}
	sentinels[xaiPrimary.ID] = "sentinel-cooldown-a"
	sentinels[devinAccount.ID] = "sentinel-cooldown-devin"
	// Only the primary exists during phase 1 so the 429 cannot fail over to a
	// second account: Execute must return the classified ExecutionError, not
	// a success via the secondary. The secondary is added after reopen to
	// prove the cooled primary is skipped in favor of an eligible alternative.

	// Snapshot the Devin ledger before the 429 dispatch; it must not move.
	devinCredBefore := first.devinLedger.callCount(devinAccount.ID)
	devinUsableBefore := first.devinLedger.usableCount(devinAccount.ID)
	devinCallsBefore := len(first.devinGeneration.requests)

	// Execute against the primary. The upstream returns 429 with Retry-After:
	// 3600, which the real xai.ProviderClient.adaptError → classifyUpstream →
	// parseRetryAfter turns into ExplicitRetryAfter + Cooldown=3600s. The
	// executor's applyFailure persists it via the real CooldownManager.
	bearersBefore429 := len(upstream.bearers)
	_, execErr := first.executor.Execute(ctx, routing.Request{Model: "grok", Body: []byte(`{"model":"grok","input":"x"}`), PreferredAccountID: xaiPrimary.ID})
	if execErr == nil {
		t.Fatal("expected 429 execution error, got nil")
	}
	var executionErr *routing.ExecutionError
	if !errors.As(execErr, &executionErr) {
		t.Fatalf("expected routing.ExecutionError, got %T: %v", execErr, execErr)
	}
	if executionErr.Classified.Class != provider.ClassRateLimit || !executionErr.Classified.ExplicitRetryAfter {
		t.Fatalf("classification=%+v want rate_limit+ExplicitRetryAfter", executionErr.Classified)
	}
	// applyFailure recomputes Cooldown = storedUntil.Sub(time.Now()) after
	// persistence, so the returned duration is slightly under 3600s at real
	// now. Assert a safe bound; the persisted Until == LastErrorAt+3600s is
	// the exact deterministic contract checked below.
	if executionErr.Classified.Cooldown <= 3590*time.Second || executionErr.Classified.Cooldown > 3600*time.Second {
		t.Fatalf("cooldown=%v want within (3590s, 3600s]", executionErr.Classified.Cooldown)
	}
	// The 429 request reached the xAI upstream with the primary's credential
	// sentinel on the wire (the credential was materialized before the
	// request; the 429 is the upstream's response, not a pre-wire skip).
	if len(upstream.bearers) != bearersBefore429+1 {
		t.Fatalf("upstream bearers after 429=%d want %d (429 request must reach the wire)", len(upstream.bearers), bearersBefore429+1)
	}
	if got := upstream.bearers[len(upstream.bearers)-1]; got != "sentinel-cooldown-a" {
		t.Fatalf("429 upstream bearer=%q want sentinel-cooldown-a (exact selected xAI credential on the wire)", got)
	}
	// Provider isolation: the 429 dispatch touched no Devin credential or
	// client. The Devin ledger is unchanged.
	if first.devinLedger.callCount(devinAccount.ID) != devinCredBefore {
		t.Fatalf("Devin credential calls changed by xAI 429: before=%d after=%d", devinCredBefore, first.devinLedger.callCount(devinAccount.ID))
	}
	if first.devinLedger.usableCount(devinAccount.ID) != devinUsableBefore {
		t.Fatalf("Devin usable calls changed by xAI 429: before=%d after=%d", devinUsableBefore, first.devinLedger.usableCount(devinAccount.ID))
	}
	if len(first.devinGeneration.requests) != devinCallsBefore {
		t.Fatalf("Devin generation calls changed by xAI 429: before=%d after=%d", devinCallsBefore, len(first.devinGeneration.requests))
	}

	// The cooldown row must be persisted in SQLite for the primary account on
	// the resolved upstream model "grok-4.5" (provider-local: the Devin
	// account has no cooldown row).
	state, err := first.states.Get(ctx, xaiPrimary.ID, "grok-4.5", time.Now().UTC())
	if err != nil {
		t.Fatalf("get cooldown: %v", err)
	}
	if state.Until == nil {
		t.Fatalf("cooldown not persisted: %+v", state)
	}
	// The stored Until is an absolute instant ~3600s in the future; assert
	// it is exactly 3600s after the persisted LastErrorAt (deterministic
	// without a mutable clock) and capture it for the reopen comparison.
	wantUntil := state.Until
	if state.LastErrorAt == nil || !state.Until.Equal(state.LastErrorAt.Add(3600*time.Second)) {
		t.Fatalf("persisted until=%v want=LastErrorAt+3600s (%v)", *state.Until, state.LastErrorAt)
	}
	// Provider-local cooldown: the Devin account has no cooldown row for any
	// model. A Get returns no-rows (sql.ErrNoRows-shaped) with a nil Until.
	devinState, err := first.states.Get(ctx, devinAccount.ID, "grok-4.5", time.Now().UTC())
	if err == nil && devinState.Until != nil {
		t.Fatalf("Devin account unexpectedly has xAI-model cooldown: %+v", devinState)
	}

	// Close and reopen the database with a fresh component graph; the
	// persisted absolute cooldown deadline survives reopen against real wall
	// clock.
	if err := first.database.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	second := c9buildRuntime(t, dataDir, keys, upstream, sentinels)
	defer second.database.Close()

	reopenedState, err := second.states.Get(ctx, xaiPrimary.ID, "grok-4.5", time.Now().UTC())
	if err != nil {
		t.Fatalf("reopen cooldown get: %v", err)
	}
	if reopenedState.Until == nil || wantUntil == nil || !reopenedState.Until.Equal(*wantUntil) {
		t.Fatalf("reopened cooldown until=%v want=%v", reopenedState.Until, wantUntil)
	}
	// Provider-local cooldown survives reopen: the Devin account still has no
	reopenedDevinState, err := second.states.Get(ctx, devinAccount.ID, "grok-4.5", time.Now().UTC())
	if err == nil && reopenedDevinState.Until != nil {
		t.Fatalf("Devin account unexpectedly has xAI-model cooldown after reopen: %+v", reopenedDevinState)
	}

	// Add the secondary xAI account after reopen. It is persisted in the same
	// SQLite data directory, so the reopened executor can select it when the
	// cooled primary is skipped.
	xaiSecondary, err := second.accounts.UpsertLogin(ctx, store.Account{Provider: provider.XAI, Label: "c9-cooldown-secondary", Status: "ready", Credentials: store.AccountCredentials{Issuer: "issuer", Subject: "c9-cooldown-b", AccessToken: "xai-b"}})
	if err != nil {
		t.Fatalf("upsert secondary after reopen: %v", err)
	}
	sentinels[xaiSecondary.ID] = "sentinel-cooldown-b"

	// Snapshot the reopened Devin ledger; it must not move across either
	// post-reopen dispatch.
	devinCredBeforeReopen := second.devinLedger.callCount(devinAccount.ID)
	devinUsableBeforeReopen := second.devinLedger.usableCount(devinAccount.ID)
	devinCallsBeforeReopen := len(second.devinGeneration.requests)

	// Before the deadline, the reopened executor must skip the cooled primary
	// and select the secondary. This proves the cooldown is enforced by the
	// reopened routing path, not just present in the table.
	bearersBeforeSkip := len(upstream.bearers)
	beforeResult, err := second.executor.Execute(ctx, routing.Request{Model: "grok", Body: []byte(`{"model":"grok","input":"before"}`), PreferredAccountID: xaiPrimary.ID})
	if err != nil {
		t.Fatalf("before-deadline execute: %v", err)
	}
	if beforeResult.AccountID != xaiSecondary.ID {
		t.Fatalf("before-deadline account=%q want secondary=%q (primary %q should be cooling)", beforeResult.AccountID, xaiSecondary.ID, xaiPrimary.ID)
	}
	// Wire sentinel post-reopen: the skip dispatched with the secondary's
	// credential sentinel, not the cooled primary's.
	if len(upstream.bearers) != bearersBeforeSkip+1 {
		t.Fatalf("upstream bearers after skip=%d want %d", len(upstream.bearers), bearersBeforeSkip+1)
	}
	if got := upstream.bearers[len(upstream.bearers)-1]; got != "sentinel-cooldown-b" {
		t.Fatalf("before-deadline upstream bearer=%q want sentinel-cooldown-b (exact selected xAI credential on the wire post-reopen)", got)
	}
	// Provider isolation post-reopen: no Devin credential/client touched.
	if second.devinLedger.callCount(devinAccount.ID) != devinCredBeforeReopen {
		t.Fatalf("Devin credential calls changed by before-deadline dispatch: before=%d after=%d", devinCredBeforeReopen, second.devinLedger.callCount(devinAccount.ID))
	}
	if second.devinLedger.usableCount(devinAccount.ID) != devinUsableBeforeReopen {
		t.Fatalf("Devin usable calls changed by before-deadline dispatch: before=%d after=%d", devinUsableBeforeReopen, second.devinLedger.usableCount(devinAccount.ID))
	}
	if len(second.devinGeneration.requests) != devinCallsBeforeReopen {
		t.Fatalf("Devin generation calls changed by before-deadline dispatch: before=%d after=%d", devinCallsBeforeReopen, len(second.devinGeneration.requests))
	}

	// After the deadline, the primary must be eligible again. Rewrite the
	// persisted cooldown_until to a past absolute timestamp via a direct DB
	// update so the primary is eligible at real now, then execute preferring
	// the primary.
	if _, err := second.database.DB.ExecContext(ctx, `UPDATE account_model_states SET cooldown_until=? WHERE account_id=? AND model=?`, time.Now().UTC().Add(-time.Hour).Unix(), xaiPrimary.ID, "grok-4.5"); err != nil {
		t.Fatalf("force primary cooldown expiry: %v", err)
	}
	bearersBeforeRecover := len(upstream.bearers)
	afterResult, err := second.executor.Execute(ctx, routing.Request{Model: "grok", Body: []byte(`{"model":"grok","input":"after"}`), PreferredAccountID: xaiPrimary.ID})
	if err != nil {
		t.Fatalf("after-deadline execute: %v", err)
	}
	if afterResult.AccountID != xaiPrimary.ID {
		t.Fatalf("after-deadline account=%q want primary=%q", afterResult.AccountID, xaiPrimary.ID)
	}
	// Wire sentinel: the recovered primary dispatched with its own credential
	// sentinel, proving the cooldown expiry restored the exact xAI
	// credential on the wire.
	if len(upstream.bearers) != bearersBeforeRecover+1 {
		t.Fatalf("upstream bearers after recover=%d want %d", len(upstream.bearers), bearersBeforeRecover+1)
	}
	if got := upstream.bearers[len(upstream.bearers)-1]; got != "sentinel-cooldown-a" {
		t.Fatalf("after-deadline upstream bearer=%q want sentinel-cooldown-a (exact selected xAI credential on the wire after cooldown expiry)", got)
	}
	// Provider isolation holds across the recovered dispatch.
	if second.devinLedger.callCount(devinAccount.ID) != devinCredBeforeReopen {
		t.Fatalf("Devin credential calls changed by after-deadline dispatch: before=%d after=%d", devinCredBeforeReopen, second.devinLedger.callCount(devinAccount.ID))
	}
	if len(second.devinGeneration.requests) != devinCallsBeforeReopen {
		t.Fatalf("Devin generation calls changed by after-deadline dispatch: before=%d after=%d", devinCallsBeforeReopen, len(second.devinGeneration.requests))
	}
	// No Devin sentinel ever reached the xAI upstream across the whole test.
	for i, bearer := range upstream.bearers {
		if bearer == "sentinel-cooldown-devin" {
			t.Fatalf("Devin sentinel reached xAI upstream at request %d (provider isolation violated)", i)
		}
	}
}

// TestC9Persistence_TerminalUsagePersistedOnceAcrossReopen asserts C9.4: a
// terminal response.completed event flows through the real executor into the
// real usage.Service and LocalUsageRepository, attributing exactly one request
// with the terminal token delta to the selected xAI account. After closing and
// reopening the database, the persisted local_usage_counters row is read back
// through the real usage.Service and matches exactly; every other account has
// zero counters. A second terminal dispatch after reopen increments the same
// selected account's counters by exactly one more request (no replay).
func TestC9Persistence_TerminalUsagePersistedOnceAcrossReopen(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	keys := c9persistenceKeys(t)
	// A single shared upstream accumulates Authorization bearers across both
	// runtimes so the exact selected xAI credential can be asserted on the
	// wire pre and post reopen.
	upstream := &c9xAIUpstream{}
	sentinels := make(map[string]string)

	first := c9buildRuntime(t, dataDir, keys, upstream, sentinels)

	selected, err := first.accounts.UpsertLogin(ctx, store.Account{Provider: provider.XAI, Label: "c9-usage-selected", Status: "ready", Credentials: store.AccountCredentials{Issuer: "issuer", Subject: "c9-usage-selected", AccessToken: "xai-selected"}})
	if err != nil {
		t.Fatalf("upsert selected: %v", err)
	}
	other, err := first.accounts.UpsertLogin(ctx, store.Account{Provider: provider.XAI, Label: "c9-usage-other", Status: "ready", Credentials: store.AccountCredentials{Issuer: "issuer", Subject: "c9-usage-other", AccessToken: "xai-other"}})
	if err != nil {
		t.Fatalf("upsert other: %v", err)
	}
	// Seed a mixed-pool Devin account so the usage test asserts provider
	// isolation: the xAI terminal usage never touches the Devin account's
	// counters, and the Devin credential/client ledger stays at zero across
	// every xAI dispatch.
	devinExpiry := time.Now().UTC().Add(time.Hour)
	devinAccount, err := first.accounts.UpsertLogin(ctx, store.Account{Provider: provider.Devin, Label: "c9-usage-devin", Status: "ready", ExpiresAt: &devinExpiry, Credentials: store.AccountCredentials{OpaqueToken: "devin-token", OpaqueTokenExpiresAt: &devinExpiry}})
	if err != nil {
		t.Fatalf("upsert devin account: %v", err)
	}
	sentinels[selected.ID] = "sentinel-usage-selected"
	sentinels[other.ID] = "sentinel-usage-other"
	sentinels[devinAccount.ID] = "sentinel-usage-devin"

	// Snapshot the Devin ledger before the first dispatch; it must not move.
	devinCredBefore := first.devinLedger.callCount(devinAccount.ID)
	devinUsableBefore := first.devinLedger.usableCount(devinAccount.ID)
	devinCallsBefore := len(first.devinGeneration.requests)

	// Drive the terminal event through the real executor (not a direct
	// LocalUsageRepository.Add). completedUsage reads response.usage from the
	// terminal event and the executor records it exactly once.
	bearersBeforeFirst := len(upstream.bearers)
	result, err := first.executor.Execute(ctx, routing.Request{Model: "grok", Body: []byte(`{"model":"grok","input":"usage"}`), PreferredAccountID: selected.ID})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.AccountID != selected.ID {
		t.Fatalf("selected account=%q want=%q", result.AccountID, selected.ID)
	}
	// Wire sentinel: the first terminal dispatch reached the xAI upstream
	// with the selected account's credential sentinel on the wire.
	if len(upstream.bearers) != bearersBeforeFirst+1 {
		t.Fatalf("upstream bearers after first=%d want %d", len(upstream.bearers), bearersBeforeFirst+1)
	}
	if got := upstream.bearers[len(upstream.bearers)-1]; got != "sentinel-usage-selected" {
		t.Fatalf("first dispatch upstream bearer=%q want sentinel-usage-selected (exact selected xAI credential on the wire)", got)
	}

	// Read back through the real usage.Service (which reads the real
	// LocalUsageRepository). Exactly one request, terminal token delta, for
	// the selected account.
	counters, err := first.usageService.Counters(ctx, selected.ID)
	if err != nil {
		t.Fatalf("counters selected: %v", err)
	}
	if counters != (usage.Counters{Requests: 1, Failures: 0, InputTokens: 31, OutputTokens: 47, CacheReadTokens: 12}) {
		t.Fatalf("selected counters=%+v want {Requests:1, Failures:0, InputTokens:31, OutputTokens:47, CacheReadTokens:12} (exactly one terminal dispatch with terminal token delta)", counters)
	}
	otherCounters, err := first.usageService.Counters(ctx, other.ID)
	if err != nil {
		t.Fatalf("counters other: %v", err)
	}
	if otherCounters != (usage.Counters{}) {
		t.Fatalf("other counters=%+v want zero", otherCounters)
	}
	// Provider-local counters: the Devin account has zero counters (no xAI
	// request was attributed to it).
	devinCounters, err := first.usageService.Counters(ctx, devinAccount.ID)
	if err != nil {
		t.Fatalf("counters devin: %v", err)
	}
	if devinCounters != (usage.Counters{}) {
		t.Fatalf("Devin counters=%+v want zero (provider-local counters: xAI usage must not attribute to Devin)", devinCounters)
	}
	// Provider isolation: the xAI dispatch touched no Devin credential or
	// client.
	if first.devinLedger.callCount(devinAccount.ID) != devinCredBefore {
		t.Fatalf("Devin credential calls changed by xAI dispatch: before=%d after=%d", devinCredBefore, first.devinLedger.callCount(devinAccount.ID))
	}
	if first.devinLedger.usableCount(devinAccount.ID) != devinUsableBefore {
		t.Fatalf("Devin usable calls changed by xAI dispatch: before=%d after=%d", devinUsableBefore, first.devinLedger.usableCount(devinAccount.ID))
	}
	if len(first.devinGeneration.requests) != devinCallsBefore {
		t.Fatalf("Devin generation calls changed by xAI dispatch: before=%d after=%d", devinCallsBefore, len(first.devinGeneration.requests))
	}

	// Close and reopen the database. The persisted counters must survive
	// reopen and be read back through the real usage.Service.
	if err := first.database.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	second := c9buildRuntime(t, dataDir, keys, upstream, sentinels)
	defer second.database.Close()

	reopenedSelected, err := second.usageService.Counters(ctx, selected.ID)
	if err != nil {
		t.Fatalf("reopen counters selected: %v", err)
	}
	if reopenedSelected != (usage.Counters{Requests: 1, Failures: 0, InputTokens: 31, OutputTokens: 47, CacheReadTokens: 12}) {
		t.Fatalf("reopen selected counters=%+v want {Requests:1, Failures:0, InputTokens:31, OutputTokens:47, CacheReadTokens:12} (persisted counters survive reopen)", reopenedSelected)
	}
	reopenedOther, err := second.usageService.Counters(ctx, other.ID)
	if err != nil {
		t.Fatalf("reopen counters other: %v", err)
	}
	if reopenedOther != (usage.Counters{}) {
		t.Fatalf("reopen other counters=%+v want zero", reopenedOther)
	}
	// Provider-local counters survive reopen: the Devin account still has
	// zero counters after reopen.
	reopenedDevinCounters, err := second.usageService.Counters(ctx, devinAccount.ID)
	if err != nil {
		t.Fatalf("reopen counters devin: %v", err)
	}
	if reopenedDevinCounters != (usage.Counters{}) {
		t.Fatalf("reopen Devin counters=%+v want zero (provider-local counters survive reopen)", reopenedDevinCounters)
	}

	// Snapshot the reopened Devin ledger; it must not move across the second
	// dispatch.
	devinCredBeforeReopen := second.devinLedger.callCount(devinAccount.ID)
	devinUsableBeforeReopen := second.devinLedger.usableCount(devinAccount.ID)
	devinCallsBeforeReopen := len(second.devinGeneration.requests)

	// A second terminal dispatch after reopen must increment the selected
	// account's counters by exactly one more request with the same terminal
	// delta (no replay, no double-count). This proves pre/post-commit no
	// replay remains across reopen.
	bearersBeforeSecond := len(upstream.bearers)
	secondResult, err := second.executor.Execute(ctx, routing.Request{Model: "grok", Body: []byte(`{"model":"grok","input":"again"}`), PreferredAccountID: selected.ID})
	if err != nil {
		t.Fatalf("second execute: %v", err)
	}
	if secondResult.AccountID != selected.ID {
		t.Fatalf("second selected account=%q want=%q", secondResult.AccountID, selected.ID)
	}
	// Wire sentinel post-reopen: the second dispatch reached the xAI
	// upstream with the same selected account's credential sentinel,
	// proving the exact xAI credential is stable across reopen.
	if len(upstream.bearers) != bearersBeforeSecond+1 {
		t.Fatalf("upstream bearers after second=%d want %d", len(upstream.bearers), bearersBeforeSecond+1)
	}
	if got := upstream.bearers[len(upstream.bearers)-1]; got != "sentinel-usage-selected" {
		t.Fatalf("second dispatch upstream bearer=%q want sentinel-usage-selected (exact selected xAI credential on the wire post-reopen)", got)
	}
	afterSecond, err := second.usageService.Counters(ctx, selected.ID)
	if err != nil {
		t.Fatalf("after-second counters: %v", err)
	}
	if afterSecond != (usage.Counters{Requests: 2, Failures: 0, InputTokens: 62, OutputTokens: 94, CacheReadTokens: 24}) {
		t.Fatalf("after-second counters=%+v want {Requests:2, Failures:0, InputTokens:62, OutputTokens:94, CacheReadTokens:24} (exactly one more terminal dispatch, no replay/double-count)", afterSecond)
	}
	// Provider-local counters: the Devin account still has zero counters
	// after the second xAI dispatch.
	afterSecondDevin, err := second.usageService.Counters(ctx, devinAccount.ID)
	if err != nil {
		t.Fatalf("after-second counters devin: %v", err)
	}
	if afterSecondDevin != (usage.Counters{}) {
		t.Fatalf("after-second Devin counters=%+v want zero (provider-local counters: second xAI dispatch must not attribute to Devin)", afterSecondDevin)
	}
	// Provider isolation post-reopen: no Devin credential/client touched.
	if second.devinLedger.callCount(devinAccount.ID) != devinCredBeforeReopen {
		t.Fatalf("Devin credential calls changed by second dispatch: before=%d after=%d", devinCredBeforeReopen, second.devinLedger.callCount(devinAccount.ID))
	}
	if second.devinLedger.usableCount(devinAccount.ID) != devinUsableBeforeReopen {
		t.Fatalf("Devin usable calls changed by second dispatch: before=%d after=%d", devinUsableBeforeReopen, second.devinLedger.usableCount(devinAccount.ID))
	}
	if len(second.devinGeneration.requests) != devinCallsBeforeReopen {
		t.Fatalf("Devin generation calls changed by second dispatch: before=%d after=%d", devinCallsBeforeReopen, len(second.devinGeneration.requests))
	}
	// No Devin sentinel ever reached the xAI upstream across the whole test.
	for i, bearer := range upstream.bearers {
		if bearer == "sentinel-usage-devin" {
			t.Fatalf("Devin sentinel reached xAI upstream at request %d (provider isolation violated)", i)
		}
	}
}

// ptrTime returns a pointer to the supplied time.
func ptrTime(t time.Time) *time.Time { return &t }
