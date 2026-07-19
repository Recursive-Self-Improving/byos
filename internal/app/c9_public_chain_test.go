package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"byos/internal/api"
	apianthropic "byos/internal/api/anthropic"
	apiopenai "byos/internal/api/openai"
	"byos/internal/config"
	appcrypto "byos/internal/crypto"
	"byos/internal/devin"
	"byos/internal/models"
	oauthdevin "byos/internal/oauth/devin"
	oauthxai "byos/internal/oauth/xai"
	"byos/internal/provider"
	"byos/internal/routing"
	"byos/internal/sessions"
	"byos/internal/store"
	"byos/internal/translate"
	"byos/internal/translate/registry"
	"byos/internal/xai"
)

// c9_public_chain_test.go is the app-level E2E composition evidence for the
// public request chain. It assembles the REAL production component graph
// exactly as internal/app.New assembles it — real translators, the real
// routing.Executor, the production static catalog (models.NewStaticCatalog)
// and StaticCatalogOverlay (models.NewStaticCatalogOverlay), the real
// xai.RequestPolicy / devin.RequestPolicy, the real OAuth credential
// managers (wrapped in observable counters), and the real public handlers —
// and drives the full public-handler request → translator → static resolve →
// runtime lookup → policy.Prepare → upstream overwrite → provider filter →
// credential isolation → generation dispatch → response translation path.
//
// The ONLY non-production substitution is the provider-wire transport: the
// real xai.ProviderClient and devin.ProviderClient are replaced by recording
// provider.GenerationClient implementations (c9xaiRecordingClient /
// c9devinRecordingClient) registered directly into
// provider.NewCapabilityRegistry. These recording clients capture the
// provider.GenerationRequest the executor dispatches (post-policy canonical,
// post-upstream-overwrite model, isolated credential) and emit protocol-neutral
// provider.Event sequences the real translators consume. This keeps the test
// off every unsafe production seam: no exported Dialer, no ObserveChatRequest,
// no ObserveWireJSON, no SetResponseIDGenerator, no real Devin TLS routing,
// no httptest TLS/cert machinery.
//
// This file deliberately does NOT assert wire serialization. The recording
// clients sit at the provider.GenerationClient interface boundary, one layer
// above the real wire serializers. Exactly-once real wire serialization
// (xAI JSON body encoding, Devin gzip-framed protobuf Connect request
// encoding, Connect frame writeFrame) is proven at the private provider-package
// boundary in internal/xai and internal/devin tests:
//   - internal/xai provider_test.go / transport_test.go prove the xAI
//     ProviderClient is the sole JSON wire encoder and emits exactly one
//     response.created + response.completed event pair per Execute/Stream.
//   - internal/devin chat_builder_test.go (TestBuildChatRequestToolChoices-
//     AcrossTranslatorShapes) proves the canonical→protobuf ToolChoice mapping
//     (none→OptionName="none", auto→OptionName="auto",
//     selected→ToolName="lookup") and that no x_search tool is injected.
//   - internal/devin stream_client_test.go / stream_mapper_test.go prove the
//     Devin connectStream readFrame/writeFrame is the sole Connect encoder and
//     that the gzip flag, big-endian length, and decompressed payload are
//     byte-for-byte the Marshal output.
// This file composes above those proven boundaries.

// c9publicRuntime bundles the real production component graph assembled exactly
// as internal/app.New assembles it, with the sole substitution of recording
// provider.GenerationClient implementations for the provider-wire transport.
type c9publicRuntime struct {
	database       *store.SQLite
	keys           appcrypto.Keys
	accounts       *store.AccountRepository
	capabilities   *store.ModelCapabilityRepository
	cooldowns      *store.CooldownRepository
	responses      *store.ResponseRepository
	registry       *provider.RuntimeCapabilityRegistry
	catalog        provider.ModelCatalog
	executor       *routing.Executor
	sessionService *sessions.Service

	xaiClient   *c9xaiRecordingClient
	devinClient *c9devinRecordingClient
	xaiCreds    *c9countingXaiCreds
	devinCreds  *c9countingDevinCreds
	xaiAccount  store.Account
	devinAccount store.Account
}

// c9xaiRecordingClient is the deterministic xAI provider endpoint. It records
// exactly one Execute/Stream call per row (the provider.GenerationRequest the
// executor dispatched, with the post-policy canonical, post-overwrite model,
// and isolated credential) and emits the protocol-neutral provider.Event
// sequence the real xai.ProviderClient emits: one response.created followed by
// one response.completed, carrying the resolved upstream model and a fixed
// text. It is registered directly as Capabilities.Generation, so the executor
// dispatches to it through the real policy and credential isolation path with
// no wire transport involved. Wire serialization is proven in internal/xai.
type c9xaiRecordingClient struct {
	text     string
	prefix   string
	idSeq    int64
	executes []c9generationCall
	streams  []c9generationCall
}

type c9generationCall struct {
	request provider.GenerationRequest
}

func (c *c9xaiRecordingClient) Execute(_ context.Context, request provider.GenerationRequest) ([]provider.Event, error) {
	c.executes = append(c.executes, c9generationCall{request: c9cloneRequest(request)})
	return c.events(request), nil
}

func (c *c9xaiRecordingClient) Stream(_ context.Context, request provider.GenerationRequest) (provider.Stream, error) {
	c.streams = append(c.streams, c9generationCall{request: c9cloneRequest(request)})
	return &c9eventStream{events: c.events(request)}, nil
}

// events builds the protocol-neutral event sequence the real xai.ProviderClient
// emits per generation: response.created then response.completed, both carrying
// the resolved upstream model from the dispatched request. idSeq is monotonic
// across the whole runtime and is not reset by reset(), so persisted response
// IDs stay unique across rows.
func (c *c9xaiRecordingClient) events(request provider.GenerationRequest) []provider.Event {
	c.idSeq++
	id := fmt.Sprintf("%s_%d", c.prefix, c.idSeq)
	actualModel := request.Model.UpstreamName
	if actualModel == "" {
		if m, _ := request.Canonical["model"].(string); m != "" {
			actualModel = m
		}
	}
	created, _ := json.Marshal(map[string]any{
		"type": "response.created", "response": map[string]any{
			"id": id, "object": "response", "status": "in_progress", "model": actualModel,
		},
	})
	completed, _ := json.Marshal(map[string]any{
		"type": "response.completed", "response": map[string]any{
			"id": id, "object": "response", "status": "completed", "model": actualModel,
			"usage": map[string]any{"input_tokens": 11, "output_tokens": 13},
			"output": []any{map[string]any{
				"type": "message", "role": "assistant",
				"content": []any{map[string]any{"type": "output_text", "text": c.text}},
			}},
		},
	})
	return []provider.Event{
		{Event: "response.created", Data: created},
		{Event: "response.completed", Data: completed},
	}
}

func (c *c9xaiRecordingClient) reset() {
	c.executes = nil
	c.streams = nil
}

// c9devinRecordingClient is the deterministic Devin provider endpoint, the
// Devin analogue of c9xaiRecordingClient. It emits the same protocol-neutral
// event sequence the real devin.ProviderClient emits (via the Devin
// StreamMapper): response.created then response.completed with the resolved
// upstream model and usage. The canonical→protobuf ToolChoice mapping and
// gzip-framed Connect wire encoding are proven in internal/devin; this client
// sits above that boundary and asserts only the app-level dispatch contract.
type c9devinRecordingClient struct {
	text     string
	prefix   string
	idSeq    int64
	executes []c9generationCall
	streams  []c9generationCall
}

func (c *c9devinRecordingClient) Execute(_ context.Context, request provider.GenerationRequest) ([]provider.Event, error) {
	c.executes = append(c.executes, c9generationCall{request: c9cloneRequest(request)})
	return c.events(request), nil
}

func (c *c9devinRecordingClient) Stream(_ context.Context, request provider.GenerationRequest) (provider.Stream, error) {
	c.streams = append(c.streams, c9generationCall{request: c9cloneRequest(request)})
	return &c9eventStream{events: c.events(request)}, nil
}

func (c *c9devinRecordingClient) events(request provider.GenerationRequest) []provider.Event {
	c.idSeq++
	id := fmt.Sprintf("%s_%d", c.prefix, c.idSeq)
	actualModel := request.Model.UpstreamName
	if actualModel == "" {
		if m, _ := request.Canonical["model"].(string); m != "" {
			actualModel = m
		}
	}
	created, _ := json.Marshal(map[string]any{
		"type": "response.created", "response": map[string]any{
			"id": id, "object": "response", "status": "in_progress", "model": actualModel,
		},
	})
	completed, _ := json.Marshal(map[string]any{
		"type": "response.completed", "response": map[string]any{
			"id": id, "object": "response", "status": "completed", "model": actualModel,
			"usage": map[string]any{"input_tokens": 7, "output_tokens": 3, "total_tokens": 10, "cache_read_tokens": 2},
			"output": []any{map[string]any{
				"type": "message", "role": "assistant",
				"content": []any{map[string]any{"type": "output_text", "text": c.text}},
			}},
		},
	})
	return []provider.Event{
		{Event: "response.created", Data: created},
		{Event: "response.completed", Data: completed},
	}
}

func (c *c9devinRecordingClient) reset() {
	c.executes = nil
	c.streams = nil
}

// c9eventStream is a deterministic provider.Stream that replays a fixed event
// slice and then returns io.EOF. It is the recording-client stream returned by
// Stream; the executor wraps it in routing.RoutedStream.
type c9eventStream struct {
	events []provider.Event
	index  int
	closed bool
}

func (s *c9eventStream) Next(_ context.Context) (provider.Event, error) {
	if s.index >= len(s.events) {
		return provider.Event{}, io.EOF
	}
	event := s.events[s.index]
	s.index++
	return event, nil
}

func (s *c9eventStream) Close() error {
	s.closed = true
	return nil
}

// c9cloneRequest copies a provider.GenerationRequest so the recording client
// retains a stable snapshot of the canonical request the executor dispatched,
// independent of any later mutation. The canonical map is shallow-copied;
// nested values are not mutated after dispatch in this composition.
func c9cloneRequest(request provider.GenerationRequest) provider.GenerationRequest {
	cloned := provider.GenerationRequest{Model: request.Model, Credential: request.Credential}
	if request.Canonical != nil {
		cloned.Canonical = make(provider.CanonicalRequest, len(request.Canonical))
		for key, value := range request.Canonical {
			cloned.Canonical[key] = value
		}
	}
	return cloned
}

// c9countingXaiCreds wraps the real xAI ProviderCredentialManager with atomic
// counters for every method the executor may call (Credential,
// AuthenticationFailed, and CredentialUsable). Forwarding CredentialUsable is
// required: routing.Executor.candidates type-asserts to provider.CredentialUsability
// and calls CredentialUsable during candidate selection, so a wrapper that
// omitted it would change scheduling.
type c9countingXaiCreds struct {
	inner                *oauthxai.ProviderCredentialManager
	credential           atomic.Int64
	authenticationFailed atomic.Int64
	credentialUsable     atomic.Int64
}

func (c *c9countingXaiCreds) Credential(ctx context.Context, accountID string) (provider.Credential, error) {
	c.credential.Add(1)
	return c.inner.Credential(ctx, accountID)
}

func (c *c9countingXaiCreds) AuthenticationFailed(ctx context.Context, accountID string, upstream *provider.UpstreamError) error {
	c.authenticationFailed.Add(1)
	return c.inner.AuthenticationFailed(ctx, accountID, upstream)
}

func (c *c9countingXaiCreds) CredentialUsable(ctx context.Context, accountID string) (bool, error) {
	c.credentialUsable.Add(1)
	return c.inner.CredentialUsable(ctx, accountID)
}

// NeedsRefresh delegates to the real xAI ProviderCredentialManager so the
// counting wrapper remains a transparent CredentialRefresher, matching the
// production registration where the xAI credential manager is its own
// CredentialRefresher.
func (c *c9countingXaiCreds) NeedsRefresh(ctx context.Context, accountID string, now time.Time) (bool, error) {
	return c.inner.NeedsRefresh(ctx, accountID, now)
}

// Refresh delegates to the real xAI ProviderCredentialManager.
func (c *c9countingXaiCreds) Refresh(ctx context.Context, accountID string) error {
	return c.inner.Refresh(ctx, accountID)
}

var _ provider.CredentialRefresher = (*c9countingXaiCreds)(nil)

// c9countingDevinCreds is the Devin analogue of c9countingXaiCreds.
type c9countingDevinCreds struct {
	inner                *oauthdevin.ProviderCredentialManager
	credential           atomic.Int64
	authenticationFailed atomic.Int64
	credentialUsable     atomic.Int64
}

func (c *c9countingDevinCreds) Credential(ctx context.Context, accountID string) (provider.Credential, error) {
	c.credential.Add(1)
	return c.inner.Credential(ctx, accountID)
}

func (c *c9countingDevinCreds) AuthenticationFailed(ctx context.Context, accountID string, upstream *provider.UpstreamError) error {
	c.authenticationFailed.Add(1)
	return c.inner.AuthenticationFailed(ctx, accountID, upstream)
}

func (c *c9countingDevinCreds) CredentialUsable(ctx context.Context, accountID string) (bool, error) {
	c.credentialUsable.Add(1)
	return c.inner.CredentialUsable(ctx, accountID)
}

// c9newPublicRuntime assembles the real production component graph against a
// SQLite data directory with both a routable xAI and a routable Devin account.
// The static catalog and overlay are built from config.Default().Models so the
// five fixed public names resolve exactly as in production. The capability
// registry uses the real xai.RequestPolicy and devin.RequestPolicy and the
// real OAuth credential managers wrapped in observable counters; the
// generation clients are recording provider.GenerationClient implementations
// registered directly into provider.NewCapabilityRegistry, so the executor
// dispatches through the real policy and credential isolation path to the
// recording endpoint with no wire transport involved.
func c9newPublicRuntime(t *testing.T) *c9publicRuntime {
	t.Helper()
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{91}, 32))
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	accountRepo := store.NewAccountRepository(database.DB, keys)
	capabilityRepo := store.NewModelCapabilityRepository(database.DB)
	cooldownRepo := store.NewCooldownRepository(database.DB)
	responseRepo := store.NewResponseRepository(database.DB, keys)
	xaiAccount, err := accountRepo.UpsertLogin(ctx, store.Account{Provider: provider.XAI, Status: "ready", Credentials: store.AccountCredentials{Issuer: "issuer", Subject: "c9-public-xai", AccessToken: "xai-token"}})
	if err != nil {
		t.Fatalf("upsert xai account: %v", err)
	}
	devinExpiry := time.Now().Add(time.Hour)
	devinAccount, err := accountRepo.UpsertLogin(ctx, store.Account{Provider: provider.Devin, Status: "ready", ExpiresAt: &devinExpiry, Credentials: store.AccountCredentials{OpaqueToken: "devin-token", OpaqueTokenExpiresAt: &devinExpiry}})
	if err != nil {
		t.Fatalf("upsert devin account: %v", err)
	}
	cfg := config.Default()
	static, err := models.NewStaticCatalog(cfg.Models.Entries)
	if err != nil {
		t.Fatalf("build static catalog: %v", err)
	}
	overlay, err := models.NewStaticCatalogOverlay(static, cfg.Models.Aliases)
	if err != nil {
		t.Fatalf("build overlay: %v", err)
	}

	// Recording provider endpoints, registered directly as
	// Capabilities.Generation. The executor dispatches to them through the
	// real policy.Prepare and credential isolation path; they emit the
	// protocol-neutral event sequence the real translators consume.
	xaiClient := &c9xaiRecordingClient{text: "xAI says hello", prefix: "resp_c9_xai"}
	devinClient := &c9devinRecordingClient{text: "Devin says hello", prefix: "resp_c9_devin"}

	xaiCredsRaw := oauthxai.NewProviderCredentialManager(accountRepo, nil)
	devinCredsRaw := oauthdevin.NewProviderCredentialManager(accountRepo)
	xaiCreds := &c9countingXaiCreds{inner: xaiCredsRaw}
	devinCreds := &c9countingDevinCreds{inner: devinCredsRaw}

	reg, err := provider.NewCapabilityRegistry([]provider.CapabilityRegistration{
		{Provider: provider.XAI, PolicyKey: "xai", Capabilities: provider.Capabilities{
			Policy: xai.RequestPolicy{}, Generation: xaiClient, Credentials: xaiCreds, CredentialRefresher: xaiCreds,
		}},
		{Provider: provider.Devin, PolicyKey: "devin", Capabilities: provider.Capabilities{
			Policy: devin.RequestPolicy{}, Generation: devinClient, Credentials: devinCreds,
		}},
	})
	if err != nil {
		t.Fatalf("build capability registry: %v", err)
	}
	cooldowns := routing.NewCooldownManager(cooldownRepo, accountRepo)
	executor := routing.NewExecutor(routing.NewScheduler(), overlay, reg, cooldowns, accountRepo, capabilityRepo, cooldownRepo)
	sessionService := sessions.NewService(responseRepo)
	return &c9publicRuntime{
		database: database, keys: keys, accounts: accountRepo, capabilities: capabilityRepo,
		cooldowns: cooldownRepo, responses: responseRepo, registry: reg, catalog: overlay,
		executor: executor, sessionService: sessionService,
		xaiClient: xaiClient, devinClient: devinClient, xaiCreds: xaiCreds, devinCreds: devinCreds,
		xaiAccount: xaiAccount, devinAccount: devinAccount,
	}
}

// c9protocolNames enumerates the three public protocols exercised in the full
// 5×3×2 matrix.
type c9protocolName string

const (
	c9ProtocolChat      c9protocolName = "openai.chat"
	c9ProtocolResponses c9protocolName = "openai.responses"
	c9ProtocolAnthropic c9protocolName = "anthropic.messages"
)

// c9publicRequest describes one cell of the 5×3×2 matrix: a public model name,
// a protocol, and a stream/non-stream mode. Tool-choice variants are exercised
// separately by the focused tool tests; they never multiply this matrix.
type c9publicRequest struct {
	model    string
	protocol c9protocolName
	stream   bool
}

type c9toolChoice string

const (
	c9ToolNone     c9toolChoice = "none"
	c9ToolAuto     c9toolChoice = "auto"
	c9ToolSelected c9toolChoice = "selected"
	c9ToolAbsent   c9toolChoice = "absent"
)

// c9matrix returns the full 5×3×2 matrix of public requests: five fixed
// public names, three protocols, and two stream modes. Each row uses the
// baseline native body with no tools and no tool_choice, so the dispatch
// proof is exactly 30 rows with no tool multiplication.
func c9matrix() []c9publicRequest {
	names := []string{"grok", "grok-4.5", "kimi-k2-7", "glm-5-2", "swe-1-6-slow"}
	protocols := []c9protocolName{c9ProtocolChat, c9ProtocolResponses, c9ProtocolAnthropic}
	modes := []bool{false, true}
	var out []c9publicRequest
	for _, name := range names {
		for _, proto := range protocols {
			for _, stream := range modes {
				out = append(out, c9publicRequest{model: name, protocol: proto, stream: stream})
			}
		}
	}
	return out
}

// c9publicBody returns a baseline protocol-native request body for the
// supplied model, protocol, and stream mode. The body is minimal but valid
// for each translator: it carries no tools and no tool_choice, and always
// includes an explicit stream field so the public handler selects Execute
// versus OpenStream solely from this JSON field.
func c9publicBody(model string, proto c9protocolName, stream bool) []byte {
	streamField := "false"
	if stream {
		streamField = "true"
	}
	switch proto {
	case c9ProtocolChat:
		return []byte(`{"model":"` + model + `","messages":[{"role":"user","content":"hello"}],"stream":` + streamField + `}`)
	case c9ProtocolResponses:
		return []byte(`{"model":"` + model + `","input":"hello","stream":` + streamField + `}`)
	case c9ProtocolAnthropic:
		return []byte(`{"model":"` + model + `","max_tokens":1024,"messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}],"system":"hi","stream":` + streamField + `}`)
	}
	return nil
}

// c9publicToolBody returns a protocol-native request body for the supplied
// model, protocol, and tool-choice variant (none/auto/selected), always with
// stream:false. The tool and tool_choice shapes are the exact native schemas
// each translator accepts:
//
//   - OpenAI Chat: function tool wrapped as {"type":"function","function":{...}};
//     selected choice {"type":"function","function":{"name":"lookup"}}; none
//     and auto are the strings "none" and "auto".
//   - OpenAI Responses: flat function tool {"type":"function","name":...};
//     selected choice {"type":"function","name":"lookup"}; none and auto are
//     the strings "none" and "auto".
//   - Anthropic Messages: tool {"name":"lookup","input_schema":{...}} (no
//     OpenAI type:function wrapper); choices are objects none {"type":"none"},
//     auto {"type":"auto"}, selected {"type":"tool","name":"lookup"}.
func c9publicToolBody(model string, proto c9protocolName, choice c9toolChoice) []byte {
	switch proto {
	case c9ProtocolChat:
		const functionTool = `{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{"q":{"type":"string"}}}}}`
		tools := `,"tools":[` + functionTool + `]`
		toolChoiceField := ""
		switch choice {
		case c9ToolNone:
			toolChoiceField = `,"tool_choice":"none"`
		case c9ToolAuto:
			toolChoiceField = `,"tool_choice":"auto"`
		case c9ToolSelected:
			toolChoiceField = `,"tool_choice":{"type":"function","function":{"name":"lookup"}}`
		}
		return []byte(`{"model":"` + model + `","messages":[{"role":"user","content":"hello"}],"stream":false` + tools + toolChoiceField + `}`)
	case c9ProtocolResponses:
		const functionTool = `{"type":"function","name":"lookup","parameters":{"type":"object","properties":{"q":{"type":"string"}}}}`
		tools := `,"tools":[` + functionTool + `]`
		toolChoiceField := ""
		switch choice {
		case c9ToolNone:
			toolChoiceField = `,"tool_choice":"none"`
		case c9ToolAuto:
			toolChoiceField = `,"tool_choice":"auto"`
		case c9ToolSelected:
			toolChoiceField = `,"tool_choice":{"type":"function","name":"lookup"}`
		}
		return []byte(`{"model":"` + model + `","input":"hello","stream":false` + tools + toolChoiceField + `}`)
	case c9ProtocolAnthropic:
		const functionTool = `{"name":"lookup","input_schema":{"type":"object","properties":{"q":{"type":"string"}}}}`
		tools := `,"tools":[` + functionTool + `]`
		toolChoiceField := ""
		switch choice {
		case c9ToolNone:
			toolChoiceField = `,"tool_choice":{"type":"none"}`
		case c9ToolAuto:
			toolChoiceField = `,"tool_choice":{"type":"auto"}`
		case c9ToolSelected:
			toolChoiceField = `,"tool_choice":{"type":"tool","name":"lookup"}`
		}
		return []byte(`{"model":"` + model + `","max_tokens":1024,"messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}],"system":"hi","stream":false` + tools + toolChoiceField + `}`)
	}
	return nil
}

// c9resolvedProvider returns the provider kind that the production static
// catalog resolves the supplied public name to.
func c9resolvedProvider(name string) provider.Kind {
	switch name {
	case "grok", "grok-4.5":
		return provider.XAI
	case "kimi-k2-7", "glm-5-2", "swe-1-6-slow":
		return provider.Devin
	}
	return provider.Kind("")
}

// c9resolvedUpstream returns the upstream model name the production static
// catalog resolves the supplied public name to.
func c9resolvedUpstream(name string) string {
	switch name {
	case "grok", "grok-4.5":
		return "grok-4.5"
	case "kimi-k2-7", "glm-5-2", "swe-1-6-slow":
		return name
	}
	return ""
}

// c9servedClient returns the recording generation client for the resolved
// provider.
func (rt *c9publicRuntime) c9servedClient(name string) c9recordingClient {
	if c9resolvedProvider(name) == provider.XAI {
		return rt.xaiClient
	}
	return rt.devinClient
}

// c9recordingClient is the union of the recording client methods the
// assertions read. Both recording clients implement it.
type c9recordingClient interface {
	executeCount() int
	streamCount() int
	executeRequest() provider.GenerationRequest
	streamRequest() provider.GenerationRequest
}

func (c *c9xaiRecordingClient) executeCount() int                     { return len(c.executes) }
func (c *c9xaiRecordingClient) streamCount() int                      { return len(c.streams) }
func (c *c9xaiRecordingClient) executeRequest() provider.GenerationRequest {
	if len(c.executes) == 0 {
		return provider.GenerationRequest{}
	}
	return c.executes[0].request
}
func (c *c9xaiRecordingClient) streamRequest() provider.GenerationRequest {
	if len(c.streams) == 0 {
		return provider.GenerationRequest{}
	}
	return c.streams[0].request
}

func (c *c9devinRecordingClient) executeCount() int                     { return len(c.executes) }
func (c *c9devinRecordingClient) streamCount() int                      { return len(c.streams) }
func (c *c9devinRecordingClient) executeRequest() provider.GenerationRequest {
	if len(c.executes) == 0 {
		return provider.GenerationRequest{}
	}
	return c.executes[0].request
}
func (c *c9devinRecordingClient) streamRequest() provider.GenerationRequest {
	if len(c.streams) == 0 {
		return provider.GenerationRequest{}
	}
	return c.streams[0].request
}

// c9wrongClient returns the cross-provider recording client.
func (rt *c9publicRuntime) c9wrongClient(name string) c9recordingClient {
	if c9resolvedProvider(name) == provider.XAI {
		return rt.devinClient
	}
	return rt.xaiClient
}

// c9buildHandlers builds the three public handlers wired exactly as
// internal/app.New wires them: real translators from translate.NewRegistry,
// the real executor.Execute and executor.Stream, and the real session service
// for Responses.
func (rt *c9publicRuntime) c9buildHandlers(t *testing.T) (apiopenai.ChatHandler, apiopenai.ResponsesHandler, apianthropic.MessagesHandler) {
	t.Helper()
	transforms := translate.NewRegistry()
	chatTransform, ok := transforms.Get(registry.OpenAIChat)
	if !ok {
		t.Fatal("OpenAI Chat translator is not registered")
	}
	responsesTransform, ok := transforms.Get(registry.OpenAIResponses)
	if !ok {
		t.Fatal("OpenAI Responses translator is not registered")
	}
	anthropicTransform, ok := transforms.Get(registry.Anthropic)
	if !ok {
		t.Fatal("Anthropic translator is not registered")
	}
	chat := apiopenai.ChatHandler{
		Transform: chatTransform, Execute: rt.executor.Execute,
		OpenStream: func(ctx context.Context, request routing.Request) (api.RoutedStream, error) {
			return rt.executor.Stream(ctx, request)
		},
	}
	responses := apiopenai.ResponsesHandler{
		Transform: responsesTransform, Execute: rt.executor.Execute,
		OpenStream: func(ctx context.Context, request routing.Request) (api.RoutedStream, error) {
			return rt.executor.Stream(ctx, request)
		},
		Sessions: rt.sessionService,
	}
	messages := apianthropic.MessagesHandler{
		Transform: anthropicTransform, Execute: rt.executor.Execute,
		OpenStream: func(ctx context.Context, request routing.Request) (api.RoutedStream, error) {
			return rt.executor.Stream(ctx, request)
		},
	}
	return chat, responses, messages
}

// c9invokeHandler drives one public handler with a protocol-native request and
// returns the recorded response. For stream requests it drains the SSE body.
func c9invokeHandler(t *testing.T, req c9publicRequest, body []byte, chat apiopenai.ChatHandler, responses apiopenai.ResponsesHandler, messages apianthropic.MessagesHandler) *httptest.ResponseRecorder {
	t.Helper()
	var handler http.Handler
	switch req.protocol {
	case c9ProtocolChat:
		handler = http.HandlerFunc(chat.ServeHTTP)
	case c9ProtocolResponses:
		handler = http.HandlerFunc(responses.ServeHTTP)
	case c9ProtocolAnthropic:
		handler = http.HandlerFunc(messages.ServeHTTP)
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	if req.protocol == c9ProtocolAnthropic {
		httpReq.Header.Set("anthropic-version", "2023-06-01")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httpReq)
	return rec
}

// c9resetRecorders clears both recording clients and credential counters
// between rows so each cell starts from zero.
func (rt *c9publicRuntime) c9resetRecorders() {
	rt.xaiClient.reset()
	rt.devinClient.reset()
	rt.xaiCreds.credential.Store(0)
	rt.xaiCreds.authenticationFailed.Store(0)
	rt.xaiCreds.credentialUsable.Store(0)
	rt.devinCreds.credential.Store(0)
	rt.devinCreds.authenticationFailed.Store(0)
	rt.devinCreds.credentialUsable.Store(0)
}

// c9assertRow asserts one matrix cell: HTTP 200, exactly one generation
// dispatch on the served provider's recording client (Execute for non-stream,
// Stream for stream), zero dispatches on the cross-provider recording client,
// exact credential counters (served Credential=1, CredentialUsable>=1,
// AuthenticationFailed=0; wrong all =0), the resolved upstream model in the
// canonical request the recording client received (proving the executor's
// upstream overwrite), the baseline policy shape (xAI injects exactly one
// x_search with no tool_choice; Devin is pass-through with no x_search), and
// protocol-native response output carrying the resolved upstream model.
func c9assertRow(t *testing.T, rt *c9publicRuntime, req c9publicRequest, rec *httptest.ResponseRecorder) {
	t.Helper()
	mode := "non-stream"
	if req.stream {
		mode = "stream"
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("model=%s proto=%s %s status=%d body=%s", req.model, req.protocol, mode, rec.Code, rec.Body.String())
	}
	if req.stream {
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
			t.Fatalf("model=%s proto=%s stream content-type=%q want text/event-stream", req.model, req.protocol, ct)
		}
	}
	served := rt.c9servedClient(req.model)
	wrong := rt.c9wrongClient(req.model)
	// Exactly one generation dispatch on the served recording client.
	if req.stream {
		if served.streamCount() != 1 {
			t.Fatalf("model=%s proto=%s %s served stream dispatches=%d want 1", req.model, req.protocol, mode, served.streamCount())
		}
		if served.executeCount() != 0 {
			t.Fatalf("model=%s proto=%s %s served execute dispatches=%d want 0 (stream row)", req.model, req.protocol, mode, served.executeCount())
		}
	} else {
		if served.executeCount() != 1 {
			t.Fatalf("model=%s proto=%s %s served execute dispatches=%d want 1", req.model, req.protocol, mode, served.executeCount())
		}
		if served.streamCount() != 0 {
			t.Fatalf("model=%s proto=%s %s served stream dispatches=%d want 0 (non-stream row)", req.model, req.protocol, mode, served.streamCount())
		}
	}
	// Zero dispatches on the cross-provider recording client.
	if wrong.executeCount() != 0 || wrong.streamCount() != 0 {
		t.Fatalf("model=%s proto=%s %s cross-provider dispatches execute=%d stream=%d want 0", req.model, req.protocol, mode, wrong.executeCount(), wrong.streamCount())
	}
	rt.c9assertCredentialCounts(t, req, mode)
	rt.c9assertPolicyShape(t, req)
	if req.stream {
		c9assertProtocolStream(t, req, rec.Body.Bytes(), c9resolvedUpstream(req.model))
	} else {
		c9assertProtocolResponse(t, req, rec.Body.Bytes(), c9resolvedUpstream(req.model))
	}
}

// c9assertCredentialCounts asserts the served provider's Credential was called
// exactly once and CredentialUsable at least once, and the wrong provider's
// Credential, AuthenticationFailed, and CredentialUsable were never called.
func (rt *c9publicRuntime) c9assertCredentialCounts(t *testing.T, req c9publicRequest, mode string) {
	t.Helper()
	if c9resolvedProvider(req.model) == provider.XAI {
		if rt.xaiCreds.credential.Load() != 1 {
			t.Fatalf("model=%s proto=%s %s xAI Credential=%d want 1", req.model, req.protocol, mode, rt.xaiCreds.credential.Load())
		}
		if rt.xaiCreds.credentialUsable.Load() < 1 {
			t.Fatalf("model=%s proto=%s %s xAI CredentialUsable=%d want >=1", req.model, req.protocol, mode, rt.xaiCreds.credentialUsable.Load())
		}
		if rt.xaiCreds.authenticationFailed.Load() != 0 {
			t.Fatalf("model=%s proto=%s %s xAI AuthenticationFailed=%d want 0", req.model, req.protocol, mode, rt.xaiCreds.authenticationFailed.Load())
		}
		if rt.devinCreds.credential.Load() != 0 || rt.devinCreds.authenticationFailed.Load() != 0 || rt.devinCreds.credentialUsable.Load() != 0 {
			t.Fatalf("model=%s proto=%s %s cross-provider Devin cred=%d auth=%d usable=%d want 0", req.model, req.protocol, mode, rt.devinCreds.credential.Load(), rt.devinCreds.authenticationFailed.Load(), rt.devinCreds.credentialUsable.Load())
		}
	} else {
		if rt.devinCreds.credential.Load() != 1 {
			t.Fatalf("model=%s proto=%s %s Devin Credential=%d want 1", req.model, req.protocol, mode, rt.devinCreds.credential.Load())
		}
		if rt.devinCreds.credentialUsable.Load() < 1 {
			t.Fatalf("model=%s proto=%s %s Devin CredentialUsable=%d want >=1", req.model, req.protocol, mode, rt.devinCreds.credentialUsable.Load())
		}
		if rt.devinCreds.authenticationFailed.Load() != 0 {
			t.Fatalf("model=%s proto=%s %s Devin AuthenticationFailed=%d want 0", req.model, req.protocol, mode, rt.devinCreds.authenticationFailed.Load())
		}
		if rt.xaiCreds.credential.Load() != 0 || rt.xaiCreds.authenticationFailed.Load() != 0 || rt.xaiCreds.credentialUsable.Load() != 0 {
			t.Fatalf("model=%s proto=%s %s cross-provider xAI cred=%d auth=%d usable=%d want 0", req.model, req.protocol, mode, rt.xaiCreds.credential.Load(), rt.xaiCreds.authenticationFailed.Load(), rt.xaiCreds.credentialUsable.Load())
		}
	}
}

// c9assertPolicyShape asserts the xAI-vs-Devin canonical request policy shape
// on the provider.GenerationRequest the recording client received — i.e. after
// the executor's policy.Prepare and upstream overwrite:
//
//   - xAI models: the canonical model equals the resolved upstream name,
//     exactly one x_search tool is present (injected by xai.RequestPolicy when
//     absent), and tool_choice is never the string "none" (the policy rewrites
//     "none" → "auto"). An absent tool_choice stays absent.
//   - Devin models: the canonical model equals the resolved upstream name and
//     no x_search tool is present (devin.RequestPolicy is pass-through and
//     never injects search). The protobuf ToolChoice mapping
//     (none→OptionName="none", auto→OptionName="auto",
//     selected→ToolName="lookup") is NOT asserted here — it is proven in
//     internal/devin chat_builder_test.go
//     TestBuildChatRequestToolChoicesAcrossTranslatorShapes, which is the
//     private provider-package boundary that owns the canonical→protobuf
//     mapping. This file composes above that boundary.
func (rt *c9publicRuntime) c9assertPolicyShape(t *testing.T, req c9publicRequest) {
	t.Helper()
	served := rt.c9servedClient(req.model)
	var canonical provider.CanonicalRequest
	if req.stream {
		canonical = served.streamRequest().Canonical
	} else {
		canonical = served.executeRequest().Canonical
	}
	if c9resolvedProvider(req.model) == provider.XAI {
		c9assertXaiPolicy(t, req, canonical, c9ToolAbsent)
	} else {
		c9assertDevinPolicy(t, req, canonical, c9ToolAbsent)
	}
}

// c9assertXaiPolicy checks the xAI canonical request for the policy shape
// expected for the supplied tool-choice variant. The resolved upstream model
// must be present (the executor overwrote the public name), exactly one
// x_search tool is injected, and tool_choice is never the string "none": none
// and auto both serialize as the string "auto", and selected serializes as
// {"type":"function","name":"lookup"}. An absent tool_choice stays absent.
func c9assertXaiPolicy(t *testing.T, req c9publicRequest, canonical provider.CanonicalRequest, choice c9toolChoice) {
	t.Helper()
	if model, _ := canonical["model"].(string); model != c9resolvedUpstream(req.model) {
		t.Fatalf("model=%s proto=%s xAI canonical model=%q want %q", req.model, req.protocol, model, c9resolvedUpstream(req.model))
	}
	tools, _ := canonical["tools"].([]any)
	xSearch := 0
	for _, raw := range tools {
		if tool, ok := raw.(map[string]any); ok && tool["type"] == "x_search" {
			xSearch++
		}
	}
	if xSearch != 1 {
		t.Fatalf("model=%s proto=%s xAI x_search count=%d want 1 (tools=%v)", req.model, req.protocol, xSearch, tools)
	}
	rawChoice := canonical["tool_choice"]
	if str, ok := rawChoice.(string); ok && str == "none" {
		t.Fatalf("model=%s proto=%s xAI tool_choice=%q want not none", req.model, req.protocol, str)
	}
	switch choice {
	case c9ToolAbsent:
		// Baseline body carries no tool_choice; the xAI policy only rewrites
		// an explicit "none" to "auto", so an absent tool_choice stays absent.
		if rawChoice != nil {
			t.Fatalf("model=%s proto=%s xAI tool_choice=%#v want absent", req.model, req.protocol, rawChoice)
		}
	case c9ToolNone, c9ToolAuto:
		if str, ok := rawChoice.(string); !ok || str != "auto" {
			t.Fatalf("model=%s proto=%s xAI tool_choice=%#v want auto", req.model, req.protocol, rawChoice)
		}
	case c9ToolSelected:
		if choiceMap, ok := rawChoice.(map[string]any); !ok || choiceMap["type"] != "function" || choiceMap["name"] != "lookup" {
			t.Fatalf("model=%s proto=%s xAI selected tool_choice=%#v want {type:function name:lookup}", req.model, req.protocol, rawChoice)
		}
	}
}

// c9assertDevinPolicy checks the Devin canonical request for the policy shape
// expected for the supplied tool-choice variant, at the app-level boundary
// (the canonical request the recording client received). The canonical model
// must equal the resolved upstream name and no x_search tool is present
// (devin.RequestPolicy is pass-through). The protobuf ToolChoice mapping
// (none→OptionName="none", auto→OptionName="auto", selected→ToolName="lookup")
// is owned by the Devin wire encoder inside the real devin.ProviderClient and
// is proven in internal/devin chat_builder_test.go
// TestBuildChatRequestToolChoicesAcrossTranslatorShapes; this file asserts
// only the app-level pass-through contract (no x_search injection, upstream
// model overwrite) and the canonical tool_choice shape the encoder receives.
func c9assertDevinPolicy(t *testing.T, req c9publicRequest, canonical provider.CanonicalRequest, choice c9toolChoice) {
	t.Helper()
	if canonical == nil {
		t.Fatalf("model=%s proto=%s Devin canonical request is nil", req.model, req.protocol)
	}
	if model, _ := canonical["model"].(string); model != c9resolvedUpstream(req.model) {
		t.Fatalf("model=%s proto=%s Devin canonical model=%q want %q", req.model, req.protocol, model, c9resolvedUpstream(req.model))
	}
	tools, _ := canonical["tools"].([]any)
	xSearch := 0
	for _, raw := range tools {
		if tool, ok := raw.(map[string]any); ok && tool["type"] == "x_search" {
			xSearch++
		}
	}
	if xSearch != 0 {
		t.Fatalf("model=%s proto=%s Devin x_search count=%d want 0 (tools=%v)", req.model, req.protocol, xSearch, tools)
	}
	// The canonical tool_choice shape the Devin wire encoder receives. The
	// none/auto/selected→protobuf mapping is proven in internal/devin.
	switch choice {
	case c9ToolAbsent:
		// Baseline body carries no tool_choice; the Devin encoder defaults an
		// absent tool_choice to OptionName="auto" (proven in internal/devin).
		if raw := canonical["tool_choice"]; raw != nil {
			t.Fatalf("model=%s proto=%s Devin tool_choice=%#v want absent", req.model, req.protocol, raw)
		}
	case c9ToolNone:
		if str, ok := canonical["tool_choice"].(string); !ok || str != "none" {
			t.Fatalf("model=%s proto=%s Devin none tool_choice=%#v want string none", req.model, req.protocol, canonical["tool_choice"])
		}
	case c9ToolAuto:
		if str, ok := canonical["tool_choice"].(string); !ok || str != "auto" {
			t.Fatalf("model=%s proto=%s Devin auto tool_choice=%#v want string auto", req.model, req.protocol, canonical["tool_choice"])
		}
	case c9ToolSelected:
		if choiceMap, ok := canonical["tool_choice"].(map[string]any); !ok || choiceMap["type"] != "function" || choiceMap["name"] != "lookup" {
			t.Fatalf("model=%s proto=%s Devin selected tool_choice=%#v want {type:function name:lookup}", req.model, req.protocol, canonical["tool_choice"])
		}
	}
}

// c9assertProtocolResponse asserts the protocol-native non-stream response
// carries the resolved upstream model in the protocol's native model field.
func c9assertProtocolResponse(t *testing.T, req c9publicRequest, body []byte, upstream string) {
	t.Helper()
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("model=%s proto=%s stream=false response not JSON: %v body=%s", req.model, req.protocol, err, body)
	}
	switch req.protocol {
	case c9ProtocolChat:
		if model, _ := parsed["model"].(string); model != upstream {
			t.Fatalf("model=%s proto=%s chat response model=%q want %q", req.model, req.protocol, model, upstream)
		}
		if obj, _ := parsed["object"].(string); obj != "chat.completion" {
			t.Fatalf("model=%s proto=%s chat response object=%q want chat.completion", req.model, req.protocol, obj)
		}
	case c9ProtocolResponses:
		if model, _ := parsed["model"].(string); model != upstream {
			t.Fatalf("model=%s proto=%s responses response model=%q want %q", req.model, req.protocol, model, upstream)
		}
	case c9ProtocolAnthropic:
		if model, _ := parsed["model"].(string); model != upstream {
			t.Fatalf("model=%s proto=%s anthropic response model=%q want %q", req.model, req.protocol, model, upstream)
		}
		if typ, _ := parsed["type"].(string); typ != "message" {
			t.Fatalf("model=%s proto=%s anthropic response type=%q want message", req.model, req.protocol, typ)
		}
	}
}

// c9assertProtocolStream asserts the protocol-native stream output carries the
// resolved upstream model and the terminal event for the protocol.
func c9assertProtocolStream(t *testing.T, req c9publicRequest, body []byte, upstream string) {
	t.Helper()
	events := c9parseSSE(body)
	if len(events) == 0 {
		t.Fatalf("model=%s proto=%s stream=true no SSE events body=%s", req.model, req.protocol, body)
	}
	switch req.protocol {
	case c9ProtocolChat:
		foundDone := false
		foundChunk := false
		for _, ev := range events {
			if ev == "data: [DONE]" {
				foundDone = true
				continue
			}
			data := c9stripDataPrefix(ev)
			var chunk map[string]any
			if json.Unmarshal([]byte(data), &chunk) != nil {
				continue
			}
			if obj, _ := chunk["object"].(string); obj == "chat.completion.chunk" {
				foundChunk = true
				if model, _ := chunk["model"].(string); model != upstream {
					t.Fatalf("model=%s proto=%s chat stream chunk model=%q want %q", req.model, req.protocol, model, upstream)
				}
			}
		}
		if !foundChunk {
			t.Fatalf("model=%s proto=%s chat stream missing chat.completion.chunk", req.model, req.protocol)
		}
		if !foundDone {
			t.Fatalf("model=%s proto=%s chat stream missing [DONE] sentinel", req.model, req.protocol)
		}
	case c9ProtocolResponses:
		foundCreated := false
		foundTerminal := false
		for _, ev := range events {
			data := c9stripDataPrefix(ev)
			var envelope map[string]any
			if json.Unmarshal([]byte(data), &envelope) != nil {
				continue
			}
			switch typ, _ := envelope["type"].(string); typ {
			case "response.created", "response.completed":
				// Both paired records must carry a response map with the exact
				// resolved upstream model; a missing map or model is a
				// composition failure, not a skip.
				if typ == "response.created" {
					foundCreated = true
				} else {
					foundTerminal = true
				}
				resp, ok := envelope["response"].(map[string]any)
				if !ok {
					t.Fatalf("model=%s proto=%s responses stream %s missing response map: %#v", req.model, req.protocol, typ, envelope)
				}
				if model, _ := resp["model"].(string); model != upstream {
					t.Fatalf("model=%s proto=%s responses stream %s model=%q want %q", req.model, req.protocol, typ, model, upstream)
				}
			}
		}
		if !foundCreated {
			t.Fatalf("model=%s proto=%s responses stream missing response.created", req.model, req.protocol)
		}
		if !foundTerminal {
			t.Fatalf("model=%s proto=%s responses stream missing response.completed", req.model, req.protocol)
		}
	case c9ProtocolAnthropic:
		foundStart := false
		foundStop := false
		for _, ev := range events {
			data := c9stripDataPrefix(ev)
			var envelope map[string]any
			if json.Unmarshal([]byte(data), &envelope) != nil {
				continue
			}
			if typ, _ := envelope["type"].(string); typ == "message_start" {
				foundStart = true
				// message_start must carry a message map with the exact
				// resolved upstream model; a missing map or model is a
				// composition failure, not a skip.
				msg, ok := envelope["message"].(map[string]any)
				if !ok {
					t.Fatalf("model=%s proto=%s anthropic stream message_start missing message map: %#v", req.model, req.protocol, envelope)
				}
				if model, _ := msg["model"].(string); model != upstream {
					t.Fatalf("model=%s proto=%s anthropic stream message_start model=%q want %q", req.model, req.protocol, model, upstream)
				}
			}
			if typ, _ := envelope["type"].(string); typ == "message_stop" {
				foundStop = true
			}
		}
		if !foundStart {
			t.Fatalf("model=%s proto=%s anthropic stream missing message_start", req.model, req.protocol)
		}
		if !foundStop {
			t.Fatalf("model=%s proto=%s anthropic stream missing message_stop", req.model, req.protocol)
		}
	}
}

// c9parseSSE splits an SSE response body into its raw event lines.
func c9parseSSE(body []byte) []string {
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "data: ") || strings.HasPrefix(line, "event: ") {
			out = append(out, line)
		}
	}
	return out
}

func c9stripDataPrefix(line string) string {
	if strings.HasPrefix(line, "data: ") {
		return strings.TrimPrefix(line, "data: ")
	}
	return line
}

// TestC9PublicChainDispatchesFullFiveByThreeByTwoMatrix asserts C9.3 across the
// full 5×3×2 matrix: for every fixed static public name, every public protocol
// (OpenAI Chat, OpenAI Responses, Anthropic Messages), and both stream and
// non-stream modes, the real public handler dispatches through the real
// translator → static resolve → runtime lookup → policy.Prepare → upstream
// overwrite → provider filter → credential isolation → recording generation
// client → response translation path. Each row uses the baseline native body
// with no tools and no tool_choice, so the dispatch proof is exactly 30 rows
// with no tool multiplication. Each row asserts exactly one generation dispatch
// on the served recording client (Execute for non-stream, Stream for stream),
// zero dispatches on the cross-provider recording client, zero cross-provider
// credential accesses (directly observable via the credential counters), the
// baseline xAI search policy versus Devin pass-through on the canonical request
// the recording client received, and protocol-native response output carrying
// the resolved upstream model. Wire serialization is NOT asserted here; it is
// proven at the private provider-package boundary in internal/xai and
// internal/devin tests.
func TestC9PublicChainDispatchesFullFiveByThreeByTwoMatrix(t *testing.T) {
	rt := c9newPublicRuntime(t)
	chat, responses, messages := rt.c9buildHandlers(t)
	for _, req := range c9matrix() {
		t.Run(fmt.Sprintf("%s/%s/stream=%v", req.model, req.protocol, req.stream), func(t *testing.T) {
			rt.c9resetRecorders()
			body := c9publicBody(req.model, req.protocol, req.stream)
			rec := c9invokeHandler(t, req, body, chat, responses, messages)
			c9assertRow(t, rt, req, rec)
		})
	}
}

// TestC9PublicChainToolChoiceMatrix exercises the none/auto/selected
// tool-choice variants separately from the dispatch matrix, for xAI (grok) and
// Devin (kimi-k2-7) across all three public protocols. Each cell uses the
// protocol-native tool and tool_choice shapes and asserts the policy shape on
// the canonical request the recording client received: xAI injects exactly one
// x_search and rewrites string "none" to "auto"; Devin stays free of x_search
// (pass-through policy). The Devin canonical→protobuf ToolChoice mapping
// (none→OptionName="none", auto→OptionName="auto",
// selected→ToolName="lookup") is proven in internal/devin
// chat_builder_test.go TestBuildChatRequestToolChoicesAcrossTranslatorShapes
// and is not re-asserted here. These rows are non-stream and do not multiply
// the 5×3×2 dispatch matrix.
func TestC9PublicChainToolChoiceMatrix(t *testing.T) {
	rt := c9newPublicRuntime(t)
	chat, responses, messages := rt.c9buildHandlers(t)
	models := []string{"grok", "kimi-k2-7"}
	protocols := []c9protocolName{c9ProtocolChat, c9ProtocolResponses, c9ProtocolAnthropic}
	choices := []c9toolChoice{c9ToolNone, c9ToolAuto, c9ToolSelected}
	for _, model := range models {
		for _, proto := range protocols {
			for _, choice := range choices {
				t.Run(fmt.Sprintf("%s/%s/tool=%s", model, proto, choice), func(t *testing.T) {
					rt.c9resetRecorders()
					req := c9publicRequest{model: model, protocol: proto, stream: false}
					body := c9publicToolBody(model, proto, choice)
					rec := c9invokeHandler(t, req, body, chat, responses, messages)
					if rec.Code != http.StatusOK {
						t.Fatalf("model=%s proto=%s tool=%s status=%d body=%s", model, proto, choice, rec.Code, rec.Body.String())
					}
					served := rt.c9servedClient(model)
					if served.executeCount() != 1 {
						t.Fatalf("model=%s proto=%s tool=%s served execute dispatches=%d want 1", model, proto, choice, served.executeCount())
					}
					if served.streamCount() != 0 {
						t.Fatalf("model=%s proto=%s tool=%s served stream dispatches=%d want 0", model, proto, choice, served.streamCount())
					}
					// Zero dispatches on the cross-provider recording client,
					// matching the base matrix accounting.
					if wrong := rt.c9wrongClient(model); wrong.executeCount() != 0 || wrong.streamCount() != 0 {
						t.Fatalf("model=%s proto=%s tool=%s cross-provider dispatches execute=%d stream=%d want 0", model, proto, choice, wrong.executeCount(), wrong.streamCount())
					}
					// Exact credential counters: served Credential=1,
					// CredentialUsable>=1, AuthenticationFailed=0;
					// cross-provider all =0, matching the base matrix.
					rt.c9assertCredentialCounts(t, req, "tool")
					// Assert the policy shape on the canonical request the
					// recording client received (post-policy.Prepare,
					// post-upstream-overwrite).
					if c9resolvedProvider(model) == provider.XAI {
						c9assertXaiPolicy(t, req, served.executeRequest().Canonical, choice)
					} else {
						c9assertDevinPolicy(t, req, served.executeRequest().Canonical, choice)
					}
				})
			}
		}
	}
}
