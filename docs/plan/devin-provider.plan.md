# Devin Provider Absorption Plan

> Status: approved implementation blueprint; implementation has not started.
>
> Current next chunk: **Chunk 1 — Provider identity, neutral contracts, and schema migration**.
>
> Progress for the Devin absorption is tracked only in [`devin-provider.todo.md`](./devin-provider.todo.md). The historical [`init.plan.md`](./init.plan.md) and [`init.todo.md`](./init.todo.md) remain unchanged evidence of the original xAI-only design and implementation. The four unchecked `init.todo.md` items—dependency pinning, two-account live OAuth/`x_search` acceptance, live failover/restart acceptance, and final source/license review—remain separate open blockers; this plan neither supersedes nor closes them.

## Goal

Absorb Devin OAuth and runtime protocol into BYOS without turning shared request, routing, persistence, or management code into provider conditionals. BYOS remains a single-process, single-tenant account-pool service with encrypted SQLite persistence and the existing public OpenAI/Anthropic compatibility routes.

The completed system must:

- retain xAI/SuperGrok/Grok ownership of `grok` and `grok-4.5`, including mandatory native `x_search` and the current xAI request/header/error/billing behavior;
- add Devin ownership of exactly `kimi-k2-7`, `glm-5-2`, and `swe-1-6-slow` as the required hardcoded catalog;
- resolve model ownership before request mutation, account scheduling, credential handling, or upstream dispatch;
- preserve Devin `tool_choice` values: absent/default remains protocol-normalized, explicit `none` remains `none`, `auto` remains `auto`, and a selected tool remains that selected tool; Devin never receives injected `x_search`;
- implement Devin browser OAuth with provider-bound, expiring, single-use state and S256 PKCE, persist only the encrypted opaque account token and encrypted pending verifier/redirect/expiry material required for durable lifecycle recovery, and require relogin when the opaque Devin token expires;
- expose provider-aware account, model, OAuth, and usage behavior through Admin REST, Web UI, and CLI;
- preserve shared cooldown, pre-commit failover, managed Responses affinity, response translation, and local usage accounting without permitting cross-provider routing.

## Authoritative inputs and source-evidence boundary

This plan is based on the four exploration packets:

- `agent://ResumeArtifactScout`: no prior Devin implementation or Devin-specific durable tracker exists; the branch is pre-implementation; historical xAI artifacts must not be rewritten.
- `agent://DevinSourceScout`: implemented Devin OAuth/runtime protocol and required-versus-optional source behavior.
- `agent://TargetArchitectureScout`: current BYOS coupling map, exact target symbols, and provider-neutral boundary.
- `agent://VerificationSecurityScout`: migration, security, deployment, and executable verification patterns.

Source-supported Devin behavior is limited to:

1. browser authorization at `https://app.devin.ai/auth/cli/continue`;
2. code exchange at `https://api.devin.ai/auth/cli/token` using JSON `code` and `code_verifier`;
3. an opaque token with no refresh credential;
4. `GetUserJwt`, `GetChatMessage`, and optional `GetCliModelConfigs` protobuf/Connect calls against `server.codeium.com` or the returned chat-only custom base URL;
5. per-response input, output, and cache-read token usage contained in chat response frames.

Capacity checks, account quota/statistics, analytics submission, credit/ACU reporting, and `RecordCascadeUsage` are not on the implemented source path and are excluded. Dynamic Devin model discovery is optional and cannot alter the required hardcoded routing set unless separately enabled and filtered through that set.

## Existing patterns that must be reused

- `internal/translate/registry/registry.go` and the three translator trees already provide a provider-neutral canonical Responses representation.
- `internal/store/accounts.go`, `internal/store/oauth_sessions.go`, and the root `migrations` package provide encrypted persistence and ordered migrations.
- `internal/routing/execute.go`, `scheduler.go`, `stream.go`, and `cooldown.go` provide retry, pre-stream failover, cooldown, affinity, and local accounting semantics.
- `internal/search/inject.go` is the existing xAI policy implementation and remains xAI-only.
- `internal/oauth/xai`, `internal/xai`, `internal/models`, and `internal/usage/xai_billing.go` are the existing xAI adapter behavior to preserve behind the new contracts.
- Admin REST allowlisted views, Web server-side templates/CSRF, and CLI command dispatch remain the management patterns; no SPA or second management stack is introduced.
- Trusted-proxy behavior, xAI ES256 verifier propagation, non-HTML-escaped xAI wire JSON, and existing credential-domain separation in `AGENTS.md` remain invariants.

## Locked architecture decisions

### 1. Provider is a durable routing key

Create `internal/provider` as the neutral contract package. It owns:

- `type Kind string` with only `xai` and `devin`;
- `ResolvedModel { PublicName, UpstreamName string; Provider Kind; OwnedBy string; PolicyKey string }`, containing only immutable static resolution data and no runtime capability object;
- neutral generation `Event` and `Stream` types currently imported from `internal/xai` by shared API/routing code;
- neutral `UpstreamError`/classification metadata sufficient for status, retryability, `Retry-After`, cooldown scope, and sanitized public errors;
- interfaces for `RequestPolicy`, `GenerationClient`, `CredentialManager`, optional `ModelDiscoverer`, and optional `UsageFetcher`;
- an immutable static `ModelCatalog` that resolves public names to `ResolvedModel`, separate from an immutable runtime `CapabilityRegistry` keyed by provider/policy key and containing provider implementations.

Provider packages implement runtime capabilities; shared API, routing, models, usage, accounts, and Web packages do not import concrete provider packages. `internal/app` is the composition root and may import both implementations. Static model ownership never contains or constructs provider clients, and runtime capability registration never creates or changes model ownership.

### 2. Resolution precedes mutation

The request path becomes:

```text
public request
  -> protocol translator / managed Responses reconstruction
  -> static model catalog Resolve(requested model)
  -> runtime capability registry lookup by resolved provider/policy key
  -> resolved provider RequestPolicy.Prepare(canonical public-model body)
  -> executor overwrites canonical model with UpstreamName
  -> account candidates filtered by account.provider
  -> scheduler/cooldown/affinity within that provider
  -> provider credential manager
  -> provider generation client serializes the provider wire payload exactly once
  -> neutral events
  -> public response translation / managed-session persistence / local usage
```

The three generation handlers stop calling `search.Inject` and stop owning provider wire payloads. The executor exclusively owns the mutable canonical request from resolution through one policy application and the subsequent `UpstreamName` overwrite; it passes that canonical request to the selected generation client, which alone marshals its provider wire representation once. There is no pre-marshaled placeholder body, handler-side provider marshal, double marshal, re-resolution, or provider change during retries.

### 3. Static model ownership is authoritative

The required immutable static model-resolution catalog is deterministic and conflict-free:

| Public name | Upstream name | Provider | Public owner | Policy key |
|---|---|---|---|---|
| `grok` | `grok-4.5` | `xai` | `byos` | `xai` |
| `grok-4.5` | `grok-4.5` | `xai` | `xai` | `xai` |
| `kimi-k2-7` | `kimi-k2-7` | `devin` | `devin` | `devin` |
| `glm-5-2` | `glm-5-2` | `devin` | `devin` | `devin` |
| `swe-1-6-slow` | `swe-1-6-slow` | `devin` | `devin` | `devin` |

Public names are globally unique, but aliases are first-class: both `grok` and `grok-4.5` validly project to the same canonical xAI registration `(UpstreamName=grok-4.5, Provider=xai, PolicyKey=xai)`. Catalog construction rejects duplicate public names and rejects an ambiguous canonical upstream registration when the same upstream name is assigned to a different provider or policy key; it does not reject multiple public aliases of one canonical provider-model registration. No conflict-resolution UI, precedence field, provider-qualified public name, or response-session provider column is added. `OwnedBy` is public listing metadata only. A model is routable only through an enabled usable account whose `account.provider` equals `ResolvedModel.Provider`; a stored preferred account remains valid only under that same equality.

Dynamic `GetCliModelConfigs` discovery is an optional capability-health overlay. It may confirm whether the three hardcoded Devin models are currently advertised and persist normalized per-account capability snapshots. It must not expose incidental discovered models or make static ownership depend on discovery. If discovery is omitted or fails, configured hardcoded Devin models use the existing unknown-capability fallback, but only among Devin accounts.

### 4. Request policies are provider-owned

- xAI policy reuses `internal/search.Inject`/`Validate`: exactly one `x_search`, `none` becomes `auto`, auto/selected/required semantics remain as today, and backend-search capability remains an xAI routability condition.
- Devin policy is a true pass-through at the canonical boundary: it does not add tools or rewrite explicit tool choice. Final Devin protobuf mapping converts canonical `none`, `auto`, or selected name directly; it always sets the source-required `disable_parallel_tool_calls=true`.
- Input-protocol normalization still belongs to translators. For example, an omitted Anthropic choice may become canonical `auto`; that is not a Devin provider rewrite.
- Unsupported canonical choices at the Devin wire boundary return a deterministic invalid-request error. They are never silently converted to xAI behavior.

### 5. Accounts and OAuth sessions are provider-typed

Add migration `migrations/005_provider_identity.sql`:

- `accounts.provider TEXT NOT NULL DEFAULT 'xai'` with a check constraint or store validation limited to `xai|devin`;
- `oauth_sessions.provider TEXT NOT NULL DEFAULT 'xai'`;
- `oauth_sessions.flow_type TEXT NOT NULL DEFAULT 'device'`, with `device` for existing xAI rows and `callback_pkce` for Devin;
- indexes required for provider/status resumable-session lookup.

SQLite limitations may require table rebuilds to add effective checks; migration tests must prove populated rows survive and become `xai`. No historical migration is edited.

The shared repositories expose provider on every account/session read and require it on new writes and lifecycle mutations. Provider mismatch is a not-found/conflict result and cannot operate on another provider's session.

For Devin, source evidence exposes no stable verified account subject. The initial identity fingerprint is therefore `HMAC(identity_key, "devin\x00" + opaque_token)`: replaying the identical token deduplicates, while a later login returning a different token creates a new account. The management flow instructs the operator to disable/delete the expired account after relogin. Do not derive identity from an unverified JWT claim or invent a refresh/identity endpoint. This is a deliberate limitation, not an implicit TODO.

### 6. Devin OAuth is callback/PKCE, not device polling

Create `internal/oauth/devin` with:

- 96 random bytes encoded as unpadded base64url for the verifier;
- SHA-256 S256 challenge;
- 32 random bytes encoded as unpadded base64url for state;
- five-minute default attempt lifetime;
- authorization query containing exactly `redirect_uri`, `state`, `prompt=select_account`, `code_challenge`, and `code_challenge_method=S256`;
- `POST` JSON `{code, code_verifier}` exchange with `Accept: application/json`, `Content-Type: application/json`, bounded timeout, HTTPS/host validation, and redirects disabled;
- acceptance of only a non-empty JSON `token` string;
- best-effort JWT `exp` metadata extraction only, with effective expiry `exp - 5m`; non-JWT/malformed tokens receive the source-supported one-year local fallback; this is not signature validation;
- no refresh path; expiry or upstream 401/403 marks relogin required.

Only genuinely durable values are stored. Encrypted account credentials contain the opaque Devin token and its derived expiry metadata. While a callback attempt is pending, its encrypted OAuth payload contains the verifier, redirect URI, expiry, and only sanitized lifecycle metadata; plaintext storage contains only the state hash plus provider/flow/status/timestamps. Raw state, callback authorization code, and per-request user JWT are never stored in account/session rows or SQLite DB/WAL/SHM. The atomic consume mutation validates the pending provider-bound attempt, irreversibly changes `pending -> consumed`, decrypts and returns the verifier only to caller memory, and clears the pending encrypted verifier/redirect payload or makes its prior ciphertext cryptographically inaccessible. `consumed` is a non-retryable in-flight state, not an immutable final state: it can transition only to `completed` or `failed`, and restart recovery finalizes an interrupted consumed attempt as failed without repeating exchange. `completed`, `failed`, `expired`, and `cancelled` are immutable terminal states and expose no decryptable pending secret. Any exchange failure finalizes `consumed -> failed`; it requires a new start and never restores the consumed attempt. After successful exchange, one SQLite transaction upserts/deduplicates the encrypted Devin account and changes the consumed OAuth session to completed; commit is the visibility/success boundary. Account-write, session-completion, or commit failure rolls back all newly written credential state, preserves any pre-existing deduplicated account, and finalizes the still-consumed attempt as failed without making it retryable.

The configured public callback origin/path is explicit and validated. It is never constructed from `Host` or forwarded headers. Start/status/cancel are admin-authenticated and keyed by OAuth session ID; unknown IDs return not-found, and concurrent session IDs cannot observe or cancel one another. The callback itself is exempt from admin authentication but authorized only by provider-bound single-use state and PKCE.

### 7. Devin runtime adapter is isolated

Create `internal/devin` for the protocol client and generated/minimal protobuf code, and `internal/provider/devin` for adapter wiring if separation is needed to keep protocol details out of the neutral package. It owns:

- exactly-one `devin-session-token$` normalization;
- source Windsurf metadata constants;
- per-request `GetUserJwt` and chat-only `custom_api_server_url` override;
- `GetChatMessage` canonical request construction, source defaults/stops/IDs/message/tool/image behavior, selected tool mapping, and unchanged model UID;
- gzip Connect framing, end-stream/trailer decoding, context cancellation, bounded frame allocation, neutral text/thinking/tool/usage/stop events, and pre/post-commit error semantics;
- non-stream buffering through the existing shared execution surface, not a second non-stream upstream call.

Security hardening beyond the source is required where the source packet identified gaps: reject empty `user_jwt`; validate custom chat base as absolute HTTPS and restrict it to an explicit configured host policy; impose a maximum frame size; treat malformed end-stream trailers deterministically; never include upstream bodies or tokens in errors.

All Devin transport bounds are locked configuration in Chunk 2, before adapter work: `unary_timeout` defaults to 15s (1s–60s); `stream_idle_timeout` defaults to 60s (5s–5m), reset only after a complete frame is decoded; optional `stream_deadline` defaults to `0` (disabled) and, when explicitly configured from 30s–30m for a justified deployment, may only shorten—not replace or extend—the caller context deadline; `max_unary_compressed_bytes` 2 MiB (1 KiB–8 MiB); `max_unary_decompressed_bytes` 8 MiB (1 KiB–32 MiB); `max_frame_compressed_bytes` 4 MiB (1 KiB–16 MiB); `max_frame_decompressed_bytes` 16 MiB (1 KiB–64 MiB); `max_stream_bytes` 64 MiB (1 MiB–256 MiB) across decompressed response payloads; `max_tool_argument_bytes` 4 MiB (1 KiB–16 MiB) per accumulated tool call; and `max_non_stream_bytes` 32 MiB (1 MiB–128 MiB) for shared buffered output. Size and idle limits are nonzero and reject out-of-range configuration; the total stream lifetime is caller-context-driven by default. Every enabled limit is enforced before allocation/decompression/append.

### 8. Refresh, discovery, and usage dispatch are capability-based

- xAI keeps refresh singleflight and rotation. Devin credential manager only checks token usability and converts expiry/401/403 to relogin-required; it never calls xAI refresh.
- model refresh workers carry account provider and dispatch to that provider's optional discoverer. Absence of a discoverer is not an error.
- xAI billing remains xAI-only. Devin has no source-supported subscription/quota fetcher; its upstream quota state is explicitly unavailable.
- per-response Devin usage is required because it is present in chat frames: input, output, total=`input+output`, and cache-read tokens are mapped to neutral events and existing local counters. Cache-write, credit, ACU, quota, and analytics fields are not exposed or submitted.

### 9. Management surfaces select and display provider

Admin REST uses distinct semantics rather than overloading xAI device routes:

- preserve `/admin/api/v1/oauth/xai/device/*`;
- add `POST /admin/api/v1/oauth/devin/start`;
- add configured `GET /admin/api/v1/oauth/devin/callback`;
- add authenticated status/cancel routes keyed by OAuth session ID.

Web `/admin/oauth/new` accepts an allowlisted provider selection and renders provider-specific instructions/status. CLI becomes `byos login --provider xai|devin`, defaulting to `xai` for compatibility; Devin prints/opens the authorization URL and waits on the same persisted lifecycle used by Web/API. All account/model/usage views include provider. Devin displays local usage and upstream quota `unavailable`, never fabricated xAI monthly/weekly values.

### 10. Clean cutover

There are no shims or parallel legacy paths:

- shared routing/API types stop importing `internal/xai` event/client types;
- handlers stop calling `search.Inject` directly;
- workers stop accepting provider-blind account projections;
- singular runtime wiring is replaced by an immutable static model catalog plus a separate immutable provider capability registry;
- every existing xAI account/session is migrated to explicit `xai`;
- historical planning files and xAI routes/protocol identifiers remain unchanged.

## Sequential implementation chunks

Each chunk is independently reviewable and committable and depends on completion of the immediately preceding chunk; checklist items form one total order with no parallel branches. A chunk is complete only after its focused verification passes. Full checklist detail and item-level definitions of done are in [`devin-provider.todo.md`](./devin-provider.todo.md).

### Chunk 1 — Provider identity, neutral contracts, and schema migration

Create `internal/provider` core types/interfaces; add `005_provider_identity.sql`; update `internal/store/accounts.go`, `oauth_sessions.go`, scans/mutations, and migration/encryption tests. Backfill all existing rows to `xai`; persist only real durable Devin account/pending-session fields under encryption; define irreversible `pending -> consumed` with in-memory-only verifier return and pending-secret disposal, constrain finalization to `consumed -> completed|failed`, keep completed/failed/expired/cancelled immutable, and reject provider mismatch.

Verification: `go test ./internal/store ./internal/crypto ./internal/provider` plus a populated-v4-to-v5 migration fixture and DB/WAL/SHM plaintext scan.

Rollback/risk: migration must be forward-only and preserve a pre-migration backup operationally. Do not proceed if old rows, foreign keys, or encrypted envelopes change unexpectedly.

### Chunk 2 — Static model ownership and provider-aware configuration

Update `internal/config/config.go`, `internal/models/catalog.go`, `internal/api/openai/models.go`, and model/config tests. Introduce provider-scoped settings, explicit callback configuration, deterministic ownership for the five public names, and the complete locked Devin body/frame/stream/buffer bounds and timeout contract. Construct and populate the immutable static model-resolution catalog here; it stores only static identity and a stable policy key, never runtime capabilities. Keep `grok -> grok-4.5` fixed.

Verification: focused config/model/OpenAI model handler tests proving exact ownership metadata, duplicate-public and ambiguous-canonical-registration startup rejection, a positive `grok` plus `grok-4.5` alias fixture sharing canonical xAI `grok-4.5`, provider-based routability including `grok` with a usable xAI account despite `OwnedBy=byos`, strict YAML, limit defaults/ranges/semantics (including caller-context-driven streams and disabled-by-default total deadline), no serialized secrets, and Devin independence from xAI backend-search capability.

Rollback/risk: configuration must fail closed on unknown providers, duplicate public names, ambiguous canonical upstream registrations across provider/policy identities, invalid callback URLs/paths, invalid size/idle limits, invalid nonzero stream deadlines, or attempts to transfer `grok-4.5` ownership. Valid public aliases of one canonical provider-model registration must remain accepted. Runtime provider capability registration is not owned by this chunk.

### Chunk 3 — Provider-neutral routing and complete xAI generation cutover

Refactor `internal/routing/execute.go`, `stream.go`, `scheduler.go`, `errors.go`, `internal/api/generation.go`, all three generation handlers, and related tests to consume the immutable static `ResolvedModel`, neutral events/streams/errors, provider-filtered candidates, and a separate runtime capability registry. In this same clean-cutover chunk, implement the real xAI `RequestPolicy` over `internal/search`, remove every handler-level `search.Inject` call, and adapt the existing xAI generation transport, credentials needed for generation, headers, serialization, events, and generation-error mapping to the neutral interfaces. The executor resolves first, looks up capabilities, applies policy to the public-model canonical request, overwrites the model with `UpstreamName`, filters provider candidates, and dispatches. It exclusively owns the canonical payload until the xAI generation client marshals the xAI wire body exactly once. Preserve cooldown/failover/account-affinity/local-usage and all current xAI request/header/error behavior; no placeholder policy, placeholder payload, double marshal, compatibility branch, or duplicate mutation path is permitted.

Verification: instrumented cross-protocol and routing tests prove resolve → runtime capability lookup → real provider policy on the public canonical model → `UpstreamName` overwrite → provider filtering → credentials/client; unknown models are byte-unmutated; every xAI request has exactly one `x_search`, `none -> auto`, selected choices remain selected; captured xAI wire bodies/headers/model override/JSON escaping remain equivalent; provider filtering precedes unknown-capability fallback; affinity/failover cannot cross providers; and no committed stream is replayed.

Rollback/risk: this chunk registers only the complete generation-required xAI runtime capabilities, but its committed state must serve existing xAI generation end to end with no direct xAI event/client imports in shared routing/API code, no pre-resolution or handler-level mutation, and no legacy transport path. Any xAI request-policy, transport, header, serialization, or error regression blocks the commit.

### Chunk 4 — xAI OAuth, refresh, discovery, and billing parity

Wrap existing `internal/oauth/xai`, OIDC identity, credential refresh, model discovery/backend-search capability, and billing behind the remaining provider capability contracts. The real xAI policy, generation transport, generation credentials, and generation-error adaptation are already complete in Chunk 3; this chunk must not reconstruct or bypass that path.

Verification: all focused xAI OAuth/refresh/discovery/billing tests prove device flow, ES256 verifier propagation, refresh singleflight/rotation, model fallback/backend-search gating, billing, migrated account/session behavior, and provider mismatch remain unchanged through provider capabilities. Chunk 3 generation parity remains green.

Rollback/risk: any observable xAI OAuth/refresh/discovery/billing regression blocks Devin work. Preserve ES256 discovery algorithms and do not introduce a second runtime registry, model catalog, or generation path.

### Chunk 5 — Devin OAuth callback, PKCE, and encrypted lifecycle

Implement `internal/oauth/devin`; generalize `internal/accounts/service.go` to provider-selected start/complete results; add provider-aware persisted callback sessions and expiry/relogin credential semantics. The authorization code is never persisted. Consume atomically returns the verifier only in memory while irreversibly clearing pending-secret access; `consumed` is non-retryable in-flight and may finalize only to completed or failed. Complete post-exchange account upsert/deduplication and `consumed -> completed` in one atomic store transaction; exchange or transactional failure finalizes the attempt failed without exposing a new account. Do not add management routes yet beyond testable service adapters.

Verification: OAuth unit/integration fixtures cover exact URLs/query/JSON, unique state/verifier shape, consume-before-exchange/replay, in-memory-only verifier return and pending-secret disposal, the exclusive `consumed -> completed|failed` finalizations, immutable completed/failed/expired/cancelled states, restart recovery of consumed as failed without re-exchange, expiry, redirects disabled, wrong provider, and callback-code absence from account/session rows and DB/WAL/SHM after success and every failure. Inject exchange, account-write, session-completion, commit, and failure-finalization interruptions plus restart at each boundary; every reported failure leaves no newly persisted usable token/account and no retryable attempt, success is visible only after the atomic account-plus-completion commit, and a pre-existing deduplicated account remains intact.

Rollback/risk: callback and token exchange remain disabled in runtime until config and management wiring are complete. Any uncertain public origin, host policy, or post-exchange atomicity fails closed.

### Chunk 6 — Devin protocol bootstrap and request builder

Port only required protobuf contracts and implement token normalization, metadata, `GetUserJwt`, custom-base validation, and canonical-to-`GetChatMessage` construction. Add provenance/license notices required by the source license; do not copy the standalone gateway HTTP/auth/token-file stack.

Verification: exact unary path/headers/protobuf fixtures; empty JWT/custom host rejection; model UID pass-through; messages/tools/images/default stops/IDs; `none`/`auto`/selected mapping unchanged; parallel tools disabled.

Rollback/risk: source/protobuf licensing is a hard entry gate. If reuse terms cannot be verified, this chunk is blocked until a legally acceptable generation source or clean-room wire definition is approved.

### Chunk 7 — Devin Connect stream, neutral events, and per-response usage

Implement compressed Connect request frames, bounded response-frame decoding, trailer/error handling, canonical event mapping, actual model, stop reasons, context cancellation, and per-response usage. Reuse shared non-stream buffering and stream commitment rules. Source-compatible clean EOF succeeds exactly when reading a fresh five-byte frame header returns zero bytes after zero or more complete frames; empty-stream EOF and EOF between complete frames therefore run normal mapper finalization, which may synthesize final stops. EOF after 1–4 header bytes or before the full declared payload is read is truncation and returns a sanitized upstream protocol error. Malformed end-stream JSON remains an explicit intentional hardening and is rejected.

Verification: byte-level framing tests, raw/gzip multi-frame streams, delta/cumulative tool arguments, clean empty EOF, clean EOF between complete frames, partial-header truncation, partial-payload truncation, malformed-trailer/error cases, first-event flush, pre/post-commit failures, and local input/output/cache-read accounting.

Rollback/risk: configured frame/stream/tool/non-stream limits and malformed trailers/truncation must fail safely; no upstream payload is logged. Cache-write/credit/quota data remains ignored.

### Chunk 8 — Provider-aware refresh, discovery, and usage workers

Update `internal/accounts/refresh_worker.go`, `internal/models/worker.go`, `internal/usage/worker.go`, service projections, and tests to carry provider and dispatch optional capabilities. Implement optional Devin `GetCliModelConfigs` only as a hardcoded-set capability overlay. Do not implement account statistics or quota RPCs.

Verification: xAI refresh/billing unchanged; Devin expiry becomes relogin; no Devin credential reaches xAI endpoints; discovery cannot expose a fourth Devin model; unavailable discovery/quota is represented safely; workers remain bounded/restart-safe.

Rollback/risk: required routing cannot depend on dynamic discovery. The optional adapter can be disabled without removing the three static model definitions.

### Chunk 9 — Final runtime composition and end-to-end model dispatch

Rewrite `internal/app/runtime.go` composition to add Devin capabilities beside the generation-complete xAI capabilities in one immutable runtime `CapabilityRegistry`; inject the already-constructed Chunk 2 static `ModelCatalog` into account/model/usage/routing services without reconstructing or registering model entries. Update readiness/public catalog and runtime tests.

Verification: capability-construction tests reject missing required capabilities and permit absent optional ones; fake-provider end-to-end requests cover Chat, Responses, and Anthropic in stream/non-stream modes, exact provider selection for all five static names, no cross-provider calls, default-model readiness, and managed Responses affinity. Static catalog duplicate-name behavior remains exclusively owned by Chunk 2.

Rollback/risk: both the static model catalog and runtime capability registry are immutable after startup and remain distinct. Chunk 9 must not rebuild model ownership or duplicate static model-registration tests; missing required runtime capabilities fail startup rather than selecting a provider by order.

### Chunk 10 — Admin REST, Web UI, and CLI flows

Update `internal/api/admin/handler.go`, `internal/web/services.go`, `internal/web/oauth.go`, `internal/app/web.go`, templates, `cmd/byos/main.go`, and tests. Add Devin start/callback plus authenticated status/cancel routes keyed by OAuth session ID, relogin UX, provider labels and filters; keep xAI device routes intact.

Verification: admin auth/throttle/no-store allowlists, callback state-only authorization, unknown-session not-found behavior, concurrent session-ID status/cancel isolation, Web CSRF/trusted-proxy behavior, restart/resume, CLI provider selection/default, provider-safe account/model/usage projections, and secret scans of responses/rendered HTML.

Rollback/risk: callback is the only unauthenticated management-adjacent route and must remain narrowly registered. Session operations may affect only the path-keyed session ID. Frozen Web hooks and destructive-action confirmation remain unchanged.

### Chunk 11 — Deployment documentation, inventory, and attribution

Update `README.md`, configuration examples, Compose/Railway guidance where applicable, license/notice material, and route/config inventories. Document the already-shipped locked transport settings from Chunk 2, explicit HTTPS callback origin, persistent `/data`, stable `BYOS_MASTER_KEY`, single replica, relogin on Devin expiry, static model ownership, xAI-only search, and absence of a Devin token environment variable. Chunk 11 does not define or change transport-limit semantics.

Verification: config parse/startup smoke scenarios using the existing settings, route inventory, secret/example scan, container restart with persisted provider rows and OAuth lifecycle, and documentation/source-license review.

Rollback/risk: no new long-lived deployment secret or late configuration contract is introduced. Public callback construction never depends on proxy headers.

### Chunk 12 — Final security, regression, and acceptance

Run focused then full automated gates, race checks for lifecycle/routing, local fake-provider smoke, database restart/backup migration scenario, route/non-goal inventory, and source/scope/license review. Live OAuth/provider acceptance is separately recorded if credentials and operator approval exist; lack of live credentials must not weaken deterministic local acceptance.

Verification: commands and deterministic scenarios in the checklist all pass; every non-live item is checked; any remaining unchecked item is only an explicitly identified credential/approval-blocked live-provider scenario recorded without claiming success; no other blocked decision remains; only the required providers/models/routes are exposed.

Rollback/risk: final acceptance must verify a v4 database can upgrade and the service can be restored from the pre-upgrade backup. Do not attempt schema downgrade in place.

## Security invariants

1. OAuth start/status/cancel require administrator authentication; Web mutations require CSRF. The Devin callback is authorized only by unpredictable, provider-bound, unexpired, single-use state and encrypted PKCE material.
2. State is consumed before exchange. The atomic `pending -> consumed` mutation returns the verifier only in memory and removes durable pending-secret access. Consumed is irreversible, non-retryable in-flight and may finalize only to completed or failed; completed, failed, expired, and cancelled are immutable. Unknown, expired, replayed, cancelled, final, missing-verifier, or wrong-provider state performs no exchange and persists no token.
3. Callback URLs come only from validated configuration. Request `Host`, `X-Forwarded-Host`, and `X-Forwarded-Proto` never construct OAuth redirects.
4. Exchange and runtime credential requests require HTTPS, bounded timeouts, redirect refusal, and secret-free errors. Custom Devin chat bases require explicit validated host policy.
5. Devin token, user JWT, OAuth code/raw state/verifier/redirect payload, xAI tokens, admin credentials, downstream keys, prompts, and raw usage never appear in logs, API projections, rendered HTML, or plaintext SQLite/WAL/SHM. Raw state, callback code, and per-request user JWT are absent from durable rows entirely; consume clears or cryptographically invalidates encrypted pending verifier/redirect material before returning the verifier only to memory, and completed/failed/expired/cancelled sessions retain no decryptable pending material.
6. BYOS AES-256-GCM envelopes and domain-separated keys remain the only credential/session persistence for fields that are genuinely durable. Encryption never justifies retaining ephemeral secrets; the source gateway's plaintext `token.json` store is not imported.
7. xAI refresh and Devin relogin semantics never cross. xAI billing/model endpoints never receive a Devin credential.
8. Account provider filtering occurs before capability fallback, cooldown ordering, affinity, or failover. A request never changes provider after model resolution.
9. xAI `x_search` and `none -> auto` remain xAI-only. Devin receives no injected search and preserves explicit `none`, `auto`, and selected tool.
10. Model listing exposes only configured models routable through an enabled usable account whose `account.provider` equals `ResolvedModel.Provider`. `OwnedBy` is response metadata only; Devin is not gated by xAI backend-search capability, and `grok` remains routable through an xAI account despite `OwnedBy=byos`.
11. Per-response usage is account/provider local and sanitized. Unsupported Devin quota is `unavailable`, not zero and not an xAI-shaped estimate.
12. Single-process deployment remains required; no claim of multi-replica-safe state consumption, refresh, SQLite, or scheduling is introduced.

## Explicit decisions and blocked gates

| ID | Decision/gate | Resolution |
|---|---|---|
| D-1 | Stable Devin identity is not source-supported. | Fingerprint the opaque token; identical token deduplicates, rotated/new token creates a new account. Document operator cleanup. Do not trust unverified JWT identity claims. |
| D-2 | Devin refresh token/endpoint is absent. | No refresh. Expiry and 401/403 produce relogin-required. |
| D-3 | Dynamic Devin discovery is implemented in the source but required IDs are not source constants. | Static ownership is required. Optional discovery only confirms the three IDs and cannot expand `/v1/models`. |
| D-4 | Devin account quota/statistics are not implemented in the source. | Excluded. Only per-response token usage is integrated. |
| D-5 | Public names must be unique without rejecting valid aliases. | The immutable static catalog rejects duplicate public names and ambiguous reuse of one canonical upstream name across different provider/policy identities, while allowing `grok` and `grok-4.5` to share canonical xAI upstream `grok-4.5`. The separate runtime capability registry rejects duplicate provider/policy keys. `OwnedBy` is listing metadata, never a routing key; no provider-qualified names or conflict-resolution schema/UI. |
| B-1 | License/provenance for copied/generated Devin protobuf and runtime code must be verified before Chunk 6. | Hard blocker for Chunk 6. Record exact source revision and required notices; otherwise obtain an approved clean-room/generation source. |
| B-2 | Live xAI/Devin OAuth credentials and operator approval may be unavailable. | Not a blocker for deterministic implementation acceptance. Record live scenarios separately as blocked with exact missing credentials/approval; never mark them passed from fake fixtures. |

The four unchecked historical `init.todo.md` blockers remain separately open: `Initialize the Go module and pin dependencies`; `Perform live OAuth and x_search acceptance with two accounts`; `Perform live failover and restart acceptance`; and `Complete final source and license review`. Devin tracker item C12.5 cannot satisfy, combine, check, or close any of them.

## Final acceptance

The implementation is accepted only when:

- all deterministic and non-live items in [`devin-provider.todo.md`](./devin-provider.todo.md) are checked; only an explicitly credential/approval-blocked live-provider item may remain unchecked and identified without masking automated acceptance;
- a migrated xAI account still serves both public `grok` and `grok-4.5` through their shared canonical xAI upstream `grok-4.5` with mandatory x_search; duplicate public names and ambiguous canonical provider-model registrations fail while this valid alias pair succeeds;
- each required Devin model serves through a Devin account with no x_search and unchanged explicit `none`/`auto`/selected tool choice across Chat, Responses, and Anthropic;
- unknown capability state, affinity, cooldown, 401/403, 429, transient failures, and streaming commitment never produce cross-provider calls;
- model routability and every account choice use `ResolvedModel.Provider == account.provider`; `OwnedBy` remains metadata, including a positive `grok` (`OwnedBy=byos`) request through an xAI account;
- Devin OAuth survives restart, rejects replay/wrong-provider/expired state, consumes pending state irreversibly before exchange while returning the verifier only in memory and clearing pending-secret access, permits only `consumed -> completed|failed`, keeps completed/failed/expired/cancelled immutable, commits account plus completion atomically, leaves failures non-retryable with no newly persisted usable account, and leaves raw state, callback code, and per-request user JWT absent from account/session rows and DB/WAL/SHM;
- xAI billing/refresh remain xAI-only, Devin per-response usage reaches local counters, and unsupported Devin quota is explicit;
- CLI, Admin REST, and Web UI can start and observe both provider login types; Devin status/cancel are session-ID keyed and isolated; all views display provider-safe account/model/usage state;
- configuration/deployment/docs/attribution match the shipped behavior, with no Devin token environment variable and no historical plan edits or closure of the four separate historical blockers.
