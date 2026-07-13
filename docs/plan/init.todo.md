# Todo List

## Locked decisions

- Go 1.26 single-process service; persistence uses encrypted SQLite and does not support multi-instance coordination.
- Single-tenant account pool: all downstream client API keys share the same enabled xAI OAuth accounts.
- Public compatibility surface is limited to `GET /v1/models`, `POST /v1/chat/completions`, `POST /v1/responses`, `POST /v1/messages`, and `POST /v1/messages/count_tokens`.
- HTTP non-stream and SSE stream are required. Legacy `/v1/completions`, Responses WebSocket/compact, media APIs, response retrieve/delete, and built-in public TLS are out of scope.
- OAuth uses xAI OIDC discovery and RFC 8628 device flow. CLI login, admin REST, and Web UI use the same OAuth/account service.
- Multiple accounts use model-aware round-robin scheduling with persisted cooldowns and failover. Billing usage is informational and does not weight routing.
- Every generated upstream Responses payload must contain `{"type":"x_search"}`. Existing x_search configuration is preserved, duplicates are forbidden, and `tool_choice:"none"` is rewritten to `"auto"`. No request-level or global opt-out exists.
- OpenAI Responses preserves native `x_search_call`, annotations, citations, and SSE events. Chat Completions and Anthropic Messages remain standard-compatible and expose search sources through inline citation text only.
- The stable public alias `grok` maps to `grok-4.5`. The default model allowlist contains `grok-4.5`; `/v1/models` returns only allowlisted, routable models.
- Model discovery uses `/models-v2`, falls back to `/models`, then falls back to the configured allowlist while retaining stale successful snapshots.
- Responses state is proxy-managed. `store` defaults to true, retained sessions expire after 30 days, and `store:false` responses cannot be used through `previous_response_id`.
- OAuth credentials, response transcripts, identity fields, and raw billing snapshots are encrypted with AES-256-GCM using subkeys derived from `SUPERGROK_MASTER_KEY`.
- Downstream API keys are generated and revoked through the management surface, shown once, and stored only as hashes.
- Admin REST uses a separate bearer key. Web UI uses an administrator password, server-side sessions, HttpOnly SameSite cookies, and CSRF protection.
- Default host binding is `127.0.0.1:8080`. Docker publishes `127.0.0.1:8080:8080`; remote TLS termination belongs to a trusted reverse proxy or private overlay network.
- Web UI uses `html/template`, embedded static assets, and minimal native JavaScript; no SPA toolchain is introduced.
- Extracted CLIProxyAPI code retains MIT attribution and is limited to xAI OAuth, Responses execution, scheduling concepts, and the three required translators.

## Implementation tasks

### Foundation and configuration

- [ ] Initialize the Go module and pin dependencies
  - Create `go.mod` for the `supergrok-api` module with Go 1.26.
  - Pin the selected packages: `modernc.org/sqlite v1.53.0`, `github.com/coreos/go-oidc/v3 v3.20.0`, `github.com/gorilla/csrf v1.7.3`, `github.com/tidwall/gjson v1.18.0`, `github.com/tidwall/sjson v1.2.5`, `github.com/tiktoken-go/tokenizer v0.7.0`, `golang.org/x/oauth2 v0.30.0`, `golang.org/x/sync v0.18.0`, and `gopkg.in/yaml.v3 v3.0.1`.
  - Definition of done: `go mod tidy` resolves reproducibly and the empty command package builds with Go 1.26.

- [x] Create the service package boundaries
  - Create `cmd/supergrok-api`, `internal/app`, `internal/config`, `internal/store`, `internal/crypto`, `internal/oauth/xai`, `internal/xai`, `internal/accounts`, `internal/routing`, `internal/models`, `internal/usage`, `internal/sessions`, `internal/search`, `internal/translate`, `internal/api`, and `internal/web`.
  - Add command dispatch placeholders for `serve`, `login`, and `version`; placeholders may only parse commands and return explicit not-initialized errors until their implementation tasks are completed.
  - Definition of done: package imports are acyclic and `go test ./...` compiles the scaffold.

- [x] Implement YAML configuration and fixed defaults
  - Add `internal/config/config.go` and focused tests.
  - Define `server.listen`, `data_dir`, upstream base URL, Grok client version, model default/aliases/allowlist, request timeout, SSE idle timeout, maximum body size, usage refresh interval, and Responses retention.
  - Lock defaults to `127.0.0.1:8080`, `https://cli-chat-proxy.grok.com/v1`, Grok client `0.2.99`, model `grok-4.5`, alias `grok`, 16 MiB request bodies, five-minute usage refresh, and 30-day session retention.
  - Reject configuration that attempts to remove mandatory x_search behavior or exceeds the locked single-instance scope.
  - Definition of done: default config and YAML overrides round-trip in tests, invalid durations/sizes/model aliases fail at startup, and secrets never appear in serialized config output.

- [x] Enforce startup secret validation
  - Add secret loading to `internal/config/secrets.go`.
  - Require `SUPERGROK_MASTER_KEY` as exactly 32 decoded bytes, `SUPERGROK_ADMIN_PASSWORD`, and `SUPERGROK_ADMIN_API_KEY`.
  - Accept secrets from environment variables or mounted secret files without copying them into logs or config dumps.
  - Definition of done: missing/malformed secrets fail closed with non-secret error messages; valid values are available only through secret-specific accessors.

- [x] Build application lifecycle and structured logging
  - Add `internal/app/app.go`, `internal/app/lifecycle.go`, and `internal/app/logging.go`.
  - Use `log/slog`, attach request IDs and opaque account IDs, and disable prompt/response body logging by default.
  - Wire root context cancellation, worker shutdown, HTTP graceful shutdown, finite SSE drain, and SQLite close/checkpoint ordering.
  - Definition of done: SIGTERM stops new traffic, cancels workers/upstream requests, drains active handlers within the configured deadline, and exits without goroutine leaks in tests.

### SQLite and cryptography

- [x] Implement SQLite bootstrap and embedded migrations
  - Add `internal/store/sqlite.go`, `internal/store/migrate.go`, and `migrations/*.sql` embedded into the binary.
  - Enable WAL, foreign keys, busy timeout, and restrictive data-directory/file permissions.
  - Create `schema_migrations`, `accounts`, `account_model_capabilities`, `account_model_states`, `oauth_sessions`, `usage_snapshots`, `api_keys`, `response_sessions`, and `admin_sessions`.
  - Definition of done: a fresh database reaches the latest schema atomically, rerunning migrations is idempotent, and migration failure rolls back without a partial schema.

- [x] Implement versioned encryption envelopes
  - Add `internal/crypto/keys.go` and `internal/crypto/envelope.go`.
  - Derive separate OAuth, transcript, billing, identity-fingerprint, and web-session keys with HKDF-SHA256.
  - Encrypt sensitive values with AES-256-GCM using a fresh random nonce per value and a versioned binary/text envelope.
  - Definition of done: round-trip, tamper, wrong-key, nonce-uniqueness, empty-value, and malformed-envelope tests pass; decryption failures never return partial plaintext.

- [x] Implement account persistence
  - Add `internal/store/accounts.go` and account storage types.
  - Encrypt access, refresh, ID tokens, email, subject, token endpoint metadata, and any raw identity claims.
  - Generate the account uniqueness fingerprint as `HMAC(identity_key, issuer + "\x00" + subject)`; relogin updates the existing account while preserving its stable ID and label unless explicitly changed.
  - Persist enabled/status/expiry/last-refresh/last-error timestamps without storing raw tokens in searchable columns.
  - Definition of done: account CRUD and relogin tests pass, duplicate subject records cannot be created, and a raw database byte scan cannot find fixture credentials.

- [x] Implement model capability and cooldown persistence
  - Add `internal/store/model_capabilities.go` and `internal/store/cooldowns.go`.
  - Persist per-account model support, backend-search capability, context/max-output metadata, discovery freshness, cooldown deadline, backoff level, and last classified error.
  - Definition of done: model/cooldown state survives database close/reopen and expired cooldowns are promoted back to ready state deterministically.

- [x] Implement encrypted OAuth-session persistence
  - Add `internal/store/oauth_sessions.go`.
  - Store state hash, encrypted device code, user code, verification URLs, token endpoint, poll interval, expiry, status, and sanitized error.
  - Ensure expired, completed, cancelled, and failed sessions cannot be resumed as pending.
  - Definition of done: a pending device flow survives simulated service restart and resumes polling; terminal sessions are immutable and cleaned after retention.

- [x] Implement encrypted usage snapshot persistence
  - Add `internal/store/usage.go`.
  - Store normalized monthly/weekly fields, local counters, fetched time, stale/error state, and encrypted raw payloads.
  - Definition of done: latest snapshot lookup, stale fallback, encrypted raw-data retrieval for internal diagnostics, and retention cleanup pass tests.

- [x] Implement encrypted Responses-session persistence
  - Add `internal/store/responses.go`.
  - Store response ID, previous ID, model, preferred account, encrypted canonical input/output, store flag, creation time, and expiry.
  - Add indexed lookups for response ID, previous chain traversal, and expiry cleanup.
  - Definition of done: response nodes survive restart, expired nodes are unavailable, and database bytes do not contain fixture prompts or model outputs.

### Client and administrator authentication

- [x] Implement downstream API-key generation and storage
  - Add `internal/accounts/apikeys.go` and `internal/store/api_keys.go`.
  - Generate at least 32 random bytes, encode a recognizable public prefix, return plaintext only from the create operation, and store prefix plus SHA-256 hash.
  - Record label, creation, last-use, and revocation timestamps.
  - Definition of done: duplicate hashes are impossible, revoked keys fail immediately, last-use updates are rate-limited to avoid a write per request, and no API lists plaintext keys.

- [ ] Implement public bearer authentication middleware
  - Add `internal/api/middleware/client_auth.go`.
  - Authenticate all `/v1/*` routes using non-revoked downstream keys and constant-time comparison.
  - Keep `/healthz` and `/readyz` unauthenticated while preventing them from returning account details.
  - Definition of done: missing, malformed, unknown, and revoked keys return standard 401 responses; valid keys attach only the key ID/label to request context.

- [ ] Implement admin REST bearer authentication
  - Add `internal/api/middleware/admin_auth.go`.
  - Validate `SUPERGROK_ADMIN_API_KEY` in constant time and apply it to `/admin/api/v1/*`.
  - Definition of done: the management API cannot be accessed with downstream client keys, and admin failures do not reveal whether a candidate key prefix was valid.

- [ ] Implement Web UI sessions and CSRF protection
  - Add `internal/web/auth.go`, `internal/store/admin_sessions.go`, and Gorilla CSRF middleware setup.
  - Validate the administrator password without logging it, issue random server-side sessions, and set HttpOnly/SameSite=Strict cookies; set Secure when the request came through a configured trusted HTTPS reverse proxy.
  - Expire and revoke sessions server-side; protect every mutation with CSRF.
  - Definition of done: login/logout/session-expiry/CSRF/cookie tests pass, and spoofed forwarded headers from untrusted peers cannot enable secure-proxy behavior.

### xAI OAuth

- [ ] Port and centralize xAI OAuth constants
  - Add `internal/oauth/xai/constants.go` using the issuer, discovery URL, public client ID, scopes, RFC 8628 grant type, poll minimum, refresh lead, and maximum flow duration extracted from CLIProxyAPI.
  - Keep client ID/scopes overrideable through deployment configuration but never through downstream requests.
  - Definition of done: defaults match the reference implementation and are used by both CLI and management login flows.

- [ ] Implement secure OIDC discovery
  - Add `internal/oauth/xai/discovery.go`.
  - Fetch the discovery document with bounded timeout and proxy-aware HTTP transport.
  - Require HTTPS and an `x.ai` or subdomain hostname for device, token, authorization, and JWKS endpoints.
  - Definition of done: valid discovery is cached safely; empty, malformed, HTTP, redirect-to-foreign-host, and non-xAI endpoints are rejected in tests.

- [ ] Implement RFC 8628 device authorization start
  - Add `internal/oauth/xai/device.go`.
  - POST client ID and scopes to the discovered device endpoint, validate required response fields, persist the pending session, and return state/user code/verification URL/expiry.
  - Prefer `verification_uri_complete` for UI/CLI display while retaining `verification_uri` and user code.
  - Definition of done: CLI and admin API receive the same normalized device-flow object and no device code is exposed to browsers or logs.

- [ ] Implement device-token polling and cancellation
  - Add `internal/oauth/xai/poll.go`.
  - Poll immediately once, enforce a minimum five-second interval, add five seconds for `slow_down`, and terminate on authorization denial, expiry, cancellation, or context shutdown.
  - Persist status transitions so service restart resumes only still-valid pending sessions.
  - Definition of done: pending/slow-down/success/denied/expired/cancel/restart tests pass without duplicate poll workers.

- [ ] Verify ID tokens and normalize account identity
  - Add `internal/oauth/xai/identity.go` using `go-oidc` remote key verification.
  - Validate signature, issuer, audience, expiry, and nonce/state linkage where applicable before using email/sub.
  - Refuse to persist an account without a stable verified subject.
  - Definition of done: valid signed fixtures pass; forged signature, wrong issuer/audience, expired token, missing subject, and key-rotation fixtures fail safely.

- [ ] Implement refresh-token rotation and background refresh
  - Add `internal/oauth/xai/refresh.go` and `internal/accounts/refresh_worker.go`.
  - Refresh five minutes before expiry, use singleflight per account, preserve the old refresh token when the response omits a replacement, and atomically persist rotated tokens.
  - Retry once on upstream 401 with a synchronous refresh; classify `invalid_grant` as requiring relogin.
  - Definition of done: concurrent refresh produces one token request, token rotation is atomic, and invalid grants disable the account without affecting other accounts.

- [ ] Implement account service orchestration
  - Add `internal/accounts/service.go`.
  - Coordinate OAuth completion, relogin deduplication, account enable/disable/delete, manual refresh, capability refresh, usage refresh, and status projection for APIs/UI.
  - Ensure deletion removes credentials/capabilities/cooldowns while leaving encrypted response transcripts usable for failover reconstruction.
  - Definition of done: all management surfaces call this service rather than repositories or OAuth clients directly.

### xAI upstream adapters

- [ ] Implement the proxy-aware xAI HTTP transport
  - Add `internal/xai/http.go` and `internal/xai/headers.go`.
  - Honor standard `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`; set connection pooling and the configured request/SSE idle timeouts.
  - Apply `Authorization`, `Content-Type`, `Accept`, `X-XAI-Token-Auth`, `x-grok-client-version`, `x-grok-model-override`, and project User-Agent centrally.
  - Definition of done: inference, model, and billing adapters cannot construct ad hoc authentication headers, and tests assert no credential header is logged.

- [ ] Implement a strict reusable SSE parser
  - Add `internal/xai/sse.go`.
  - Support comments, event names, multiple data lines, blank-line event termination, large events, EOF, idle timeout, and cancellation without `bufio.Scanner`'s default token cap.
  - Preserve unknown event payloads for the Responses compatibility path.
  - Definition of done: fragmented network reads and events larger than 64 KiB parse correctly and cancellation closes the upstream body promptly.

- [ ] Implement the xAI Responses executor
  - Add `internal/xai/responses.go`.
  - Always send upstream `stream:true` and `store:false` to `POST /responses`.
  - For non-stream requests, collect events through `response.completed`; fail if the stream ends before a terminal event.
  - For stream requests, expose parsed events without committing downstream output until the first valid event is available.
  - Definition of done: executor tests cover success, non-2xx error body, missing terminal event, cancellation, large events, and response headers.

- [ ] Implement model catalog discovery
  - Add `internal/models/upstream.go`, `internal/models/catalog.go`, and `internal/models/types.go`.
  - Call `GET /models-v2` first. On 2xx accept either an array or `{models:[...]}` and normalize `id`/`model`, display name, context window, max completion tokens, reasoning efforts, and `supportsBackendSearch`.
  - On `/models-v2` 404 or an unrecognized successful schema, call `GET /models`. Treat 401/403 as credential failure rather than catalog absence.
  - When both endpoints are unavailable, retain the last successful per-account snapshot as stale; without a snapshot, route from the configured allowlist.
  - Definition of done: final public catalog equals the allowlist intersected with support from at least one enabled account when fresh/stale capabilities exist, and otherwise equals the allowlist with alias resolution.

- [ ] Implement model-catalog refresh workers
  - Add `internal/models/worker.go`.
  - Refresh after account login, token refresh, service startup, explicit admin refresh, and the configured periodic interval.
  - Deduplicate concurrent refreshes per account and record last success/error/freshness.
  - Definition of done: refreshes never block inference startup indefinitely, stale catalog data remains queryable, and `/readyz` reflects whether the default model is routable.

- [ ] Implement the OAuth billing adapter
  - Add `internal/usage/xai_billing.go` and strict payload parsers.
  - Fetch `/billing?format=credits` for weekly/current-period data and `/billing` for monthly limit/used/reset data.
  - Normalize monthly remaining and weekly remaining percentage; preserve on-demand/prepaid fields only when present in validated upstream data.
  - A failed refresh must return the last snapshot with `stale:true`; no snapshot produces `unknown` fields without blocking inference.
  - Definition of done: monthly, weekly, combined, malformed, changed-type, 401, 429, and network-error fixtures pass.

- [ ] Implement usage refresh and local counters
  - Add `internal/usage/service.go` and `internal/usage/worker.go`.
  - Refresh each enabled account every five minutes and on explicit admin request with bounded concurrency.
  - Record local requests, failures, input tokens, and output tokens separately from upstream subscription usage.
  - Never aggregate weekly percentages across accounts and never make routing choices from billing snapshots.
  - Definition of done: usage worker cancellation/restart/stale behavior passes tests and local counters survive restart.

### Protocol translation and mandatory search

- [ ] Create the minimal translator registry and common types
  - Add `internal/translate/registry`, canonical format constants, request/response transform interfaces, stream state types, and shared SSE helpers.
  - Extract only the required common code from CLIProxyAPI and retain source/license comments.
  - Definition of done: transforms can be registered for Chat, Responses, and Anthropic without importing CLIProxyAPI as a Go module.

- [ ] Extract OpenAI Chat Completions translation
  - Add `internal/translate/openai/chatcompletions/request.go`, `response.go`, and focused fixtures derived from CLIProxyAPI.
  - Preserve roles, multimodal text/image inputs, client function calls/results, reasoning summary, usage, finish reason, structured output fields supported by the reference, and tool-name shortening/restoration.
  - Ignore server-side x_search call progress as client tool calls while retaining final text and inline citation links.
  - Definition of done: stream and non-stream Chat payloads match OpenAI-compatible fixtures, and built-in search never yields `finish_reason:"tool_calls"` unless a real client-side function call exists.

- [ ] Extract OpenAI Responses translation
  - Add `internal/translate/openai/responses/request.go` and `response.go`.
  - Normalize string input, system/developer roles, unsupported upstream fields, and canonical Responses request shape.
  - Preserve native `x_search_call`, output annotations, citations, usage, IDs, and unknown server-side events in both stream and non-stream modes.
  - Definition of done: Responses fixtures round-trip without dropping x_search metadata or adding Chat-specific `[DONE]` markers.

- [ ] Extract Anthropic Messages translation
  - Add `internal/translate/anthropic/request.go`, `response.go`, `count_tokens.go`, and stream state helpers.
  - Preserve system/messages/content blocks, client tools/results, thinking summary, usage, stop sequences, and Anthropic SSE ordering.
  - Treat x_search as an internal server-side operation: do not synthesize `server_tool_use`, `web_search_tool_result`, or client `tool_use`; return final inline-cited text with `stop_reason:end_turn`.
  - Definition of done: Messages stream/non-stream fixtures validate message_start/content blocks/message_delta/message_stop ordering and correct stop reason.

- [ ] Implement mandatory x_search injection
  - Add `internal/search/inject.go` and a table-driven invariant suite.
  - Append `{"type":"x_search"}` when absent, preserve an existing x_search tool and all supported filters, reject duplicate reconstruction, and rewrite `tool_choice:"none"` to `"auto"`.
  - Preserve absent/auto/required and explicitly selected non-search function/tool choices while keeping x_search in the tool list.
  - Do not expose any configuration or request mechanism that disables injection.
  - Definition of done: every canonical request accepted by the executor contains exactly one x_search tool, and an executor precondition fails internally before network I/O when this invariant is violated.

- [ ] Implement Anthropic input token counting
  - Add deterministic canonicalization and tokenizer integration in `internal/translate/anthropic/count_tokens.go`.
  - Count the translated request including the mandatory x_search declaration and return the standard Anthropic `input_tokens` shape.
  - Document through the response behavior and tests that this is a compatibility estimate rather than provider billing authority.
  - Definition of done: repeated equivalent requests return stable counts and malformed input uses Anthropic-standard validation errors.

### Managed Responses state

- [ ] Implement response-chain reconstruction
  - Add `internal/sessions/service.go` and `internal/sessions/reconstruct.go`.
  - Resolve `previous_response_id`, traverse newest-to-oldest with cycle detection, reverse the chain, and combine prior canonical request inputs and terminal outputs before appending current input.
  - Retain message, function call/output, reasoning summary, and encrypted reasoning content required for continuity; remove upstream `previous_response_id`.
  - Enforce 256 nodes and 64 MiB reconstructed payload limits.
  - Definition of done: text, tool-call, reasoning, account-failover, cycle, missing-node, expiry, and size-limit tests pass.

- [ ] Implement store and retention semantics
  - Treat omitted `store` as true; persist the completed node only after receiving a valid terminal response.
  - For `store:false`, do not create a `response_sessions` row; later continuation returns the standard `previous_response_not_found` error.
  - Expire stored nodes at 30 days and run hourly cleanup.
  - Definition of done: incomplete/failed responses are not persisted, successful chains survive restart, and expired/store-false IDs are unusable.

- [ ] Implement response account affinity with safe failover
  - Record the successful account on each stored response node.
  - Prefer that account for the next turn when healthy and model-capable; otherwise supply the reconstructed transcript to the normal scheduler.
  - Definition of done: healthy chains remain sticky, disabled/cooling/deleted accounts fail over without losing prior messages, and no upstream HTTP request contains the downstream `previous_response_id`.

### Routing, cooldowns, and execution

- [ ] Implement model-aware round-robin scheduling
  - Add `internal/routing/scheduler.go`.
  - Maintain a cursor per resolved upstream model, filter disabled/invalid/cooling/incompatible accounts, and attempt each candidate at most once per request.
  - Treat unknown model capability as fallback eligibility only when no known-compatible account is available.
  - Definition of done: deterministic cycle, concurrent access, account mutation, model-specific candidate, and affinity-preference tests pass without races.

- [ ] Implement upstream error classification
  - Add `internal/routing/errors.go`.
  - Classify validation/model errors, unauthorized/invalid-grant, payment/permission failures, exact free-usage exhaustion, generic 429, transient 408/5xx, connection setup failure, and client cancellation.
  - Parse `Retry-After` and the known `subscription:free-usage-exhausted` payload; use billing reset when available, otherwise 24 hours for exact free-usage exhaustion.
  - Definition of done: each class maps to the locked retry/cooldown/status behavior and sanitized public error.

- [ ] Implement persisted cooldown transitions
  - Add `internal/routing/cooldown.go`.
  - Use explicit Retry-After when present, exponential one-to-thirty-minute cooldown for generic 429, and 60 seconds for transient 408/500/502/503/504.
  - Disable accounts on invalid grant; apply quota/transient state at model scope unless the error is account-wide.
  - Definition of done: backoff progression, expiry promotion, successful recovery, restart restoration, and per-model isolation tests pass.

- [ ] Implement non-stream execution with failover
  - Add `internal/routing/execute.go`.
  - Resolve model/alias, refresh near-expiry credentials, prepare the canonical x_search request, execute, classify failures, and move to the next candidate only for retryable pre-output failures.
  - Retry a 401 once on the same account after refresh before rotating.
  - Definition of done: success, validation no-retry, refresh retry, multi-account 429/5xx failover, all-accounts-cooling, and cancellation tests pass.

- [ ] Implement stream execution commit boundaries
  - Add `internal/routing/stream.go`.
  - Buffer upstream status and the first valid SSE event before writing downstream headers/body.
  - Permit account failover only before the first downstream event; after commit, propagate protocol-safe error/closure and never replay on another account.
  - Definition of done: tests prove no duplicate text/tool calls across first-event-before/after failures and client cancellation closes the active upstream stream.

### Public compatibility API

- [ ] Implement protocol-specific error writers
  - Add `internal/api/errors/openai.go` and `internal/api/errors/anthropic.go`.
  - Map validation, authentication, model unavailable, cooldown, context limits, previous-response errors, upstream failures, and internal failures to standard status codes/bodies.
  - Include `Retry-After` on cooldown without leaking account identity or upstream credential details.
  - Definition of done: all handlers use these writers and error fixtures match the target protocol shapes.

- [ ] Implement health, readiness, and models handlers
  - Add `internal/api/system.go` and `internal/api/openai/models.go`.
  - `/healthz` reports process/database liveness only. `/readyz` reports ready only when the database is usable and at least one enabled account can serve the default model.
  - `/v1/models` returns only allowlisted/routable models and the stable `grok` alias without exposing per-account capabilities.
  - Definition of done: liveness stays healthy during upstream outages, readiness changes with account/model availability, and model listing honors stale/fallback catalog rules.

- [ ] Implement Chat Completions handler
  - Add `internal/api/openai/chat_completions.go`.
  - Enforce client auth/body limits/content type, translate to canonical Responses, inject x_search, resolve managed routing, and return standard stream/non-stream Chat output.
  - End streaming with `[DONE]` exactly once.
  - Definition of done: official-style OpenAI client fixtures can consume both modes, client disconnects cancel upstream, and citations remain in response text.

- [ ] Implement Responses handler
  - Add `internal/api/openai/responses.go`.
  - Enforce auth/body limits, managed `previous_response_id`, store semantics, mandatory x_search, native Responses stream/non-stream output, and persistence after terminal success.
  - Do not emit Chat `[DONE]` markers or implement retrieve/delete/WebSocket/compact routes.
  - Definition of done: OpenAI Responses client fixtures preserve x_search events/citations and multi-turn continuation works after service restart.

- [ ] Implement Anthropic Messages handlers
  - Add `internal/api/anthropic/messages.go` and `internal/api/anthropic/count_tokens.go`.
  - Validate required Anthropic headers/body, translate to canonical Responses, inject x_search, execute, and return standard Anthropic stream/non-stream output.
  - Return count-token estimates through `/v1/messages/count_tokens` using the same canonicalization path.
  - Definition of done: Anthropic SDK-compatible fixtures consume both endpoints and never receive a fake x_search client tool call.

- [ ] Register the locked HTTP route surface
  - Add `internal/api/server.go` with Go ServeMux method/path patterns.
  - Register only the locked public, health, admin API, and Web UI routes; unknown and explicitly out-of-scope routes return 404/405.
  - Apply request ID, panic recovery, size limit, client/admin auth, CSRF, and security-header middleware at the correct scopes.
  - Definition of done: a route inventory test proves no legacy completions, media, compact, WebSocket, or response retrieve/delete endpoint is exposed.

### Management REST and Web UI

- [ ] Implement OAuth management endpoints
  - Add `internal/api/admin/oauth.go` for `POST /oauth/xai/device`, `GET /oauth/xai/device/{state}`, and `DELETE /oauth/xai/device/{state}`.
  - Return only state, user code, verification URL, expiry, terminal status, account ID, and sanitized errors.
  - Definition of done: start/poll/cancel/restart flows work and device/access/refresh tokens never cross the admin API boundary.

- [ ] Implement account management endpoints
  - Add `internal/api/admin/accounts.go` for list, label/enabled patch, delete, and manual refresh.
  - Restrict PATCH to label and enabled; reject token/base-URL/model-state mutation attempts.
  - Definition of done: account status includes expiry/cooldown/capability/usage freshness without sensitive identity fields, and deletion semantics match stored-session failover rules.

- [ ] Implement usage and model management endpoints
  - Add `internal/api/admin/usage.go` and `internal/api/admin/models.go`.
  - Expose per-account normalized usage/local counters, aggregate account status without summing weekly percentages, model capabilities, stale state, and explicit refresh actions.
  - Definition of done: refresh calls are deduplicated/bounded, stale snapshots are returned with status metadata, and failures do not alter routing availability by themselves.

- [ ] Implement API-key management endpoints
  - Add `internal/api/admin/api_keys.go` for list, create, and revoke.
  - Show plaintext only in the create response and never again; list prefix/label/timestamps/revocation status.
  - Definition of done: create/list/revoke lifecycle works, response/log/database scans do not reveal previously issued plaintext keys, and revocation is immediately enforced.

- [ ] Build the Web UI layout and login flow
  - Add `internal/web/templates/layout.html`, `login.html`, embedded CSS, and auth handlers.
  - Include security headers, CSRF fields, session expiry handling, accessible form errors, and no localStorage secrets.
  - Definition of done: unauthenticated users are redirected to login, authenticated sessions can navigate the admin area, and logout revokes the server-side session.

- [ ] Build dashboard and account pages
  - Add templates/handlers for `/admin/`, `/admin/accounts`, and `/admin/accounts/{id}`.
  - Display readiness, account status, expiry, cooldown, model support, usage freshness, and safe enable/disable/delete/refresh actions.
  - Definition of done: UI actions call the same account service as REST, destructive deletion requires explicit confirmation, and no token/subject/raw billing payload is rendered.

- [ ] Build the OAuth device-flow page
  - Add `/admin/oauth/new` template, handler, and minimal JavaScript polling.
  - Display verification URL/user code/countdown, support cancellation, stop polling on terminal status, and redirect to account detail on success.
  - Definition of done: browser refresh resumes the persisted flow by state and concurrent pages cannot create duplicate account records.

- [ ] Build usage, models, and API-key pages
  - Add `/admin/usage`, `/admin/models`, and `/admin/api-keys` templates/handlers.
  - Show monthly/weekly/local usage separately, stale/error/fetched times, discovered model support, allowlist exposure, and one-time new-key display.
  - Definition of done: pages work without JavaScript except device polling and one-time key copy convenience, and no weekly percentages are aggregated incorrectly.

### CLI and runtime workers

- [ ] Implement `serve`, `login`, and `version` commands
  - Add command files under `cmd/supergrok-api` and reusable command logic under `internal/app`.
  - `serve` loads config/secrets/migrations/workers/server; `login` runs the same device/account service against the same SQLite database; `version` prints build version and Grok client profile version.
  - Definition of done: CLI login displays URL/code, handles cancellation, stores or updates the account, and does not require the HTTP server to be running.

- [ ] Implement periodic cleanup workers
  - Add `internal/app/cleanup_worker.go`.
  - Hourly delete expired response sessions, OAuth sessions, admin sessions, and usage raw snapshots beyond retention; promote expired cooldowns without deleting audit timestamps needed by the UI.
  - Definition of done: cleanup is idempotent, bounded, cancellation-aware, and covered with clock-controlled tests.

- [ ] Add Docker packaging and loopback-only Compose publishing
  - Create `Dockerfile`, `.dockerignore`, and `docker-compose.yml`.
  - Use a Go 1.26 multi-stage build and a non-root runtime with CA certificates; persist `/data`; add `/healthz` healthcheck.
  - Container may listen on `0.0.0.0:8080`, but Compose must publish `127.0.0.1:8080:8080`.
  - Definition of done: image builds without CGO, starts as non-root, writes only to `/data`, and is not reachable through the host's non-loopback interfaces by default.

- [ ] Preserve third-party license attribution
  - Add project `LICENSE` and `THIRD_PARTY_NOTICES` entries for extracted CLIProxyAPI and any extracted pi-grok-cli billing logic.
  - Keep source-level attribution comments on materially copied translator/OAuth sections.
  - Definition of done: attribution includes the upstream MIT notices and a reviewer can trace each extracted subsystem to its source path.

## Validation

- [ ] Run formatting, static checks, and focused package tests
  - Run `gofmt` over Go sources, `go vet ./...`, and `go test ./...`.
  - Definition of done: all commands pass from a clean checkout with no generated local state outside test temp directories.

- [ ] Run race detection for concurrent subsystems
  - Run `go test -race` on OAuth refresh, model/usage workers, scheduler, cooldown, API-key last-use updates, response-session reconstruction, and SSE cancellation packages.
  - Definition of done: no data races, leaked goroutines, or flaky cursor/refresh behavior across repeated runs.

- [ ] Validate OAuth behavior against a complete fake issuer
  - Use `httptest.Server` to simulate discovery, device authorization, token polling, refresh, JWKS rotation, denial, expiry, malformed endpoints, and invalid grants.
  - Definition of done: the device and refresh state machines pass every terminal path and never accept unverified identity data.

- [ ] Validate xAI adapters against fake upstream endpoints
  - Simulate `/models-v2`, `/models`, `/billing`, `/billing?format=credits`, and `/responses` with success, schema drift, 401, 429, 5xx, latency, fragmented SSE, and early/late disconnects.
  - Definition of done: discovery fallback, stale usage, SSE terminal detection, and error classification exactly match the locked rules.

- [ ] Validate mandatory x_search across all public protocols
  - Capture canonical upstream bodies for Chat Completions, Responses, and Anthropic Messages with absent tools, existing x_search filters, client functions, `tool_choice:none`, auto, required, and specific tool choices.
  - Definition of done: every accepted generation request contains exactly one x_search tool and none can disable it.

- [ ] Validate protocol stream and non-stream contracts
  - Test Chat `[DONE]`, Responses native events, Anthropic message event ordering, reasoning, client tool calls/results, token usage, finish/stop reasons, annotations, citations, and unknown server-side events.
  - Definition of done: standard SDK-style consumers parse every response and x_search never appears as a client-executed tool in Chat or Anthropic.

- [ ] Validate managed Responses continuation
  - Cover single/multi-turn text, function call outputs, encrypted reasoning replay, `store:false`, missing/expired IDs, 30-day cleanup, service restart, chain limits, cycle detection, and original-account failover.
  - Definition of done: continuation preserves semantic history without sending downstream `previous_response_id` to the HTTP CLI proxy.

- [ ] Validate multi-account scheduling and cooldowns
  - Use at least two fake accounts to test per-model round-robin, capability filtering, affinity preference, enable/disable/delete, 401 refresh, invalid grant, 429 Retry-After, free-usage exhaustion, transient cooldown, and all-accounts-unavailable responses.
  - Definition of done: each request attempts an account at most once and no post-commit stream is replayed on another account.

- [ ] Validate security and plaintext absence
  - Scan SQLite files, WAL files, logs, HTTP responses, rendered HTML, and crash/error messages using known fixture tokens, passwords, API keys, subjects, prompts, and billing payloads.
  - Definition of done: sensitive fixtures appear only in live in-memory test inputs and decrypted values explicitly requested by internal tests.

- [ ] Validate admin REST and Web UI security
  - Test separate admin/client keys, password login, HttpOnly/SameSite/Secure cookie behavior, trusted proxy handling, CSRF, session expiry/revocation, one-time key display, destructive-action confirmation, and unauthorized route access.
  - Definition of done: no management mutation succeeds without the correct admin authentication and CSRF context.

- [ ] Validate route inventory and non-goals
  - Enumerate registered routes and probe legacy completions, Responses WebSocket/compact/retrieve/delete, media, and tenant-management paths.
  - Definition of done: only the locked public/admin/UI/health routes exist; excluded routes return 404/405 and do not invoke upstream services.

- [ ] Run Docker smoke tests
  - Build the image, start Compose with a temporary data volume and test secrets, call `/healthz`, verify non-root UID and database persistence, restart, and verify loopback-only host publishing.
  - Definition of done: the container survives restart with persisted state and the published port is not bound to a public host interface.

- [ ] Perform live OAuth and x_search acceptance with two accounts
  - Login account A through CLI and account B through Web UI.
  - Refresh `/models-v2`/fallback catalogs and billing; save only scrubbed response fixtures.
  - Call Chat, Responses, and Anthropic endpoints with a query requiring current X posts; verify upstream x_search, Responses structured search/citations, and inline citations in Chat/Anthropic.
  - Definition of done: `grok` and `grok-4.5` are listed, both accounts route successfully, and at least one OAuth account/model completes native x_search through the CLI proxy.

- [ ] Perform live failover and restart acceptance
  - Verify round-robin across two accounts, disable account A, simulate or safely reproduce account B's retryable 429, and verify pre-stream failover plus `Retry-After` behavior.
  - Restart the service and verify accounts, usage, API keys, cooldowns, model snapshots, admin sessions policy, and Responses continuation restore correctly.
  - Definition of done: no request loses persisted state, no committed stream is duplicated, and unavailable-account errors use the correct public protocol shape.

- [ ] Complete final source and license review
  - Compare extracted OAuth/translator behavior with the named CLIProxyAPI source paths, remove unrelated provider/plugin/media/WebSocket code, and verify MIT notices.
  - Review logs, errors, UI, config examples, Docker files, and tests for accidental secrets or claims that billing data is official.
  - Definition of done: the repository contains only the locked scope, attribution is complete, and all validation items above are checked.