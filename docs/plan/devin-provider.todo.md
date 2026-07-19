# Devin Provider Implementation Tracker

> Architecture: [`devin-provider.plan.md`](./devin-provider.plan.md)
>
> Status: pre-implementation. Every implementation item is intentionally unchecked.
>
> Current next chunk: **Chunk 1 — Provider identity, neutral contracts, and schema migration**.
>
> Execution rule: items form one total order: each item depends on the immediately preceding item, chunks complete in numeric order, and the listed commit subject is used only after that chunk's observable definition of done passes. Do not edit the historical [`init.plan.md`](./init.plan.md) or [`init.todo.md`](./init.todo.md); its four unchecked blockers remain separately open and cannot be closed by this tracker.

## Locked implementation contract

- xAI owns `grok-4.5`; the public alias `grok` continues to resolve to it. xAI alone injects mandatory `x_search` and changes explicit `tool_choice:"none"` to `"auto"`.
- Devin owns exactly `kimi-k2-7`, `glm-5-2`, and `swe-1-6-slow`. Devin receives no injected search tool and preserves canonical absent/default, explicit `none`, `auto`, and selected-tool semantics.
- Model resolution uses an immutable static catalog before runtime capability lookup, provider request policy, model overwrite, account selection, credential handling, or transport dispatch. The executor owns the canonical request through one policy application and the `UpstreamName` overwrite; only the selected provider client marshals a wire payload, exactly once. Public names are unique, while valid aliases may share one canonical provider-model registration: `grok` and `grok-4.5` both map to `(grok-4.5,xai,xai)`. Reject duplicate public names and ambiguous canonical upstream reuse across different provider/policy identities, not alias projections. `OwnedBy` is public metadata only; routing requires `ResolvedModel.Provider == account.provider`.
- Existing accounts and OAuth sessions backfill to provider `xai`. Persist only real durable values: encrypted account credentials and, while pending, encrypted verifier/redirect/expiry material; plaintext lifecycle metadata contains only state hash/provider/flow/status/timestamps. Raw state, callback code, and per-request user JWT are never durable. Atomic consume irreversibly changes pending to non-retryable in-flight consumed, returns the verifier only in memory, and clears pending-secret access; consumed may finalize only to completed or failed, while completed/failed/expired/cancelled are immutable and retain no decryptable pending secrets. No plaintext token file or Devin token environment variable is introduced.
- Devin OAuth uses browser callback, provider-bound single-use state, S256 PKCE, opaque-token exchange, and relogin on expiry or upstream 401/403. Devin has no refresh path.
- Required Devin runtime behavior is `GetUserJwt` bootstrap followed by streamed `GetChatMessage`; non-stream responses buffer the same stream. Per-response input/output/cache-read usage is required.
- Devin model discovery is optional. C8.3 is completed either by implementing a bounded discoverer that can only intersect the fixed three-model set, or by explicitly recording omission and proving that no discoverer/stub is registered and the absent-capability path passes. Devin quota/statistics, capacity preflight, analytics, credit/ACU reporting, and usage-submission RPCs are out of scope.
- Routing, affinity, retry, cooldown, failover, model workers, usage workers, Admin REST, Web UI, CLI, and readiness must all carry or derive explicit provider identity. No request or worker operation may cross providers.

## Flat dependency-ordered tracker

- [ ] **C1.1 — Define provider kinds and resolved-model identity**
  - Chunk owner: **Chunk 1 — Provider identity, neutral contracts, and schema migration**.
  - Depends on: none.
  - Files: create `internal/provider` core files and focused tests.
  - Work: define closed `provider.Kind` values `xai` and `devin`; validation/parsing; `ResolvedModel` with public name, upstream name, provider, public owner, and stable policy key only. Keep provider strings stable because they are persisted; do not embed a concrete policy/client/capability object in static model identity.
  - Observable DoD: invalid/empty provider values fail deterministically; valid values round-trip through text/DB-facing representations; static resolved-model identity contains no runtime implementation and no concrete xAI or Devin package is imported by `internal/provider`.
  - Verification: focused `internal/provider` tests prove accepted/rejected stable provider values and neutral static resolved-model identity.

- [ ] **C1.2 — Define provider-neutral execution, credential, policy, discovery, and usage contracts**
  - Chunk owner: **Chunk 1**.
  - Depends on: C1.1.
  - Files: `internal/provider/*`; identify later shared call sites without cutting them over yet.
  - Work: define neutral event/stream, generation client, request policy, credential manager, sanitized upstream error/classification, optional model discoverer, optional usage fetcher, immutable static `ModelCatalog`, and separate immutable runtime `CapabilityRegistry` interfaces. Contracts must support stream commitment, `Retry-After`, cooldown scope, relogin-required state, per-response usage, and executor ownership of the canonical request until the selected generation client performs the sole provider-wire marshal, without importing `internal/xai`.
  - Observable DoD: fake providers implement required runtime capabilities; optional capabilities can be absent without fake no-ops; the static catalog contains only resolution data/policy keys; the runtime registry contains capabilities only; no concrete registration table or pre-marshaled/placeholder payload is built in Chunk 1.
  - Verification: compile-time fakes and focused behavior tests cover neutral contracts, absent optional capabilities, static/runtime separation, and one-owner/one-marshal payload semantics. Concrete static catalog construction and duplicate model-name tests are deferred exclusively to C2.2.

- [ ] **C1.3 — Add the ordered provider-identity migration**
  - Chunk owner: **Chunk 1**.
  - Depends on: C1.2.
  - Files: create `migrations/005_provider_identity.sql`; update migration-count/schema assertions only.
  - Work: add `accounts.provider` and `oauth_sessions.provider` as non-null durable routing keys, backfilled/defaulted to `xai`; add `oauth_sessions.flow_type`, backfilled/defaulted to `device`; add provider/status/flow indexes needed by resumable lifecycle queries. Use a SQLite table rebuild if necessary for effective constraints. Do not edit migrations 001–004.
  - Observable DoD: both fresh and populated v4 databases migrate atomically to v5; every legacy row reads `provider=xai`, every legacy OAuth row reads `flow_type=device`, IDs/foreign keys/status/timestamps/encrypted blobs are byte-preserved, and migration rollback leaves no partial schema.
  - Verification: extend `internal/store/sqlite_test.go` with fresh-schema and populated-v4 migration fixtures, foreign-key checks, migration count, and failure rollback.

- [ ] **C1.4 — Make account persistence provider-typed**
  - Chunk owner: **Chunk 1**.
  - Depends on: C1.3.
  - Files: `internal/store/accounts.go`, account repository callers/fixtures, persistence tests.
  - Work: add provider to account rows, scans, inserts/upserts, list/get projections, and credential updates. Require an explicit valid provider for new rows. Preserve the current xAI issuer/subject fingerprint behavior; add a provider-scoped identity-fingerprint input contract for later Devin use.
  - Observable DoD: xAI and Devin accounts round-trip provider across close/reopen; an update cannot change an account's provider accidentally; repository APIs never infer provider from model or token contents.
  - Verification: account CRUD/restart tests plus legacy-row migration coverage.

- [ ] **C1.5 — Make OAuth-session persistence provider- and flow-typed**
  - Chunk owner: **Chunk 1**.
  - Depends on: C1.4.
  - Files: `internal/store/oauth_sessions.go`, lifecycle tests, resumable-session callers.
  - Work: carry provider and `device|callback_pkce` through create/get/list/resume/consume/complete/fail/cancel operations; require provider-bound mutations and provider-filtered resumable queries; keep provider/flow/state hash/status/timestamps plaintext for restart dispatch while provider payload remains encrypted only while pending. Define atomic `pending -> consumed` to validate the attempt, decrypt and return the verifier only to caller memory, and clear or cryptographically invalidate encrypted pending verifier/redirect material. Treat consumed as irreversible, non-retryable in-flight with only `consumed -> completed|failed`; completed, failed, expired, and cancelled are immutable terminal states.
  - Observable DoD: restart dispatch can select the correct provider without decrypting every row; wrong-provider or wrong-flow completion/cancel/resume returns not-found/conflict and performs no mutation; consume exposes the verifier only in memory and cannot be replayed; consumed cannot return to pending or be cancelled/expired, only finalized completed or failed; completed/failed/expired/cancelled expose no decryptable pending secret and reject every mutation.
  - Verification: extend `internal/store/oauth_sessions_lifecycle_test.go` for both flow types, restart, atomic verifier-returning consume, pending-secret disposal, replay, exclusive consumed finalizations, restart finalization of interrupted consumed attempts as failed without re-exchange, immutable completed/failed/expired/cancelled states, and wrong-provider operations.

- [ ] **C1.6 — Prove encrypted provider persistence and secret absence**
  - Chunk owner: **Chunk 1**.
  - Depends on: C1.5.
  - Files: `internal/store/persistence_test.go`, crypto/store fixtures.
  - Work: persist only representative production-durable fields: a Devin opaque token plus derived expiry in encrypted account credentials, encrypted pending verifier/redirect/expiry, and plaintext state hash/provider/flow/status/timestamps. Use distinct raw-state, callback-code, and user-JWT-like sentinels solely as negative absence fixtures; never write them to account/session records. Checkpoint and inspect DB/WAL/SHM. Test envelope primitives separately from production persistence and preserve existing xAI secret scans and tamper/wrong-key behavior.
  - Observable DoD: durable secret fixtures are absent from plaintext DB/WAL/SHM; raw state, callback code, and per-request user JWT are absent from decoded account/session rows and raw DB/WAL/SHM; provider/flow/status/state hash remain queryable; consume leaves no decryptable pending verifier/redirect material after returning the verifier only in memory; completed/failed/expired/cancelled states remain immutable and secret-free; wrong master key and tampered envelopes fail closed without partial plaintext.
  - Verification: focused store/crypto persistence, negative-absence, consume/final-disposal, state-transition, and envelope tests; C5 repeats unique raw-state/callback-code absence, in-memory-only verifier return, exclusive consumed finalization, and pending-secret disposal after every success/failure path, and C6 proves user JWT is request-local only.

- [ ] **C1.7 — Review and commit Chunk 1**
  - Chunk owner: **Chunk 1**.
  - Depends on: C1.6.
  - Work: review the migration/core boundary for hidden provider inference, migration edits, plaintext, and compatibility shims.
  - Observable DoD: all Chunk 1 verification passes; the diff contains only neutral contracts, migration, repositories, and focused tests; historical plans and migrations 001–004 are unchanged.
  - Sequential commit: `feat(provider): persist provider identity and add neutral contracts`.

- [ ] **C2.1 — Introduce deterministic provider-owned model configuration**
  - Chunk owner: **Chunk 2 — Static model ownership and provider-aware configuration**.
  - Depends on: C1.7.
  - Files: `internal/config/config.go`, config fixtures/tests, example config surfaces as needed for compile-time behavior only.
  - Work: represent provider-scoped upstream/OAuth/runtime settings and deterministic model entries. Lock `grok -> grok-4.5` to xAI and exactly `kimi-k2-7`, `glm-5-2`, `swe-1-6-slow` to Devin. Add explicit Devin callback origin/path, an allowed chat-host list defaulting to only `server.codeium.com`, and these transport settings: `unary_timeout` 15s (1s–60s), `stream_idle_timeout` 60s (5s–5m), optional `stream_deadline` default `0` disabled (when explicitly justified/configured, 30s–30m and only shortens the caller context), `max_unary_compressed_bytes` 2 MiB (1 KiB–8 MiB), `max_unary_decompressed_bytes` 8 MiB (1 KiB–32 MiB), `max_frame_compressed_bytes` 4 MiB (1 KiB–16 MiB), `max_frame_decompressed_bytes` 16 MiB (1 KiB–64 MiB), `max_stream_bytes` 64 MiB (1 MiB–256 MiB), `max_tool_argument_bytes` 4 MiB (1 KiB–16 MiB), and `max_non_stream_bytes` 32 MiB (1 MiB–128 MiB). Unary timeout covers each unary operation; stream idle resets only after a complete frame; caller context drives total stream lifetime by default.
  - Observable DoD: strict YAML rejects unknown provider fields, duplicate configured names, invalid kinds, attempted Grok ownership transfer, invalid callback/host values, zero/out-of-range size or idle limits, and invalid nonzero stream deadlines; defaults and caller-context/timeout semantics round-trip; serialized config contains no secrets.
  - Verification: expand `internal/config/config_test.go` default, boundary, override, round-trip, invalid, Railway, disabled-deadline/caller-context, and secret-absence cases.

- [ ] **C2.2 — Build the immutable static model-resolution catalog**
  - Chunk owner: **Chunk 2**.
  - Depends on: C2.1.
  - Files: `internal/provider` catalog/model files, `internal/models/catalog.go`, tests.
  - Work: construct and populate the one immutable static `ModelCatalog`; resolve aliases and real names to `ResolvedModel` values containing public/upstream/provider/owner/policy key only. Reject duplicate public names. Permit multiple public aliases to project to the same canonical `(UpstreamName, Provider, PolicyKey)` registration, specifically `grok` and `grok-4.5` to canonical xAI `grok-4.5`; reject ambiguity when one canonical upstream name is registered under a different provider or policy key. Expose explicit `owned_by` as public metadata only. Do not construct runtime policies, clients, credentials, or capability entries here.
  - Observable DoD: the five public names resolve exactly as specified; the positive `grok`/`grok-4.5` alias pair constructs successfully and shares canonical `(grok-4.5,xai,xai)`; duplicate public names and ambiguous canonical upstream registrations fail construction; unknown names fail before capability/policy/account calls; no concrete runtime object, precedence, qualification, or conflict branch exists.
  - Verification: table tests assert public name, upstream name, provider, owner metadata, and stable policy key for every entry; include the positive `grok` plus `grok-4.5` fixture, duplicate-public negatives, and same-upstream/different-provider-or-policy ambiguity negatives. No other chunk owns static catalog construction or these registration tests.

- [ ] **C2.3 — Make catalog routability provider-aware**
  - Chunk owner: **Chunk 2**.
  - Depends on: C2.2.
  - Files: `internal/models/catalog.go`, `internal/app/runtime.go` public-catalog projection seams, model tests.
  - Work: list a model only when an enabled usable account whose `account.provider` equals its `ResolvedModel.Provider` can route it; never use `OwnedBy` for account eligibility. Apply backend-search support only to xAI and preserve stale/unknown capability semantics within the resolved provider.
  - Observable DoD: `grok` is listed/routable with a usable xAI account even though `OwnedBy=byos`; Devin models are not suppressed by missing xAI search support; unknown Devin capabilities may use Devin accounts only; an account matching owner text but not resolved provider cannot route; no usable account for the resolved provider means that provider's models are omitted.
  - Verification: catalog/readiness tests include a positive `grok` plus xAI-account fixture, a negative owner-text/provider-mismatch fixture, xAI known/unknown search capability, and Devin known/unknown capability independently.

- [ ] **C2.4 — Return explicit public model ownership**
  - Chunk owner: **Chunk 2**.
  - Depends on: C2.3.
  - Files: `internal/api/openai/models.go`, model response tests, admin projection types if needed for the compile boundary.
  - Work: remove the fallback that assigns empty ownership to xAI; require catalog entries to supply `OwnedBy` strictly as public model-list metadata, never as an account-routing key.
  - Observable DoD: `/v1/models` returns `byos` for `grok`, `xai` for `grok-4.5`, and `devin` for each Devin model; `grok` remains routable through an xAI account; an incomplete internal model entry fails a test rather than silently becoming xAI.
  - Verification: focused OpenAI model handler tests separate displayed `owned_by` from provider-based eligibility and include the positive `grok`/xAI-account case.

- [ ] **C2.5 — Review and commit Chunk 2**
  - Chunk owner: **Chunk 2**.
  - Depends on: C2.4.
  - Observable DoD: exact ownership metadata, valid canonical aliases, ambiguous-registration rejection, and fail-closed config behavior are proven; routability uses resolved provider/account provider equality; dynamic discovery is not a routing authority; no model-conflict machinery exists.
  - Sequential commit: `feat(models): add deterministic provider ownership`.

- [ ] **C3.1 — Move shared execution types out of xAI**
  - Chunk owner: **Chunk 3 — Provider-neutral routing and complete xAI generation cutover**.
  - Depends on: C2.5.
  - Files: `internal/api/generation.go`, `internal/routing/execute.go`, `internal/routing/stream.go`, neutral provider types, tests.
  - Work: replace shared imports of `xai.Event`, `xai.Stream`, and concrete xAI client/error types with neutral equivalents. Preserve existing event shape and stream commitment behavior.
  - Observable DoD: shared API/routing packages compile without importing `internal/xai` or `internal/oauth/xai`; existing translators can consume neutral events without behavioral conversion loss.
  - Verification: import-boundary assertion or focused build plus existing generation/routing tests.

- [ ] **C3.2 — Resolve provider without mutating the canonical request**
  - Chunk owner: **Chunk 3**.
  - Depends on: C3.1.
  - Files: `internal/routing/execute.go`, static catalog/runtime registry interfaces, generation handler seams.
  - Work: make executor preparation resolve one immutable `ResolvedModel` and look up its runtime capability entry without changing the canonical request. Retain that resolution for every retry/stream attempt. Unknown models or missing required capabilities stop before policy, model overwrite, account listing, credential handling, marshal, or client dispatch.
  - Observable DoD: unknown models leave the canonical body byte-equivalent and invoke no capability/policy/account/marshal/client; retries cannot change provider/model; instrumented tests expose the call order.
  - Verification: non-stream and stream executor tests with instrumented catalog/capability/policy/account/marshal/client order.

- [ ] **C3.3 — Implement the real xAI request policy and remove global mutation**
  - Chunk owner: **Chunk 3**.
  - Depends on: C3.2.
  - Files: xAI provider adapter, `internal/search`, `internal/api/openai/chat_completions.go`, `responses.go`, `internal/api/anthropic/messages.go`, tests.
  - Work: remove every handler-level `search.Inject`; implement the real xAI `RequestPolicy` over existing Inject/Validate. After static resolution and runtime capability lookup, run it exactly once against the canonical request while the public model name is still present, then have the executor overwrite only the canonical model with `UpstreamName`. Do not alter translator normalization or introduce a temporary/no-op/duplicate mutation path.
  - Observable DoD: order is resolve → capability lookup → policy on public canonical model → upstream overwrite; every xAI request contains exactly one `x_search`; explicit `none` becomes `auto`; auto, required, and selected choices retain current xAI behavior; unknown/Devin models are never search-mutated; no handler imports/calls search mutation directly.
  - Verification: cross-protocol captured canonical-body/order tests plus existing `internal/search` tests.

- [ ] **C3.4 — Filter candidates by provider before scheduling**
  - Chunk owner: **Chunk 3**.
  - Depends on: C3.3.
  - Files: `internal/routing/scheduler.go`, `execute.go`, candidate/account projections, tests.
  - Work: after policy and `UpstreamName` overwrite, add provider to candidates and eliminate wrong-provider accounts before capability lookup/fallback, cooldown ordering, round robin, or affinity.
  - Observable DoD: a body-capture fake receives the post-policy, upstream-named canonical request unchanged; an unknown capability snapshot cannot route to another provider; a preferred account with mismatched provider is ignored; disabled/invalid/expired accounts remain excluded as before.
  - Verification: scheduler/executor matrix includes exact resolve/policy/overwrite/filter order, body capture, known/unknown capabilities, mismatched affinity, and mixed account pools.

- [ ] **C3.5 — Adapt xAI generation transport and dispatch through runtime capabilities**
  - Chunk owner: **Chunk 3**.
  - Depends on: C3.4.
  - Files: `internal/routing/execute.go`, `stream.go`, `errors.go`, `internal/xai/responses.go`, `headers.go`, xAI provider adapter, runtime capability registry/fakes, tests.
  - Work: construct the generation-complete xAI runtime capability entry with the real policy, generation credential access, generation client, and generation-error adapter. Adapt existing xAI Execute/Stream/events/errors without changing endpoint, headers, model override, stream/store flags, JSON escaping, retry classification, or `Retry-After`. The executor exclusively owns the canonical request until the xAI client performs the sole xAI wire marshal; remove the legacy/pre-marshaled path and permit no placeholder bytes, handler marshal, or double marshal.
  - Observable DoD: existing xAI generation works end to end in this committed chunk; xAI wire output/errors are byte/semantically equivalent at tested boundaries; `X-XAI-Token-Auth`, Grok version/user agent, `x-grok-model-override`, `stream=true`, `store=false`, and `SetEscapeHTML(false)` remain intact; same-account retry, pre-commit failover, cooldown, terminal recording, and local usage persist; all attempts stay within xAI and marshal once.
  - Verification: xAI response/transport/header/body fixtures plus marshal-count and routing error/failover tests for 401, 403, 429, transient 5xx, cancellation, incomplete terminal, and post-commit failure.

- [ ] **C3.6 — Preserve managed Responses affinity under provider routing**
  - Chunk owner: **Chunk 3**.
  - Depends on: C3.5.
  - Files: `internal/api/openai/responses.go`, `internal/sessions/reconstruct.go`, routing tests.
  - Work: keep stored affinity as account ID; validate account provider against the newly resolved model before preference. Do not add a response-session provider column.
  - Observable DoD: same-provider continuation prefers the prior account; provider/model mismatch safely falls back within the resolved provider; reconstructed transcripts remain unchanged.
  - Verification: continuation tests with same-provider, wrong-provider, deleted, disabled, and cooled-down preferred accounts.

- [ ] **C3.7 — Review and commit Chunk 3**
  - Chunk owner: **Chunk 3**.
  - Depends on: C3.6.
  - Observable DoD: call order is visibly resolve → runtime capability lookup → real provider policy on public canonical model → upstream overwrite → provider-filtered candidates → credentials/client/sole marshal; all handlers stopped direct search mutation; shared routing/API has no direct concrete-provider event/client import; xAI search and generation transport are real and covered; no legacy transport, temporary compatibility/no-op policy, placeholder payload, or double marshal exists.
  - Sequential commit: `refactor(routing): cut xai generation to provider dispatch`.

- [ ] **C4.1 — Cut xAI OAuth and refresh over to provider capabilities**
  - Chunk owner: **Chunk 4 — xAI OAuth, refresh, discovery, and billing parity**.
  - Depends on: C3.7.
  - Files: `internal/oauth/xai`, xAI capability adapter, account service seams, tests.
  - Work: wrap current device OAuth, OIDC identity, ES256 verifier propagation, refresh singleflight/rotation, and provider-specific credential lifecycle behind capabilities. Reuse the C3 generation entry; do not reconstruct or bypass its policy/transport/error path.
  - Observable DoD: migrated xAI accounts/sessions and device/refresh behavior remain exact; no parallel direct path or compatibility shim remains; xAI-only lifecycle capabilities reject non-xAI accounts.
  - Verification: focused xAI OAuth/OIDC/refresh tests and provider-mismatch negatives.

- [ ] **C4.2 — Cut xAI discovery and billing over and prove parity**
  - Chunk owner: **Chunk 4**.
  - Depends on: C4.1.
  - Files: xAI model-discovery/backend-search and billing adapters, model/usage service seams, tests.
  - Work: wrap models-v2/models/fallback, backend-search capability, billing, and associated worker-facing errors behind optional provider capabilities without changing generation composition.
  - Observable DoD: xAI discovery/fallback/billing behavior is unchanged; provider mismatch cannot send Devin credentials to xAI; the full C3 xAI request/header/transport/error suite remains green through the same generation path.
  - Verification: all focused xAI model/usage tests, provider-mismatch endpoint counters, and C3 generation parity suite.

- [ ] **C4.3 — Review and commit Chunk 4**
  - Chunk owner: **Chunk 4**.
  - Depends on: C4.2.
  - Observable DoD: xAI is the only registered runtime implementation; its real policy and generation transport already work from Chunk 3; OAuth/refresh/discovery/billing now use capabilities; Devin registration has not started; no second catalog, registry, mutation, marshal, or transport path exists.
  - Sequential commit: `refactor(xai): move oauth refresh discovery and billing behind capabilities`.

- [ ] **C5.1 — Add Devin OAuth configuration and PKCE primitives**
  - Chunk owner: **Chunk 5 — Devin OAuth callback, PKCE, and encrypted lifecycle**.
  - Depends on: C4.3.
  - Files: create `internal/oauth/devin`; config integration/tests.
  - Work: implement 96-random-byte unpadded base64url verifier, S256 challenge, 32-random-byte state, five-minute expiry, and exact authorization URL query: `redirect_uri`, `state`, `prompt=select_account`, `code_challenge`, `code_challenge_method=S256`.
  - Observable DoD: concurrent starts produce distinct raw state/verifier values; only a hash of state and encrypted verifier/redirect/expiry payload persist while pending; raw state is absent from rows and DB/WAL/SHM; no invented scope/client-secret/refresh parameters are sent.
  - Verification: deterministic challenge/authorization-query tests, raw-state absence scan, and pending-versus-terminal payload inventory based on source fixtures.

- [ ] **C5.2 — Implement persisted provider-bound start/consume lifecycle**
  - Chunk owner: **Chunk 5**.
  - Depends on: C5.1.
  - Files: Devin OAuth service, shared account service, OAuth session store integration/tests.
  - Work: create callback-PKCE sessions; atomically consume state before exchange; reject wrong provider/flow, unknown, expired, cancelled, replayed, completed, failed, or missing-verifier attempts. The consume mutation irreversibly changes `pending -> consumed`, decrypts and returns the verifier only to caller memory, and clears or cryptographically invalidates pending verifier/redirect access before network exchange. Consumed is a non-retryable in-flight state and permits only `consumed -> completed|failed`; cancellation/expiry act only on pending, and completed/failed/expired/cancelled are immutable. Raw state and callback authorization code remain in memory only and are never written to account/session payloads or lifecycle metadata.
  - Observable DoD: a pending attempt survives restart and can be consumed exactly once; every rejected callback makes zero exchange calls; consume returns the verifier only in memory and leaves no decryptable pending secret; replay or failure never restores pending; exchange failure and interrupted-consumed restart finalize failed without another exchange; no path persists raw state, account token, authorization code, or decryptable final-state pending secret.
  - Verification: positive, negative, replay, cancellation, race, restart, verifier-memory-only, consume-disposal, exclusive `consumed -> completed|failed`, immutable completed/failed/expired/cancelled, and unique raw-state/callback-code absence matrix.

- [ ] **C5.3 — Implement bounded redirect-refusing token exchange**
  - Chunk owner: **Chunk 5**.
  - Depends on: C5.2.
  - Files: `internal/oauth/devin` exchange client/tests.
  - Work: POST exact JSON `{code,code_verifier}` to validated `https://api.devin.ai/auth/cli/token` by default, with JSON accept/content headers, configured unary body/decompression/time limits, redirects disabled, and acceptance of only a non-empty string `token`. Discard the code after the exchange call returns.
  - Observable DoD: redirect, non-HTTPS/invalid host, empty token, malformed/oversized response, cancellation, timeout, and upstream error all fail without logging or persisting code/verifier/body/token.
  - Verification: local HTTP fixtures assert method/path/headers/body and secret-free errors; a unique code is absent from session/account rows and DB/WAL/SHM after every exchange outcome.

- [ ] **C5.4 — Persist Devin account credentials with explicit no-refresh semantics**
  - Chunk owner: **Chunk 5**.
  - Depends on: C5.3.
  - Files: shared account service/types, Devin credential manager, OAuth-session/account store transaction, store tests.
  - Work: after successful exchange, execute one store transaction that upserts/deduplicates encrypted Devin account credentials and changes the already-consumed OAuth session to completed; callback success becomes visible only after commit. Parse JWT `exp` solely as unverified expiry metadata (`exp-5m`), otherwise use the one-year fallback. Fingerprint identity as HMAC over provider plus opaque token; identical token deduplicates, different token creates a new account. Never derive identity from JWT claims. Any account-write, session-completion, or commit failure rolls back both transaction changes and preserves a pre-existing deduplicated account, then finalizes the still-consumed session failed without retrying exchange or exposing a new usable account.
  - Observable DoD: every exchange or post-exchange failure ends in failed or, if finalization itself is interrupted, a consumed state that restart recovery changes only to failed without exchange; no failure leaves a newly persisted usable token/account or retryable attempt. Success exposes account and completed session together only after the atomic commit; expired credentials and upstream 401/403 become relogin-required; no Devin refresh exists.
  - Verification: expiry/malformed-token/dedup/new-token tests plus injected exchange, account-write, session-completion, commit, and failure-finalization interruptions and restart at each boundary; assert transaction rollback, consumed-to-failed recovery without re-exchange, pre-existing-account preservation, atomic success visibility, immutable final states, and unique code/token plaintext absence in rows and DB/WAL/SHM.

- [ ] **C5.5 — Generalize account login orchestration by provider**
  - Chunk owner: **Chunk 5**.
  - Depends on: C5.4.
  - Files: `internal/accounts/service.go`, service tests/fakes.
  - Work: expose provider-selected start/status/cancel/complete results while allowing xAI device polling and Devin callback completion to retain distinct protocols. Shared service persists normalized account results and runs model/usage hooks only for the correct provider.
  - Observable DoD: no type switch leaks xAI device types into generic callers; concurrent completion remains singleflight where applicable; provider mismatch never invokes another provider's OAuth service.
  - Verification: account service tests for both providers, cancellation, concurrent observation, and hook dispatch.

- [ ] **C5.6 — Review and commit Chunk 5**
  - Chunk owner: **Chunk 5**.
  - Depends on: C5.5.
  - Observable DoD: Devin OAuth service is fully testable but not yet exposed by runtime routes; callback origin/path, exchange policy, code non-persistence, atomic in-memory-verifier consume, exclusive consumed finalization, immutable final states, and atomic account-plus-completion commit with failure-to-failed behavior are explicit; no plaintext file store or refresh fiction exists.
  - Sequential commit: `feat(devin): add encrypted callback oauth lifecycle`.

- [ ] **C6.1 — Verify provenance and add only required Devin protocol definitions**
  - Chunk owner: **Chunk 6 — Devin protocol bootstrap and request builder**.
  - Depends on: C5.6.
  - Files: license/notice inventory and `internal/devin/proto` generated/minimal definitions.
  - Work: record exact source revision and license provenance before copying/generating AuthService/GetUserJwt, ApiServerService/GetChatMessage, Metadata, message/tool/model-usage, and optional discovery definitions. Exclude unrelated provider/plugin/media/WebSocket/capacity/analytics RPCs.
  - Observable DoD: source and generated-code notices satisfy repository policy; required symbols compile; no unsupported protocol surface is imported.
  - Verification: source-to-symbol inventory review. This item is a hard gate: do not proceed with copied/generated code if provenance is unresolved.

- [ ] **C6.2 — Implement Devin session-token normalization and unary metadata**
  - Chunk owner: **Chunk 6**.
  - Depends on: C6.1.
  - Files: create `internal/devin` client/metadata files and tests.
  - Work: trim whitespace, remove repeated `devin-session-token$` prefixes, add exactly one prefix, reject prefix-only/empty values, and construct the source Windsurf metadata constants without mixing downstream/admin credentials.
  - Observable DoD: bare, once-prefixed, repeatedly prefixed, whitespace, and empty cases behave exactly; errors/logs never include the token.
  - Verification: table tests and captured protobuf metadata.

- [ ] **C6.3 — Implement per-request GetUserJwt bootstrap**
  - Chunk owner: **Chunk 6**.
  - Depends on: C6.2.
  - Files: `internal/devin` unary client/transport tests.
  - Work: POST protobuf to `/exa.auth_pb.AuthService/GetUserJwt` with exact Connect unary headers; support bounded raw-protobuf or raw-gzip response decoding; reject empty `user_jwt`; invoke bootstrap for every chat request with no cache.
  - Observable DoD: default runtime base is `https://server.codeium.com`; redirects are refused; request/response/decompression sizes and time are bounded; 401/403 map to relogin-required without calling xAI refresh.
  - Verification: raw/gzip, empty JWT, status, timeout, cancellation, redirect, oversized body, and malformed protobuf fixtures.

- [ ] **C6.4 — Enforce the custom chat-base trust policy**
  - Chunk owner: **Chunk 6**.
  - Depends on: C6.3.
  - Files: Devin URL validator/dial transport/config tests.
  - Work: accept `custom_api_server_url` only as an absolute HTTPS origin with no userinfo, query, fragment, or non-root path; require its hostname to exactly match configured `devin.allowed_chat_hosts`; default allowlist is only `server.codeium.com`; resolve/dial only public non-loopback, non-private, non-link-local addresses; refuse redirects and revalidate each connection to limit DNS rebinding.
  - Observable DoD: unlisted host, IP literal, userinfo, path/query/fragment, HTTP, loopback/private/link-local resolution, redirect, and DNS rebinding fixture are rejected before sending session token or user JWT. Empty custom base falls back to the validated default.
  - Verification: URL and controlled resolver/dialer tests prove credentials reach only an allowed public HTTPS endpoint.

- [ ] **C6.5 — Build canonical Devin chat requests**
  - Chunk owner: **Chunk 6**.
  - Depends on: C6.4.
  - Files: `internal/devin/chat_builder.go` and focused tests.
  - Work: map canonical model/messages/tools/options to `GetChatMessageRequest`; pass selected model unchanged as `chat_model_uid`; include session token and user JWT metadata; preserve source message ordering, system prompt/cache behavior, inline images, thinking/signatures, tool calls/results, IDs, stops/default caps, planner/provider enums, and `disable_parallel_tool_calls=true`. Reject remote URL images rather than fetching them.
  - Observable DoD: each required Devin model reaches the wire unchanged; mixed history produces the expected protobuf; deterministic IDs are stable for structural inputs; no prompt or credential is logged.
  - Verification: source-equivalent request-builder fixture matrix.

- [ ] **C6.6 — Preserve Devin tool-choice semantics at the wire boundary**
  - Chunk owner: **Chunk 6**.
  - Depends on: C6.5.
  - Files: Devin builder tests and canonical validation seams.
  - Work: map omitted/default and `auto` to upstream `auto`, explicit `none` to `none`, and selected tool to its exact `tool_name`; reject unsupported choices deterministically. Do not call xAI search policy or silently map to another choice.
  - Observable DoD: none/auto/selected values are unchanged from canonical request to captured Devin protobuf; every case sets parallel tools disabled.
  - Verification: table tests covering all three public translators' canonical outputs and invalid selected-tool cases.

- [ ] **C6.7 — Review and commit Chunk 6**
  - Chunk owner: **Chunk 6**.
  - Depends on: C6.6.
  - Observable DoD: provenance is recorded; bootstrap and request building are bounded and credential-safe; no streaming, optional discovery, capacity, analytics, or quota code is mixed into this chunk.
  - Sequential commit: `feat(devin): add session bootstrap and request builder`.

- [ ] **C7.1 — Implement bounded Connect request/response framing**
  - Chunk owner: **Chunk 7 — Devin Connect stream, neutral events, and per-response usage**.
  - Depends on: C6.7.
  - Files: `internal/devin/stream_client.go`, transport tests.
  - Work: encode gzip protobuf request with flag `0x01` and big-endian length; send exact Connect streaming headers; decode raw/gzip frames and JSON end-stream trailers. Enforce every C2.1 compressed/decompressed unary/frame, total stream, tool-argument, buffered non-stream, and idle-timeout bound before allocation/decompression/append. Caller context is the default total lifetime; apply `stream_deadline` only when explicitly nonzero and only as an earlier child deadline.
  - Observable DoD: invalid config cannot reach transport; truncated/oversized/invalid flags, gzip bombs, malformed protobuf/trailers, cancellation, idle timeout, caller deadline, and explicitly configured total deadline fail deterministically without unbounded allocation or raw-body errors; no default adapter deadline truncates an otherwise-live caller stream.
  - Verification: byte-level framing plus adversarial boundary, decompression, truncation, idle, caller-cancellation/deadline, disabled-total-deadline, and explicit-total-deadline tests for every locked setting.

- [ ] **C7.2 — Map Devin stream responses to neutral events**
  - Chunk owner: **Chunk 7**.
  - Depends on: C7.1.
  - Files: stream mapper and tests.
  - Work: map text, thinking/signature, tool-call start/delta/stop, actual model, explicit/inferred stop, usage, and message completion. Handle incremental versus cumulative tool arguments without duplication. Reject malformed end-stream JSON as an intentional hardening. Source-compatible clean EOF succeeds exactly when reading a fresh five-byte header returns zero bytes after zero or more complete frames, including an empty stream and EOF between complete nonterminal frames; run normal mapper finalization so final stops may be synthesized. EOF after 1–4 header bytes or before the declared payload completes is truncation.
  - Observable DoD: multi-frame output preserves event order; explicit stop wins and mapper finalization remains source-compatible; empty clean EOF and clean EOF after any complete-frame sequence succeed; partial header/payload returns a sanitized truncation error; no event is emitted twice.
  - Verification: raw/gzip multi-frame, cumulative/delta, explicit/inferred stop, empty EOF, EOF between complete frames, partial-header, partial-payload, malformed-trailer, and stop-reason fixtures.

- [ ] **C7.3 — Integrate stream commitment and buffered non-stream behavior**
  - Chunk owner: **Chunk 7**.
  - Depends on: C7.2.
  - Files: Devin generation adapter, shared routed stream tests, public generation fixtures.
  - Work: expose one upstream streaming operation; let existing shared execution buffer it for non-stream output. Preserve failover only before first valid event; flush the first public SSE event promptly; map post-commit errors to protocol stream errors.
  - Observable DoD: non-stream performs no second/upstream non-stream call; pre-first-event failure can fail over within Devin accounts; post-first-event failure never replays on another account.
  - Verification: first-event flush timing, pre/post-commit error, cancellation, and buffered response tests.

- [ ] **C7.4 — Map and record per-response Devin usage exactly once**
  - Chunk owner: **Chunk 7**.
  - Depends on: C7.3.
  - Files: stream mapper, routing/local usage integration tests.
  - Work: map input tokens, output tokens, cache-read tokens, and total=`input+output`; ignore cache-write, credit, ACU, quota, pricing, and analytics fields; record against the selected Devin account using existing detached terminal accounting.
  - Observable DoD: repeated usage frames or close paths do not double-count; incomplete/terminal usage follows existing semantics; actual model is preserved separately; no usage-submission RPC occurs.
  - Verification: repeated-frame, cache-write exclusion, incomplete stream, cancellation, failover, and local-counter persistence tests.

- [ ] **C7.5 — Review and commit Chunk 7**
  - Chunk owner: **Chunk 7**.
  - Depends on: C7.4.
  - Observable DoD: transport limits, event order, commitment, usage, and secret-free failures are proven; no optional discovery/statistics work is included.
  - Sequential commit: `feat(devin): add connect streaming and usage mapping`.

- [ ] **C8.1 — Make credential refresh workers provider-aware**
  - Chunk owner: **Chunk 8 — Provider-aware refresh, discovery, and usage workers**.
  - Depends on: C7.5.
  - Files: `internal/accounts/refresh_worker.go`, account projections, tests.
  - Work: carry account provider and dispatch credential maintenance through the registry. xAI retains proactive/singleflight refresh; Devin performs no refresh and projects expiry/relogin-required.
  - Observable DoD: no Devin token reaches an xAI refresh endpoint; concurrent Devin requests do not fabricate refresh; xAI rotation/hooks remain unchanged.
  - Verification: mixed-account worker fixture with endpoint call counters and expiry transitions.

- [ ] **C8.2 — Make model workers provider-aware**
  - Chunk owner: **Chunk 8**.
  - Depends on: C8.1.
  - Files: `internal/models/worker.go`, upstream/discovery adapters, tests.
  - Work: include provider in worker account projections and dispatch only when that provider has a discoverer; preserve xAI models-v2/models/fallback behavior.
  - Observable DoD: absence of Devin discovery is a supported no-op capability state, not a worker error; no provider credential reaches another provider endpoint; worker bounds/cancellation/restart remain intact.
  - Verification: mixed-provider worker tests with absent capability and endpoint isolation.

- [ ] **C8.3 — Optionally implement safely bounded Devin model discovery**
  - Chunk owner: **Chunk 8**.
  - Depends on: C8.2.
  - Files: Devin optional discoverer and tests if retained; implementation-review disposition and absent-capability registration/worker tests if omitted.
  - Work: choose and record exactly one disposition. **Implemented:** call source-supported `GetCliModelConfigs` with normalized session token and default runtime base, without `GetUserJwt` or custom chat base; bound response/decompression/count/string sizes; ignore disabled/empty records and untrusted pricing/provider/default/capacity metadata; trim/deduplicate IDs; intersect results with exactly the three static Devin models. **Omitted:** record the explicit implementation-review decision, register no Devin discoverer or no-op stub, and retain the optional absent-capability dispatch from C8.2.
  - Observable DoD: **implemented path:** bounded discovery fixtures prove only the three fixed models can become supported/unsupported/unknown, no fourth public/routable model or ownership change is possible, and sanitized failure/stale state does not unexpectedly disable static unknown-capability fallback. **Omission path:** the recorded decision, registry/composition proof that no Devin discoverer or stub is registered, and passing absent-capability worker/runtime behavior prove static routing and unknown-capability fallback remain available without discovery.
  - Verification: for the implemented path, disabled/empty/duplicate/oversized/incidental-model/failure fixtures; for the omission path, implementation-review record, registry assertion for absent Devin discovery, no discoverer/stub inventory result, and C8.2 absent-capability tests.

- [ ] **C8.4 — Make usage workers and projections provider-aware**
  - Chunk owner: **Chunk 8**.
  - Depends on: C8.3.
  - Files: `internal/usage/worker.go`, `service.go`, xAI billing adapter, tests.
  - Work: dispatch optional subscription usage by provider. Keep xAI monthly/weekly billing unchanged. Register no Devin quota fetcher unless new source evidence is separately approved; represent upstream quota as `unavailable` while retaining local counters.
  - Observable DoD: xAI billing never receives Devin credentials; Devin does not fabricate zero/monthly/weekly quota; optional fetch failure never blocks inference; stale/error strings are sanitized.
  - Verification: mixed-provider usage worker tests and explicit xAI endpoint non-call assertion for Devin.

- [ ] **C8.5 — Review and commit Chunk 8**
  - Chunk owner: **Chunk 8**.
  - Depends on: C8.4.
  - Observable DoD: all workers dispatch by provider, remain bounded/restart-safe, and optional capabilities are truly optional; required routing does not depend on discovery or quota.
  - Sequential commit: `feat(provider): dispatch account model and usage workers`.

- [ ] **C9.1 — Compose the immutable two-provider runtime capability registry**
  - Chunk owner: **Chunk 9 — Final runtime composition and end-to-end model dispatch**.
  - Depends on: C8.5.
  - Files: `internal/app/runtime.go`, runtime construction tests.
  - Work: compose the generation-complete xAI and Devin runtime capabilities plus their OAuth/credential/discovery/usage capabilities in one immutable `CapabilityRegistry`; inject the immutable static `ModelCatalog` already constructed/populated by C2.2 into account/model/usage/routing services. Do not reconstruct, populate, or validate duplicate static model entries here; fail startup only when a static entry references a missing required runtime provider/policy capability.
  - Observable DoD: runtime has one composition path and no singular xAI-only executor/catalog wiring; static ownership and runtime capabilities remain distinct and immutable; optional Devin capabilities may be absent without startup failure.
  - Verification: runtime capability construction tests for valid, missing-required, duplicate provider/policy capability, and optional-capability configurations; static catalog duplicate-name behavior remains exclusively in C2.2.

- [ ] **C9.2 — Make readiness and public catalog follow the default model owner**
  - Chunk owner: **Chunk 9**.
  - Depends on: C9.1.
  - Files: runtime public catalog/readiness logic and tests.
  - Work: resolve the configured default model from the static catalog, look up its runtime capabilities, then assess enabled usable accounts and provider policy using `ResolvedModel.Provider`; never use `OwnedBy` for readiness. Preserve xAI backend-search readiness only for xAI defaults.
  - Observable DoD: default `grok-4.5` readiness remains xAI-dependent; public `grok` is ready with a usable xAI account despite `OwnedBy=byos`; a configured Devin default is ready only with a usable Devin account and required runtime capabilities and is independent of xAI search capability; wrong-provider accounts never make readiness true.
  - Verification: static-resolution/runtime-capability/provider/default/account readiness matrix includes positive `grok` plus xAI account and owner-metadata/provider-mismatch cases.

- [ ] **C9.3 — Prove end-to-end provider dispatch for all public protocols**
  - Chunk owner: **Chunk 9**.
  - Depends on: C9.2.
  - Files: runtime/API integration fixtures for OpenAI Chat, Responses, Anthropic Messages.
  - Work: exercise stream and non-stream requests through the real translator → static resolve → runtime capability lookup → policy → upstream-name overwrite → provider filter → fake provider client/sole marshal → response translation chain.
  - Observable DoD: `grok`/`grok-4.5` hit xAI only with search policy; all three Devin models hit Devin only without search; explicit none/auto/selected reach Devin unchanged; each provider wire payload is marshaled once and no cross-provider endpoint is called.
  - Verification: table-driven end-to-end request/body/marshal-count/event fixtures for three protocols and both response modes.

- [ ] **C9.4 — Prove provider-local retry, affinity, cooldown, and accounting end to end**
  - Chunk owner: **Chunk 9**.
  - Depends on: C9.3.
  - Files: runtime/routing/session integration tests.
  - Work: cover mixed account pools, unknown capabilities, wrong-provider affinity, disabled/expired accounts, 401/403, 429 with `Retry-After`, transient failures, pre/post-commit stream failure, restart, and local usage.
  - Observable DoD: every retry/failover/cooldown/affinity choice remains within the resolved provider; usage is charged only to the selected account once; managed Responses continuation cannot force a provider change.
  - Verification: fake-provider call ledger and persisted store assertions.

- [ ] **C9.5 — Review and commit Chunk 9**
  - Chunk owner: **Chunk 9**.
  - Depends on: C9.4.
  - Observable DoD: core runtime behavior works end to end before management UI/routes are added; all five names and both response modes have observable dispatch proof.
  - Sequential commit: `feat(runtime): compose xai and devin providers`.

- [ ] **C10.1 — Add provider-aware Admin REST OAuth routes**
  - Chunk owner: **Chunk 10 — Admin REST, Web UI, and CLI flows**.
  - Depends on: C9.5.
  - Files: `internal/api/admin/handler.go`, admin route/handler tests.
  - Work: preserve `/admin/api/v1/oauth/xai/device/*`; add authenticated `POST /admin/api/v1/oauth/devin/start`, `GET /admin/api/v1/oauth/devin/status/{sessionID}`, and `POST /admin/api/v1/oauth/devin/cancel/{sessionID}`, plus the explicitly configured GET callback. Status/cancel look up and mutate only the path-keyed OAuth session ID and provider. Callback bypasses admin bearer auth only for its exact method/path and uses state/PKCE lifecycle authorization.
  - Observable DoD: start/status/cancel retain admin auth, throttle, and no-store headers; unknown/wrong-provider session IDs return not-found without mutation; status/cancel for one concurrent session cannot observe or affect another; callback rejects wrong method/path/provider/error/code/state/replay without exchange; responses contain allowlisted lifecycle fields only.
  - Verification: positive/negative/replay/restart/sanitized-error route matrix, unknown-ID cases, two-concurrent-session status/cancel isolation, and middleware separation tests.

- [ ] **C10.2 — Add provider to Admin REST account/model/usage projections**
  - Chunk owner: **Chunk 10**.
  - Depends on: C10.1.
  - Files: admin views/handlers/tests.
  - Work: include provider in safe account and model views; expose local usage and provider-specific upstream-usage availability; make refresh/relogin actions provider-capability-aware.
  - Observable DoD: no credential/raw token/identity/OAuth payload appears; Devin never exposes xAI billing fields as if valid; wrong-provider operations fail safely.
  - Verification: JSON allowlist and secret-scan tests.

- [ ] **C10.3 — Add provider selection and lifecycle to Web UI**
  - Chunk owner: **Chunk 10**.
  - Depends on: C10.2.
  - Files: `internal/web/services.go`, `oauth.go`, pages, `internal/app/web.go`, account/oauth/model/usage templates, tests.
  - Work: let `/admin/oauth/new` select `xai|devin`; render correct device versus callback instructions/status; show provider labels, relogin state, model ownership, and usage availability. Preserve server-rendered templates, frozen JS hooks, CSRF, trusted-proxy cookies, destructive confirmation, and no-store behavior.
  - Observable DoD: xAI wording appears only in xAI flow; Devin callback completion can be observed after restart; rendered HTML includes provider but no state/verifier/code/token/user JWT/raw billing.
  - Verification: page/service/app tests, CSRF/trusted-proxy regressions, and rendered-output secret scan.

- [ ] **C10.4 — Add provider-aware CLI login**
  - Chunk owner: **Chunk 10**.
  - Depends on: C10.3.
  - Files: `cmd/byos/main.go`, CLI tests/docs seam.
  - Work: implement `byos login --provider xai|devin`, default `xai`. Keep xAI device behavior. For Devin, run the same persisted start/status service and a bounded callback-only HTTP listener on configured `server.listen` and exact callback path; the command requires the normal service to be stopped and fails clearly if the listener cannot bind. Print/open only the authorization URL and safe status; never print token/state/verifier/code.
  - Observable DoD: provider parsing/default is deterministic; Devin CLI completes through the same encrypted lifecycle, survives process-visible status transitions, times out/cancels cleanly, and does not create a second callback implementation.
  - Verification: CLI argument tests and local callback-listener success, bind-failure, timeout, cancellation, and secret-output fixtures.

- [ ] **C10.5 — Review and commit Chunk 10**
  - Chunk owner: **Chunk 10**.
  - Depends on: C10.4.
  - Observable DoD: Admin REST, Web, and CLI can start/observe the correct provider flow and display safe provider-aware state; Devin status/cancel are OAuth-session-ID keyed and isolated; only the exact callback route is unauthenticated by admin session.
  - Sequential commit: `feat(admin): expose provider-aware oauth and account flows`.

- [ ] **C11.1 — Inventory the already-shipped configuration and routes**
  - Chunk owner: **Chunk 11 — Deployment documentation, inventory, and attribution**.
  - Depends on: C10.5.
  - Files: config examples, route inventory/tests, deployment files only where behavior requires changes.
  - Work: document/verify the authorization, token, runtime base, callback origin/path, allowed chat hosts, fixed models, and the exact bounds/timeouts already defined and shipped by C2.1. Do not decide, rename, or change limit semantics here. Do not add a Devin token/client-secret environment variable.
  - Observable DoD: examples match C2.1 defaults/ranges/semantics; fresh default config remains xAI-compatible; enabling Devin has explicit validated callback/host settings; route inventory contains only required public/admin/callback routes.
  - Verification: config parse/startup scenarios using the existing contract and route enumeration tests.

- [ ] **C11.2 — Update operator and deployment documentation**
  - Chunk owner: **Chunk 11**.
  - Depends on: C11.1.
  - Files: `README.md` and existing configuration/Compose/Railway documentation; do not create or modify historical plan files.
  - Work: explain provider ownership, login methods, HTTPS callback setup, persistent `/data`, stable `BYOS_MASTER_KEY`, single replica, Devin relogin-on-expiry, xAI-only search/billing, local Devin usage, unavailable Devin quota, and absence of a token env.
  - Observable DoD: documented commands/routes/config names match implementation; examples contain placeholders only; no claim implies multi-replica safety, Devin refresh, arbitrary discovered models, or official Devin quota.
  - Verification: manual doc-to-config/route inventory and secret/example scan.

- [ ] **C11.3 — Complete source attribution and scope review**
  - Chunk owner: **Chunk 11**.
  - Depends on: C11.2.
  - Files: existing license/notice material and source-reference inventory.
  - Work: retain required notices for copied/generated Devin material and exact source revision; compare imported symbols with the approved required path; remove unrelated protocol/generated code.
  - Observable DoD: licensing is approved, attribution is complete, and no standalone gateway token store/public auth/server stack, capacity, analytics, quota, media, plugin, or WebSocket code was absorbed.
  - Verification: source/symbol/license inventory review.

- [ ] **C11.4 — Review and commit Chunk 11**
  - Chunk owner: **Chunk 11**.
  - Depends on: C11.3.
  - Observable DoD: config, deployment, docs, and attribution exactly describe shipped behavior; historical plans remain byte-unchanged.
  - Sequential commit: `docs(devin): document provider setup and attribution`.

- [ ] **C12.1 — Run focused provider and migration verification**
  - Chunk owner: **Chunk 12 — Final security, regression, and acceptance**.
  - Depends on: C11.4.
  - Work: run the focused package/test commands accumulated by Chunks 1–11, including populated v4→v5 migration, store/crypto, config/models, routing, xAI, Devin OAuth/bootstrap/stream, workers, runtime, admin, Web, and CLI.
  - Observable DoD: every focused command passes with no skipped required contract; failures are fixed at source rather than waived.
  - Verification: record exact commands and results in the implementation review/PR evidence, not in this pre-implementation tracker.

- [ ] **C12.2 — Run full automated regression and race gates**
  - Chunk owner: **Chunk 12**.
  - Depends on: C12.1.
  - Work: run full repository tests, static checks already required by project convention, and targeted race tests for OAuth state consumption/completion, refresh, routing cursors, stream close, and detached usage persistence.
  - Observable DoD: all required gates pass; no flaky timing-only assertion or provider-shared mutable registry remains.
  - Verification: exact command output retained with implementation review evidence.

- [ ] **C12.3 — Smoke test both providers with local fixtures and restart**
  - Chunk owner: **Chunk 12**.
  - Depends on: C12.2.
  - Work: launch BYOS against fake xAI and Devin OAuth/runtime endpoints; migrate a populated v4 DB; complete both login types; issue Chat, Responses, and Anthropic stream/non-stream requests; restart; exercise continuation, model list/readiness, admin/Web/CLI views, workers, and backup restore.
  - Observable DoD: observed upstream call ledger proves exact model/provider/policy dispatch and no cross-provider calls; encrypted state survives restart; pre-upgrade backup restores under the prior binary procedure; no in-place schema downgrade is attempted.
  - Verification: retain sanitized smoke logs and call-ledger assertions.

- [ ] **C12.4 — Perform the final security and scope review**
  - Chunk owner: **Chunk 12**.
  - Depends on: C12.3.
  - Work: apply the independent review rubric: provider identity survives restart; static resolution precedes runtime capability lookup, real xAI policy on the public model, upstream overwrite, and all scheduling; wrong-provider accounts are excluded before fallback; neutral executor payload ownership yields exactly one provider marshal and no placeholder path; no cross-provider refresh/billing/failover/affinity; callback/state/PKCE, raw-state/code/user-JWT non-persistence, terminal pending-secret disposal, atomic account/session completion, session-ID route isolation, custom-base trust, bounds, caller-context-driven stream lifetime, and exact clean-EOF/truncation semantics are proven; optional discovery cannot expand models; unsupported RPCs are absent; xAI parity remains intact.
  - Architecture corrections explicitly proven here: duplicate public names and ambiguous canonical provider-model registrations fail while the `grok`/`grok-4.5` canonical xAI alias fixture succeeds; every listing/readiness/routing decision uses `ResolvedModel.Provider == account.provider` with `OwnedBy` metadata-only; OAuth consume returns the verifier only in memory after clearing pending-secret access, consumed is irreversible non-retryable in-flight with only completed/failed finalization, completed/failed/expired/cancelled are immutable, and transaction/restart failures expose no account or retryable exchange.
  - Observable DoD: every rubric statement has code/test/smoke evidence; no legacy direct xAI path, static/runtime registry conflation, duplicate static catalog ownership, compatibility shim, placeholder, double marshal, silent default, unresolved non-live decision, or accidental out-of-scope protocol remains.
  - Verification: independent reviewer checklist is attached to implementation review and every finding is resolved.

- [ ] **C12.5 — Record live-provider acceptance honestly**
  - Chunk owner: **Chunk 12**.
  - Depends on: C12.4.
  - Work: complete and check this required disposition item using exactly one honest outcome. If real Devin credentials and operator approval are available, perform scrubbed live Devin login/inference for owned models and both stream modes and record sanitized evidence. If either is unavailable, record the exact missing credential and/or operator-approval blocker; keep the live scenario blocked in evidence without weakening deterministic local acceptance or representing it as passed. This item is Devin-specific and cannot satisfy or close any historical `init.todo.md` task.
  - Observable DoD: a sanitized live operator record or an exact credential/operator blocker is recorded, with no fake fixture represented as live and no real secret or prompt retained; the disposition item is checked in either case; automated/local acceptance remains independently complete; the four historical blockers remain separately unchecked unless completed under their own tracker.
  - Verification: sanitized Devin operator record or exact Devin live-only blocker, explicit confirmation that a blocker is evidence rather than an open dependency for C12.6, plus explicit confirmation that C12.5 did not close `Initialize the Go module and pin dependencies`, `Perform live OAuth and x_search acceptance with two accounts`, `Perform live failover and restart acceptance`, or `Complete final source and license review` in `init.todo.md`.

- [ ] **C12.6 — Review and commit final acceptance**
  - Chunk owner: **Chunk 12**.
  - Depends on: C12.5.
  - Observable DoD: all preceding Devin tracker items are checked, including C8.3 under one observable discovery disposition and C12.5 under one completed live disposition. If live execution was unavailable, its exact credential/operator blocker remains in evidence without claiming success and without leaving an open tracker dependency. The architecture plan, shipped code, tests, routes, config, docs, attribution, and security evidence agree; no historical planning artifact changed and none of its four open blockers was superseded or closed.
  - Sequential commit: `test(provider): complete devin integration acceptance`.

## Historical tracker non-supersession

The following four unchecked [`init.todo.md`](./init.todo.md) blockers remain separate and open: `Initialize the Go module and pin dependencies`; `Perform live OAuth and x_search acceptance with two accounts`; `Perform live failover and restart acceptance`; and `Complete final source and license review`. C12.5 is not equivalent to any of them and cannot combine, satisfy, check, or close them.

## Final review checklist

The final reviewer must answer **yes** to every applicable question before C12.6:

1. Does each persisted account and OAuth session have a validated provider, including deterministic `xai` backfill across restart; does consume return the verifier only in memory after clearing pending-secret access; and are only real durable fields retained with consumed constrained to completed/failed and completed/failed/expired/cancelled immutable?
2. Does the effective request order read static model resolve → runtime capability lookup → provider policy on the public canonical model → `UpstreamName` overwrite → provider-filtered candidates → provider credentials/client → exactly one provider-wire marshal?
3. Are wrong-provider accounts excluded before capability fallback, affinity, cooldown, retry, and failover for both stream and non-stream paths, using `ResolvedModel.Provider == account.provider` rather than `OwnedBy`?
4. Does xAI alone provide both public `grok` and `grok-4.5` through canonical upstream `grok-4.5`, mandatory `x_search`, `none -> auto`, refresh, billing, backend-search gating, Grok headers, and xAI error-body semantics; does the positive alias fixture pass while duplicate public and ambiguous canonical registrations fail?
5. Does Devin alone own the three named models, preserve none/auto/selected choices, use no xAI search/refresh/billing, and pass model IDs unchanged; and is `OwnedBy` used only as public metadata, including `grok` routability through an xAI account despite `OwnedBy=byos`?
6. Is Devin OAuth state provider-bound, expiring, atomically consumed before exchange, restart-safe, replay-proof, redirect-refusing, and based only on explicit callback configuration; does consume irreversibly enter non-retryable in-flight consumed, return the verifier only in memory, and clear pending-secret access; are only state hash plus encrypted pending verifier/redirect/expiry persisted while pending; and are raw state, callback code, and per-request user JWT absent from rows and DB/WAL/SHM?
7. Can consumed finalize only to completed or failed, are completed/failed/expired/cancelled immutable, and does one transaction make post-exchange account upsert/deduplication plus completion visible atomically, with injected exchange/write/completion/commit/finalization interruption and restart proof that failures expose no new account or repeated exchange; are expiry/401/403 relogin-only with no invented refresh or trusted JWT identity?
8. Can a Devin session token or user JWT reach only validated, allowlisted, public HTTPS runtime hosts, with redirects and oversized bodies/frames refused?
9. Are Connect frames, decompression, total stream data, tool arguments, and non-stream buffering bounded by the exact C2.1 settings; is total stream lifetime caller-context-driven with the adapter deadline disabled by default; and do fixtures prove clean EOF succeeds on zero bytes at a fresh header after zero or more complete frames while partial header/payload truncates?
10. Is per-response usage recorded exactly once against the selected account, with cache-read preserved and cache-write/credit/quota excluded?
11. Is C8.3 completed under exactly one disposition: bounded discovery fixtures prove intersection with only the fixed three-model set, or explicit omission evidence proves no Devin discoverer/stub is registered and the absent-capability path passes; and is unsupported quota explicitly unavailable without blocking inference?
12. Do Admin REST Devin status/cancel routes use OAuth session-ID keys with unknown-ID not-found and concurrent-session isolation, and do Web UI, CLI, model listing, readiness, workers, and docs expose correct provider behavior without secrets or ambiguous xAI-shaped Devin fields?
13. Are historical `init.plan.md` and `init.todo.md` untouched, are its four named blockers still separate/open, and are generated/source attribution and excluded-feature proofs complete?
14. Do focused, full, race, local smoke, migration, restart, and backup-restore proofs all match the claimed acceptance?
15. Is C12.5 checked with either sanitized live Devin evidence or the exact credential/operator blocker, with any unavailable live scenario remaining blocked only in evidence rather than as an open dependency for C12.6?
