# Lessons

- `github.com/coreos/go-oidc/v3 v3.20.0` requires `golang.org/x/oauth2 v0.36.0`; the lower tracker baseline `v0.30.0` cannot be selected under Go MVS.
- `modernc.org/sqlite v1.53.0` pulls `modernc.org/libc v1.73.4`, which requires `golang.org/x/sync v0.20.0`; the lower tracker baseline `v0.18.0` cannot be selected under Go MVS.
- Go `embed` cannot reference parent directories. Root `migrations/*.sql` are embedded by the root `migrations` package and consumed by `internal/store`.
- `server.trusted_proxies` accepts IP addresses or CIDR prefixes. Web security treats `X-Forwarded-Proto: https` as authoritative only when `RemoteAddr` matches that configured set; otherwise forwarded headers are ignored.
- Administrator Web-password and API-key throttling share a keyed client-source identity. `X-Forwarded-For` is accepted only from configured trusted peers, parsed right-to-left to the first untrusted hop, and malformed trusted chains fail closed before credential evaluation.
- Railway Dockerfile start commands run in exec form, so `$PORT` expansion requires an explicit `/bin/sh -c "exec …"`; the deployment uses one persistent `/data` volume and trusts Railway proxy peers in `100.0.0.0/8` via `deploy/railway.yaml`.
- Railway rejects Dockerfiles containing a Docker `VOLUME` instruction; keep Compose on root `Dockerfile` and point `railway.json` to `Dockerfile.railway`, with persistence supplied only by the Railway Volume mounted at `/data`.
- Railway mounts persistent volumes as `root`; a Dockerfile `USER` set to a non-root UID cannot chmod or write `/data`. The dedicated Railway image must run as UID 0 while the application enforces owner-only directory and database modes.
- Browser form POSTs under `Referrer-Policy: no-referrer` can carry `Origin: null`, which Gorilla CSRF rejects even for same-origin forms. The administrator UI uses `Referrer-Policy: same-origin` so CSRF origin verification retains same-origin provenance without leaking referrers cross-origin.
- `oidc.NewVerifier` constructed manually defaults to `RS256` unless `SupportedSigningAlgs` is set. xAI discovery advertises `ES256`, so the discovered `id_token_signing_alg_values_supported` values must be propagated into the verifier.
- Go `1.26.4` is affected by `GO-2026-5856` in `crypto/tls` and `GO-2026-4970` in `os`; require Go `1.26.5` or newer for source builds. Fresh `golang:1.26-bookworm` builds currently resolve to `1.26.5`, but the tag remains mutable.
