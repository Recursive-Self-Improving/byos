# Lessons

- `github.com/coreos/go-oidc/v3 v3.20.0` requires `golang.org/x/oauth2 v0.36.0`; the lower tracker baseline `v0.30.0` cannot be selected under Go MVS.
- `modernc.org/sqlite v1.53.0` pulls `modernc.org/libc v1.73.4`, which requires `golang.org/x/sync v0.20.0`; the lower tracker baseline `v0.18.0` cannot be selected under Go MVS.
- Go `embed` cannot reference parent directories. Root `migrations/*.sql` are embedded by the root `migrations` package and consumed by `internal/store`.
- `server.trusted_proxies` accepts IP addresses or CIDR prefixes. Web security treats `X-Forwarded-Proto: https` as authoritative only when `RemoteAddr` matches that configured set; otherwise forwarded headers are ignored.
