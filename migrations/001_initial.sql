CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    identity_fingerprint BLOB NOT NULL UNIQUE,
    label TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    status TEXT NOT NULL,
    credentials_encrypted TEXT NOT NULL,
    expires_at INTEGER,
    last_refresh_at INTEGER,
    last_error TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE account_model_capabilities (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    model TEXT NOT NULL,
    supported INTEGER NOT NULL CHECK (supported IN (0, 1)),
    supports_backend_search INTEGER,
    display_name TEXT,
    context_window INTEGER,
    max_output_tokens INTEGER,
    reasoning_efforts TEXT,
    discovered_at INTEGER NOT NULL,
    stale INTEGER NOT NULL DEFAULT 0 CHECK (stale IN (0, 1)),
    PRIMARY KEY (account_id, model)
);

CREATE TABLE account_model_states (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    model TEXT NOT NULL,
    cooldown_until INTEGER,
    backoff_level INTEGER NOT NULL DEFAULT 0,
    last_error_class TEXT,
    last_error_at INTEGER,
    PRIMARY KEY (account_id, model)
);

CREATE TABLE oauth_sessions (
    state_hash BLOB PRIMARY KEY,
    payload_encrypted TEXT NOT NULL,
    status TEXT NOT NULL,
    poll_interval_seconds INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    sanitized_error TEXT
);
CREATE INDEX oauth_sessions_expiry_idx ON oauth_sessions(expires_at);

CREATE TABLE usage_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    normalized_json TEXT NOT NULL,
    raw_encrypted TEXT,
    fetched_at INTEGER NOT NULL,
    stale INTEGER NOT NULL DEFAULT 0 CHECK (stale IN (0, 1)),
    error TEXT
);
CREATE INDEX usage_snapshots_account_fetched_idx ON usage_snapshots(account_id, fetched_at DESC);

CREATE TABLE api_keys (
    id TEXT PRIMARY KEY,
    prefix TEXT NOT NULL,
    key_hash BLOB NOT NULL UNIQUE,
    label TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at INTEGER
);
CREATE INDEX api_keys_prefix_idx ON api_keys(prefix);

CREATE TABLE response_sessions (
    response_id TEXT PRIMARY KEY,
    upstream_response_id TEXT,
    previous_response_id TEXT REFERENCES response_sessions(response_id) ON DELETE SET NULL,
    model TEXT NOT NULL,
    preferred_account_id TEXT,
    input_encrypted TEXT NOT NULL,
    output_encrypted TEXT NOT NULL,
    store INTEGER NOT NULL CHECK (store IN (0, 1)),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX response_sessions_previous_idx ON response_sessions(previous_response_id);
CREATE INDEX response_sessions_expiry_idx ON response_sessions(expires_at);

CREATE TABLE admin_sessions (
    id_hash BLOB PRIMARY KEY,
    csrf_secret_encrypted TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE INDEX admin_sessions_expiry_idx ON admin_sessions(expires_at);
