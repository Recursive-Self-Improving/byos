ALTER TABLE accounts
    ADD COLUMN provider TEXT NOT NULL DEFAULT 'xai'
    CHECK (provider IN ('xai', 'devin'));

CREATE INDEX accounts_provider_status_idx
    ON accounts(provider, status);

ALTER TABLE oauth_sessions
    ADD COLUMN provider TEXT NOT NULL DEFAULT 'xai'
    CHECK (provider IN ('xai', 'devin'));

ALTER TABLE oauth_sessions
    ADD COLUMN flow_type TEXT NOT NULL DEFAULT 'device'
    CHECK (flow_type IN ('device', 'callback_pkce'));

CREATE INDEX oauth_sessions_provider_flow_status_expiry_idx
    ON oauth_sessions(provider, flow_type, status, expires_at);
