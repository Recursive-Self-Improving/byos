CREATE TABLE response_sessions_new (
    response_id TEXT PRIMARY KEY,
    upstream_response_id TEXT,
    previous_response_id TEXT,
    model TEXT NOT NULL,
    preferred_account_id TEXT,
    input_encrypted TEXT NOT NULL,
    output_encrypted TEXT NOT NULL,
    store INTEGER NOT NULL CHECK (store IN (0, 1)),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

INSERT INTO response_sessions_new(response_id, upstream_response_id, previous_response_id, model, preferred_account_id, input_encrypted, output_encrypted, store, created_at, expires_at)
SELECT response_id, upstream_response_id, previous_response_id, model, preferred_account_id, input_encrypted, output_encrypted, store, created_at, expires_at
FROM response_sessions;

DROP TABLE response_sessions;
ALTER TABLE response_sessions_new RENAME TO response_sessions;
CREATE INDEX response_sessions_previous_idx ON response_sessions(previous_response_id);
CREATE INDEX response_sessions_expiry_idx ON response_sessions(expires_at);
