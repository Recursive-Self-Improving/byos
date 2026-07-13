CREATE TABLE local_usage_counters (
    account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    requests INTEGER NOT NULL DEFAULT 0 CHECK (requests >= 0),
    failures INTEGER NOT NULL DEFAULT 0 CHECK (failures >= 0),
    input_tokens INTEGER NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    output_tokens INTEGER NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
    updated_at INTEGER NOT NULL
);
