CREATE TABLE admin_auth_sources (
    source_hash BLOB PRIMARY KEY CHECK(length(source_hash) = 32),
    failure_count INTEGER NOT NULL CHECK(failure_count BETWEEN 1 AND 5),
    blocked_until INTEGER,
    last_failure_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX admin_auth_sources_updated_idx ON admin_auth_sources(updated_at);

CREATE TABLE admin_auth_global (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    window_started_at INTEGER NOT NULL,
    source_locks INTEGER NOT NULL CHECK(source_locks >= 0),
    blocked_until INTEGER,
    updated_at INTEGER NOT NULL
);
