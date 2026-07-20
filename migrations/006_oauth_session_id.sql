-- 006_oauth_session_id.sql
-- Add a random opaque public SessionID distinct from the raw OAuth state.
--
-- The raw state remains durably represented only by state_hash (callback-PKCE)
-- or encrypted plaintext (legacy device flow) and is never exposed to callers.
-- session_id is a public, plaintext, provider+flow-bound handle that lets the
-- admin/CLI/Web surfaces poll and cancel an authorization without ever seeing
-- the raw state. It is unique within a (provider, flow_type) pair so a status
-- lookup cannot cross providers or flows.
--
-- Legacy rows created before this migration have no SessionID. The column is
-- nullable so the migration applies cleanly; a Go post-migration step
-- (store.BackfillOAuthSessionIDs) populates every existing row with a distinct
-- CSPRNG-generated SessionID using crypto/rand and creates the unique partial
-- index. New rows always carry a SessionID enforced by the application layer.

ALTER TABLE oauth_sessions
    ADD COLUMN session_id TEXT;
