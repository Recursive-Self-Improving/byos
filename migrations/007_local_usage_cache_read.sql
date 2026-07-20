-- 007_local_usage_cache_read.sql
-- Persist cache-read token accounting alongside the existing local proxy counters.
--
-- Cache-read tokens are a per-response usage observation reported by Devin
-- (and the OpenAI Responses shape used by xAI) inside input_tokens_details.
-- They are local proxy counters only: they never influence routing and are
-- not treated as upstream billing quota. Existing rows default to zero so the
-- migration applies cleanly against any v3+ schema without rewriting history.

ALTER TABLE local_usage_counters
    ADD COLUMN cache_read_tokens INTEGER NOT NULL DEFAULT 0 CHECK (cache_read_tokens >= 0);
