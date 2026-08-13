-- 0015 audit-log viewer indexes (S4.6).
--
-- The viewer adds keyset pagination + actor/action/date filters over the
-- forever-growing audit_logs. Every index leads with org_id (tenant scoping),
-- then the filter column, then created_at DESC for the ordering.
--
-- DEPLOY NOTE (EPIC 11 runbook): at production scale these should be built with
-- CREATE INDEX CONCURRENTLY (out-of-band, non-transactional). Here they are plain
-- CREATE INDEX — the table is dev-scale and the migration stays atomic/reversible.

-- Keyset ordering: (created_at, id) DESC as the exact cursor tuple. Replaces the
-- created_at-only index (subsumed by this one for the default feed + keyset).
DROP INDEX IF EXISTS audit_logs_org_id_created_at_idx;
CREATE INDEX audit_logs_org_created_id_idx ON audit_logs (org_id, created_at DESC, id DESC);

-- Filter paths. The id DESC tiebreak is INCLUDED so a fixed actor/action gives
-- the exact ORDER BY (created_at DESC, id DESC) from the index — without it the
-- planner falls back to the org_created_id index + a Filter (the id-less form is
-- dead weight, verified via EXPLAIN).
CREATE INDEX audit_logs_org_actor_created_idx ON audit_logs (org_id, actor_user_id, created_at DESC, id DESC);
CREATE INDEX audit_logs_org_action_created_idx ON audit_logs (org_id, action, created_at DESC, id DESC);
