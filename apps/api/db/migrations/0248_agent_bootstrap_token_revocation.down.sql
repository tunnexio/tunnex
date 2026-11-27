-- Dropping revoked_at would make a revoked, not-yet-expired token redeemable
-- again. Remove revoked tokens first so a rollback never restores access.
DELETE FROM agent_bootstrap_tokens WHERE revoked_at IS NOT NULL;
ALTER TABLE agent_bootstrap_tokens
    DROP CONSTRAINT IF EXISTS agent_bootstrap_tokens_revoked_ck,
    DROP COLUMN IF EXISTS revoked_by,
    DROP COLUMN IF EXISTS revoked_at;
