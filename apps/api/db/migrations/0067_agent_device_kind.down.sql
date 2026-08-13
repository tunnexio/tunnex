-- Reverses 0067: restore the cap index over all kinds, drop the agent uniqueness and the column.
DROP INDEX IF EXISTS devices_agent_node_key;
DROP INDEX IF EXISTS devices_org_user_active_human_idx;
CREATE INDEX IF NOT EXISTS devices_org_user_active_idx ON devices (org_id, user_id)
    WHERE status = 'active' AND deleted_at IS NULL;
ALTER TABLE devices DROP COLUMN IF EXISTS kind;
