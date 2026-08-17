-- Do not silently discard a live security decision during rollback. Operators
-- must disable managed runtime synchronization before reverting this schema.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM organizations
        WHERE managed_agent_runtime_enabled = true AND deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION '0093 rollback refused: managed agent runtime is enabled for a live organization';
    END IF;
END;
$$;

ALTER TABLE organizations
    DROP COLUMN IF EXISTS managed_agent_runtime_enabled;
