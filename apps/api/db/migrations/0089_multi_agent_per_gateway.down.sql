-- Restoring 0067's one-live-agent-per-gateway constraint is lossless only while
-- no gateway actually has multiple live agent rows. Refuse rollback rather than
-- deleting or arbitrarily retaining one independently identified peer.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM devices
        WHERE kind = 'agent' AND deleted_at IS NULL
        GROUP BY node_id
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION '0089 rollback refused: multiple live agents are present on one gateway';
    END IF;
END
$$;

CREATE UNIQUE INDEX devices_agent_node_key ON devices (node_id)
    WHERE kind = 'agent' AND deleted_at IS NULL;
