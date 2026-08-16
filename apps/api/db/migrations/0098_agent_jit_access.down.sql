-- Preservation first: rollback is supported only before F10 carries state.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM organizations WHERE agent_jit_access_enabled)
       OR EXISTS (SELECT 1 FROM agent_access_request_operations)
       OR EXISTS (SELECT 1 FROM agent_access_request_events)
       OR EXISTS (SELECT 1 FROM agent_access_requests) THEN
        RAISE EXCEPTION 'cannot roll back 0098: agent JIT access state exists';
    END IF;
END;
$$;

DROP TABLE agent_access_request_operations;
DROP TABLE agent_access_request_events;
DROP FUNCTION agent_access_request_events_prevent_mutation();
DROP TRIGGER agent_access_requests_destination_snapshot_no_update ON agent_access_requests;
DROP FUNCTION agent_access_request_destination_snapshot_immutable();
DROP TRIGGER agent_access_requests_snapshot_destination_before_write ON agent_access_requests;
DROP FUNCTION agent_access_request_snapshot_destination();
DROP TRIGGER agent_access_requests_require_managed_agent_before_write ON agent_access_requests;
DROP FUNCTION agent_access_request_require_managed_agent();
DROP TABLE agent_access_requests;
ALTER TABLE organizations DROP COLUMN agent_jit_access_enabled;
