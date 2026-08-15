-- A durable operation is the only provenance for an in-flight or completed
-- ownership handoff. Dropping it would erase replay/CAS evidence and let an
-- old artifact be mistaken for fresh after re-up, so rollback is permitted
-- only while the table is empty.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM k8s_connector_handoff_operations) THEN
        RAISE EXCEPTION 'cannot roll back 0082: connector handoff operations exist';
    END IF;
END;
$$;

DROP TRIGGER IF EXISTS k8s_connector_handoff_operations_enforce_update ON k8s_connector_handoff_operations;
DROP FUNCTION IF EXISTS k8s_connector_handoff_operations_enforce_update();
DROP TABLE IF EXISTS k8s_connector_handoff_operations;
ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS audit_logs_id_org_key;
