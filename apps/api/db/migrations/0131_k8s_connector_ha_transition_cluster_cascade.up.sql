-- A connector pool is cluster-owned and already cascade-deletes with its
-- cluster. HA transition state has no independent lifetime, so it must follow
-- that pool cascade instead of blocking cluster deregistration.
DO $$
DECLARE
    fk_name name;
BEGIN
    SELECT c.conname INTO fk_name
    FROM pg_constraint c
    WHERE c.conrelid = 'k8s_connector_pool_ha_transitions'::regclass
      AND c.confrelid = 'k8s_connector_pools'::regclass
      AND c.contype = 'f';

    IF fk_name IS NULL THEN
        RAISE EXCEPTION 'k8s connector HA transition pool FK is missing';
    END IF;

    EXECUTE format(
        'ALTER TABLE k8s_connector_pool_ha_transitions DROP CONSTRAINT %I',
        fk_name
    );
END;
$$;

ALTER TABLE k8s_connector_pool_ha_transitions
    ADD CONSTRAINT k8s_connector_pool_ha_transitions_pool_scope_fkey
    FOREIGN KEY (pool_id, org_id, site_id, cluster_id)
    REFERENCES k8s_connector_pools (id, org_id, site_id, cluster_id)
    ON DELETE CASCADE;
