-- The observation state is the sole durable source for hysteresis. Dropping
-- it with data would let a restart silently forget ticks and change promotion
-- timing, so rollback is permitted only before any observation is accepted.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM k8s_connector_pool_health_states)
       OR EXISTS (SELECT 1 FROM k8s_connector_pool_health_candidate_ticks) THEN
        RAISE EXCEPTION 'cannot roll back 0083: connector pool health history exists';
    END IF;
END;
$$;

DROP TRIGGER IF EXISTS set_updated_at ON k8s_connector_pool_health_candidate_ticks;
DROP TRIGGER IF EXISTS k8s_connector_pool_health_membership_inserted ON k8s_connector_pool_members;
DROP TRIGGER IF EXISTS k8s_connector_pool_health_membership_deleted ON k8s_connector_pool_members;
DROP TRIGGER IF EXISTS k8s_connector_pool_health_membership_updated ON k8s_connector_pool_members;
DROP FUNCTION IF EXISTS k8s_connector_pool_health_membership_changed();
DROP TRIGGER IF EXISTS k8s_connector_pool_health_pool_changed ON k8s_connector_pools;
DROP FUNCTION IF EXISTS k8s_connector_pool_health_pool_changed();
DROP TABLE IF EXISTS k8s_connector_pool_health_candidate_ticks;
DROP TRIGGER IF EXISTS set_updated_at ON k8s_connector_pool_health_states;
DROP TABLE IF EXISTS k8s_connector_pool_health_states;
