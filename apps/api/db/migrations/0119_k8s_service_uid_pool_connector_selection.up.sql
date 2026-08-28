-- S20.3a: extend 0084's selected-connector fence to connector-pool mode.
-- Existing single-connector clusters keep their exact legacy predicate. A
-- pool-bound cluster accepts observations only from its current, eligible
-- active member; there is no fallback across ownership modes.
CREATE OR REPLACE FUNCTION k8s_service_uid_observation_require_selected_connector() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM k8s_clusters c
        WHERE c.id = NEW.cluster_id
          AND c.org_id = NEW.org_id
          AND c.site_id = NEW.site_id
          AND (
              (
                  c.connector_pool_id IS NULL
                  AND c.connector_node_id = NEW.connector_node_id
              )
              OR
              (
                  c.connector_node_id IS NULL
                  AND c.connector_pool_id IS NOT NULL
                  AND EXISTS (
                      SELECT 1
                      FROM k8s_connector_pools p
                      JOIN k8s_connector_pool_members m
                        ON m.pool_id = p.id
                       AND m.org_id = p.org_id
                       AND m.site_id = p.site_id
                       AND m.node_id = p.active_node_id
                      JOIN nodes n
                        ON n.id = m.node_id
                       AND n.org_id = m.org_id
                       AND n.site_id = m.site_id
                      WHERE p.id = c.connector_pool_id
                        AND p.org_id = c.org_id
                        AND p.site_id = c.site_id
                        AND p.cluster_id = c.id
                        AND p.active_node_id = NEW.connector_node_id
                        AND p.generation > 0
                        AND n.status = 'active'
                        AND n.revoked_at IS NULL
                        AND n.wg_public_key ~ '^[A-Za-z0-9+/]{43}=$'
                        AND btrim(n.endpoint) <> ''
                  )
              )
          )
    ) THEN
        RAISE EXCEPTION 'Kubernetes Service UID observation connector is not selected and eligible for cluster';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 0084 checks inserts and scope-identity changes. Recheck the same authority
-- when the durable replay high-watermark advances so a connector revoked or
-- demoted after state creation cannot keep publishing through its old row.
CREATE TRIGGER k8s_service_uid_observation_require_selected_connector_before_progress
    BEFORE UPDATE OF sequence, digest
    ON k8s_service_uid_observation_replay_states
    FOR EACH ROW EXECUTE FUNCTION k8s_service_uid_observation_require_selected_connector();
