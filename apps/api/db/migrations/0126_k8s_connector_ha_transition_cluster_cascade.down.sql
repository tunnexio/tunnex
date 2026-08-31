ALTER TABLE k8s_connector_pool_ha_transitions
    DROP CONSTRAINT k8s_connector_pool_ha_transitions_pool_scope_fkey;

ALTER TABLE k8s_connector_pool_ha_transitions
    ADD CONSTRAINT k8s_connector_pool_ha_transitions_pool_scope_fkey
    FOREIGN KEY (pool_id, org_id, site_id, cluster_id)
    REFERENCES k8s_connector_pools (id, org_id, site_id, cluster_id)
    ON DELETE RESTRICT;
