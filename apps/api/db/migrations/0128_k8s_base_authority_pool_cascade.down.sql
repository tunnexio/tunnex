ALTER TABLE k8s_base_authority_delivery_pools
    DROP CONSTRAINT k8s_base_authority_delivery_pools_pool_scope_fkey;

ALTER TABLE k8s_base_authority_delivery_pools
    ADD CONSTRAINT k8s_base_authority_delivery_pools_pool_scope_fkey
    FOREIGN KEY (pool_id, org_id, site_id, cluster_id)
    REFERENCES k8s_connector_pools (id, org_id, site_id, cluster_id)
    ON DELETE RESTRICT;
