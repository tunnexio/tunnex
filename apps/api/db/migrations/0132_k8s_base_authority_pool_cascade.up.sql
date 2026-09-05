-- Base-authority deliveries are durable evidence and outlive an individual
-- cluster. Their pool-attribution rows do not: remove only the join row when
-- the cluster-owned connector pool is deleted.
DO $$
DECLARE
    fk_name name;
BEGIN
    SELECT c.conname INTO fk_name
    FROM pg_constraint c
    WHERE c.conrelid = 'k8s_base_authority_delivery_pools'::regclass
      AND c.confrelid = 'k8s_connector_pools'::regclass
      AND c.contype = 'f';

    IF fk_name IS NULL THEN
        RAISE EXCEPTION 'k8s base-authority delivery pool FK is missing';
    END IF;

    EXECUTE format(
        'ALTER TABLE k8s_base_authority_delivery_pools DROP CONSTRAINT %I',
        fk_name
    );
END;
$$;

ALTER TABLE k8s_base_authority_delivery_pools
    ADD CONSTRAINT k8s_base_authority_delivery_pools_pool_scope_fkey
    FOREIGN KEY (pool_id, org_id, site_id, cluster_id)
    REFERENCES k8s_connector_pools (id, org_id, site_id, cluster_id)
    ON DELETE CASCADE;
