DROP INDEX IF EXISTS k8s_clusters_connector_pool_idx;
ALTER TABLE k8s_clusters
    DROP CONSTRAINT IF EXISTS k8s_clusters_connector_mode_check,
    DROP CONSTRAINT IF EXISTS k8s_clusters_connector_pool_fk,
    DROP COLUMN IF EXISTS connector_pool_id;
-- Pools and members have intentionally reciprocal FKs: membership owns a
-- pool, while preferred/active state must name a member. Remove the two
-- reverse state constraints first, then drop child membership before pool.
ALTER TABLE k8s_connector_pools
    DROP CONSTRAINT IF EXISTS k8s_connector_pools_preferred_member_fk,
    DROP CONSTRAINT IF EXISTS k8s_connector_pools_active_member_fk;
DROP TABLE IF EXISTS k8s_connector_pool_members;
DROP TABLE IF EXISTS k8s_connector_pools;
ALTER TABLE k8s_clusters DROP CONSTRAINT IF EXISTS k8s_clusters_id_org_site_key;
ALTER TABLE nodes DROP CONSTRAINT IF EXISTS nodes_id_org_site_key;
