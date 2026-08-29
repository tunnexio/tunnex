-- Rollback is safe only before any S20.4 data exists. Scope rows created by
-- either the dormant or activated writer also block contraction because the
-- old CASCADE behavior would weaken deregistration semantics.
LOCK TABLE k8s_service_inventory_ports,
           k8s_service_inventory_items,
           k8s_service_inventory_reports,
           k8s_cluster_scope_initial_candidates,
           k8s_cluster_scope_memberships,
           k8s_cluster_scope_grants,
           k8s_cluster_scope_settings,
           policy_rules IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM k8s_cluster_scope_settings)
       OR EXISTS (SELECT 1 FROM k8s_service_inventory_reports)
       OR EXISTS (SELECT 1 FROM k8s_cluster_scope_initial_candidates)
       OR EXISTS (SELECT 1 FROM k8s_cluster_scope_grants)
       OR EXISTS (SELECT 1 FROM policy_rules WHERE dst_kind='k8s_cluster_scope') THEN
        RAISE EXCEPTION '0123 rollback refused: Kubernetes cluster-scope activation data exists';
    END IF;
END;
$$;

ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_check;
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_dst_kind_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_dst_kind_check
    CHECK (dst_kind IN ('resource','group','site','k8s_service','fqdn_resource'));
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_check CHECK (
    (dst_kind='resource' AND dst_resource_id IS NOT NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL AND dst_fqdn_resource_id IS NULL)
 OR (dst_kind='group' AND dst_group_id IS NOT NULL AND dst_resource_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL AND dst_fqdn_resource_id IS NULL)
 OR (dst_kind='site' AND dst_site_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_k8s_service_id IS NULL AND dst_fqdn_resource_id IS NULL)
 OR (dst_kind='k8s_service' AND dst_k8s_service_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_fqdn_resource_id IS NULL)
 OR (dst_kind='fqdn_resource' AND dst_fqdn_resource_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL)
);

ALTER TABLE k8s_cluster_scope_grants
    DROP CONSTRAINT k8s_cluster_scope_grants_cluster_id_fkey;
ALTER TABLE k8s_cluster_scope_grants
    ADD CONSTRAINT k8s_cluster_scope_grants_cluster_id_fkey
    FOREIGN KEY (cluster_id) REFERENCES k8s_clusters (id) ON DELETE CASCADE;

ALTER TABLE k8s_cluster_scope_grants
    DROP CONSTRAINT k8s_cluster_scope_grants_initial_candidate_count_check;
ALTER TABLE k8s_cluster_scope_grants
    DROP COLUMN revision;
ALTER TABLE k8s_cluster_scope_grants
    ADD CONSTRAINT k8s_cluster_scope_grants_initial_candidate_count_check
    CHECK (initial_candidate_count BETWEEN 0 AND 100);

DROP TRIGGER a_k8s_cluster_scope_memberships_capacity_before_insert ON k8s_cluster_scope_memberships;
DROP FUNCTION k8s_cluster_scope_serialize_membership_capacity();
DROP TRIGGER k8s_cluster_scope_memberships_before_truncate ON k8s_cluster_scope_memberships;
DROP TRIGGER k8s_cluster_scope_memberships_before_delete ON k8s_cluster_scope_memberships;
DROP FUNCTION k8s_cluster_scope_membership_refuse_direct_delete();
DROP TRIGGER k8s_cluster_scope_memberships_initial_snapshot_after_write ON k8s_cluster_scope_memberships;
DROP TRIGGER k8s_cluster_scope_grants_initial_snapshot_after_write ON k8s_cluster_scope_grants;
DROP TRIGGER k8s_cluster_scope_initial_candidates_verify_after_write ON k8s_cluster_scope_initial_candidates;
DROP FUNCTION k8s_cluster_scope_verify_initial_snapshot();
DROP TRIGGER k8s_cluster_scope_initial_candidates_identity_before_insert ON k8s_cluster_scope_initial_candidates;
DROP FUNCTION k8s_cluster_scope_initial_candidate_require_identity();

DROP TRIGGER k8s_cluster_scope_initial_candidates_before_update ON k8s_cluster_scope_initial_candidates;
DROP TRIGGER k8s_cluster_scope_initial_candidates_before_truncate ON k8s_cluster_scope_initial_candidates;
DROP FUNCTION k8s_cluster_scope_initial_candidate_immutable();
DROP TABLE k8s_cluster_scope_initial_candidates;

DROP TRIGGER k8s_service_inventory_items_uid_before_insert ON k8s_service_inventory_items;
DROP FUNCTION k8s_service_inventory_require_current_uid();
DROP TRIGGER k8s_service_inventory_reports_reporter_before_write ON k8s_service_inventory_reports;
DROP FUNCTION k8s_service_inventory_require_current_reporter();
DROP TRIGGER k8s_service_inventory_ports_count_after_write ON k8s_service_inventory_ports;
DROP TRIGGER k8s_service_inventory_items_count_after_write ON k8s_service_inventory_items;
DROP TRIGGER k8s_service_inventory_reports_count_after_write ON k8s_service_inventory_reports;
DROP FUNCTION k8s_service_inventory_verify_counts();
DROP TRIGGER k8s_service_inventory_ports_before_truncate ON k8s_service_inventory_ports;
DROP TRIGGER k8s_service_inventory_items_before_truncate ON k8s_service_inventory_items;
DROP TRIGGER k8s_service_inventory_reports_before_truncate ON k8s_service_inventory_reports;
DROP FUNCTION k8s_service_inventory_refuse_truncate();
DROP TRIGGER k8s_service_inventory_ports_immutable_before_change ON k8s_service_inventory_ports;
DROP TRIGGER k8s_service_inventory_items_immutable_before_change ON k8s_service_inventory_items;
DROP TRIGGER k8s_service_inventory_reports_immutable_before_change ON k8s_service_inventory_reports;
DROP FUNCTION k8s_service_inventory_snapshot_immutable();
DROP TABLE k8s_service_inventory_ports;
DROP TABLE k8s_service_inventory_items;
DROP TABLE k8s_service_inventory_reports;
DROP TRIGGER k8s_cluster_scope_settings_actor_before_write ON k8s_cluster_scope_settings;
DROP FUNCTION k8s_cluster_scope_setting_require_actor_membership();
DROP TABLE k8s_cluster_scope_settings;
