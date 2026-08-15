-- ⛔ FAIL CLOSED ON POPULATED SCOPE STATE. Rolling 0086 back must never turn a
-- live policy decision into an invisible deletion. The supported recovery is
-- to preserve/export the scope data, remove the scope intentionally through
-- its normal policy lifecycle, then retry this down migration. PostgreSQL runs
-- the migration in one transaction, so this refusal leaves both schema and
-- data exactly as they were.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM policy_rules WHERE dst_kind = 'k8s_cluster_scope')
       OR EXISTS (SELECT 1 FROM k8s_cluster_scope_grants)
       OR EXISTS (SELECT 1 FROM k8s_cluster_scope_memberships) THEN
        RAISE EXCEPTION 'cannot rollback 0086 with cluster-scope policy or decision data; export or intentionally remove scope state first';
    END IF;
END;
$$;

DROP TRIGGER IF EXISTS k8s_cluster_scope_memberships_decision_before_update ON k8s_cluster_scope_memberships;
DROP TRIGGER IF EXISTS k8s_cluster_scope_memberships_actor_before_write ON k8s_cluster_scope_memberships;
DROP TRIGGER IF EXISTS k8s_cluster_scope_grants_actor_before_write ON k8s_cluster_scope_grants;
DROP FUNCTION IF EXISTS k8s_cluster_scope_membership_decision_immutable();
DROP FUNCTION IF EXISTS k8s_cluster_scope_actor_require_org_membership();
DROP TRIGGER IF EXISTS k8s_cluster_scope_memberships_identity_before_update ON k8s_cluster_scope_memberships;
DROP FUNCTION IF EXISTS k8s_cluster_scope_membership_identity_immutable();
DROP TRIGGER IF EXISTS k8s_cluster_scope_memberships_require_live_identity_before_insert ON k8s_cluster_scope_memberships;
DROP FUNCTION IF EXISTS k8s_cluster_scope_membership_require_live_identity();
DROP TRIGGER IF EXISTS k8s_cluster_scope_memberships_bound_before_insert ON k8s_cluster_scope_memberships;
DROP TRIGGER IF EXISTS k8s_cluster_scope_grants_bound_before_write ON k8s_cluster_scope_grants;
DROP FUNCTION IF EXISTS k8s_cluster_scope_bound_write();
DROP TRIGGER IF EXISTS k8s_cluster_scope_grants_require_rule_before_write ON k8s_cluster_scope_grants;
DROP FUNCTION IF EXISTS k8s_cluster_scope_grant_require_rule();
DROP TABLE IF EXISTS k8s_cluster_scope_memberships;
DROP TABLE IF EXISTS k8s_cluster_scope_grants;

DROP INDEX IF EXISTS policy_rules_k8s_cluster_scope_idx;
DROP INDEX IF EXISTS policy_rules_group_k8s_cluster_scope_uniq;
DROP INDEX IF EXISTS policy_rules_user_k8s_cluster_scope_uniq;
DROP INDEX IF EXISTS policy_rules_site_k8s_cluster_scope_uniq;
DROP INDEX IF EXISTS policy_rules_cidr_k8s_cluster_scope_uniq;
DROP INDEX IF EXISTS policy_rules_agent_k8s_cluster_scope_uniq;
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_check;
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_dst_kind_check;
ALTER TABLE policy_rules DROP COLUMN dst_k8s_cluster_id;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_dst_kind_check
    CHECK (dst_kind IN ('resource', 'group', 'site', 'k8s_service'));
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_check CHECK (
    (dst_kind = 'resource' AND dst_resource_id IS NOT NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL)
 OR (dst_kind = 'group' AND dst_group_id IS NOT NULL AND dst_resource_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL)
 OR (dst_kind = 'site' AND dst_site_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_k8s_service_id IS NULL)
 OR (dst_kind = 'k8s_service' AND dst_k8s_service_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_site_id IS NULL)
);
