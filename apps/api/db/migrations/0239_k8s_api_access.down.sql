-- Rollback is refused while the feature holds data: an API rule cannot be represented in the 0123 checks,
-- and dropping an enabled endpoint would silently withdraw a path someone is using. Turn API access off
-- for every cluster and delete its rules first.
LOCK TABLE k8s_api_endpoints, policy_rules IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM policy_rules WHERE dst_kind = 'k8s_api')
       OR EXISTS (SELECT 1 FROM k8s_api_endpoints WHERE enabled) THEN
        RAISE EXCEPTION '0239 rollback refused: Kubernetes API access is on or has rules';
    END IF;
END;
$$;

DROP INDEX policy_rules_dst_k8s_api_endpoint_idx;
DROP INDEX policy_rules_user_k8s_api_uniq;
DROP INDEX policy_rules_group_k8s_api_uniq;
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_k8s_api_people_only;

ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_check;
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_dst_kind_check;
ALTER TABLE policy_rules DROP COLUMN dst_k8s_api_endpoint_id;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_dst_kind_check
    CHECK (dst_kind IN ('resource','group','site','k8s_service','fqdn_resource','k8s_cluster_scope'));
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_check CHECK (
    (dst_kind='resource' AND dst_resource_id IS NOT NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL AND dst_fqdn_resource_id IS NULL AND dst_k8s_cluster_id IS NULL)
 OR (dst_kind='group' AND dst_group_id IS NOT NULL AND dst_resource_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL AND dst_fqdn_resource_id IS NULL AND dst_k8s_cluster_id IS NULL)
 OR (dst_kind='site' AND dst_site_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_k8s_service_id IS NULL AND dst_fqdn_resource_id IS NULL AND dst_k8s_cluster_id IS NULL)
 OR (dst_kind='k8s_service' AND dst_k8s_service_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_fqdn_resource_id IS NULL AND dst_k8s_cluster_id IS NULL)
 OR (dst_kind='fqdn_resource' AND dst_fqdn_resource_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL AND dst_k8s_cluster_id IS NULL)
 OR (dst_kind='k8s_cluster_scope' AND dst_k8s_cluster_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL AND dst_fqdn_resource_id IS NULL)
);

DROP TRIGGER k8s_service_identities_api_vip_before_write ON k8s_service_identities;
DROP FUNCTION k8s_service_identities_refuse_api_vip();
DROP TRIGGER k8s_api_endpoints_vip_before_write ON k8s_api_endpoints;
DROP FUNCTION k8s_api_endpoints_check_vip();
DROP TABLE k8s_api_endpoints;
