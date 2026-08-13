DROP INDEX IF EXISTS policy_rules_user_k8s_service_uniq;
DROP INDEX IF EXISTS policy_rules_group_k8s_service_uniq;

ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_check CHECK (
    (dst_kind = 'resource' AND dst_resource_id IS NOT NULL AND dst_group_id IS NULL AND dst_site_id IS NULL)
 OR (dst_kind = 'group'    AND dst_group_id    IS NOT NULL AND dst_resource_id IS NULL AND dst_site_id IS NULL)
 OR (dst_kind = 'site'     AND dst_site_id     IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL));

ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_dst_kind_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_dst_kind_check
    CHECK (dst_kind IN ('resource', 'group', 'site'));

ALTER TABLE policy_rules DROP COLUMN dst_k8s_service_id;
