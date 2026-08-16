-- Preservation first: F09 down is supported only before the capability carries
-- state. PostgreSQL runs this migration transactionally, so refusal changes
-- neither schema nor rows.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM organizations WHERE agent_policy_templates_enabled)
       OR EXISTS (SELECT 1 FROM agent_policy_template_rule_bindings)
       OR EXISTS (SELECT 1 FROM agent_policy_template_assignments)
       OR EXISTS (SELECT 1 FROM agent_policy_template_version_items)
       OR EXISTS (SELECT 1 FROM agent_policy_template_versions)
       OR EXISTS (SELECT 1 FROM agent_policy_templates)
       OR EXISTS (SELECT 1 FROM agent_group_members)
       OR EXISTS (SELECT 1 FROM agent_groups)
       OR EXISTS (SELECT 1 FROM policy_rules WHERE src_kind = 'agent_group') THEN
        RAISE EXCEPTION 'cannot roll back 0097: agent group or policy template state exists';
    END IF;
END;
$$;

DROP TABLE agent_policy_template_rule_bindings;
DROP TABLE agent_policy_template_assignments;
DROP TABLE agent_policy_template_version_items;
DROP TABLE agent_policy_template_versions;
DROP TABLE agent_policy_templates;

DROP INDEX policy_rules_agent_group_k8s_cluster_scope_uniq;
DROP INDEX policy_rules_agent_group_k8s_service_uniq;
DROP INDEX policy_rules_agent_group_site_uniq;
DROP INDEX policy_rules_agent_group_group_uniq;
DROP INDEX policy_rules_agent_group_resource_uniq;
DROP INDEX policy_rules_src_agent_group_idx;
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_src_check;
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_src_kind_check;
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_src_agent_group_fk;
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_id_org_key;
ALTER TABLE policy_rules DROP COLUMN src_agent_group_id;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_src_kind_check
    CHECK (src_kind IN ('group', 'user', 'site', 'cidr', 'agent'));
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_src_check CHECK (
    (src_kind = 'group' AND src_group_id IS NOT NULL AND src_user_id IS NULL AND src_site_id IS NULL AND src_cidr IS NULL AND src_device_id IS NULL)
 OR (src_kind = 'user' AND src_user_id IS NOT NULL AND src_group_id IS NULL AND src_site_id IS NULL AND src_cidr IS NULL AND src_device_id IS NULL)
 OR (src_kind = 'site' AND src_site_id IS NOT NULL AND src_group_id IS NULL AND src_user_id IS NULL AND src_cidr IS NULL AND src_device_id IS NULL)
 OR (src_kind = 'cidr' AND src_cidr IS NOT NULL AND src_group_id IS NULL AND src_user_id IS NULL AND src_site_id IS NULL AND src_device_id IS NULL)
 OR (src_kind = 'agent' AND src_device_id IS NOT NULL AND src_group_id IS NULL AND src_user_id IS NULL AND src_site_id IS NULL AND src_cidr IS NULL)
);

DROP TABLE agent_group_members;
DROP FUNCTION agent_policy_template_actor_require_membership();
DROP FUNCTION agent_group_member_require_live_agent();
DROP TABLE agent_groups;

ALTER TABLE k8s_services DROP CONSTRAINT k8s_services_id_org_key;
ALTER TABLE sites DROP CONSTRAINT sites_id_org_key;
ALTER TABLE user_groups DROP CONSTRAINT user_groups_id_org_key;
ALTER TABLE resources DROP CONSTRAINT resources_id_org_key;
ALTER TABLE devices DROP CONSTRAINT devices_id_org_key;
ALTER TABLE organizations DROP COLUMN agent_policy_templates_enabled;
