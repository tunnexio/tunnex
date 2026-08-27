-- A downgrade must never erase policy destinations, immutable publication
-- history, or port-restriction intent.  Empty schema-only installations can
-- move backward; any real use refuses loudly.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM policy_rules WHERE dst_kind = 'fqdn_resource')
       OR EXISTS (SELECT 1 FROM fqdn_resource_answer_generations WHERE state <> 'pending')
       OR EXISTS (SELECT 1 FROM fqdn_resources WHERE port_low IS NOT NULL OR port_high IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot roll back 0113: FQDN policy destination or published generation data exists';
    END IF;
END $$;

DROP TRIGGER fqdn_generation_published_immutable_before_delete ON fqdn_resource_answer_generations;
DROP TRIGGER fqdn_generation_published_immutable_before_update ON fqdn_resource_answer_generations;
DROP FUNCTION fqdn_generation_published_immutable();
DROP TRIGGER fqdn_policy_rule_reference_mirror_after_write ON policy_rules;
DROP FUNCTION fqdn_policy_rule_reference_mirror();
ALTER TABLE fqdn_resources DROP CONSTRAINT fqdn_resources_ports_complete_check;
ALTER TABLE fqdn_resources ADD CONSTRAINT fqdn_resources_check CHECK ((protocol = 'any' AND port_low IS NULL AND port_high IS NULL) OR (protocol IN ('tcp', 'udp') AND (port_low IS NULL OR port_high IS NULL OR port_low <= port_high)));
ALTER TABLE resources DROP CONSTRAINT resources_ports_complete_check;
ALTER TABLE resources ADD CONSTRAINT resources_check CHECK ((protocol = 'any' AND port_low IS NULL AND port_high IS NULL) OR (protocol IN ('tcp', 'udp')));
ALTER TABLE resources ADD CONSTRAINT resources_check1 CHECK (port_low IS NULL OR port_high IS NULL OR port_low <= port_high);
DROP INDEX policy_rules_org_dst_fqdn_resource_idx;
DROP INDEX policy_rules_group_fqdn_resource_uniq;
DROP INDEX policy_rules_user_fqdn_resource_uniq;
DROP INDEX policy_rules_site_fqdn_resource_uniq;
DROP INDEX policy_rules_cidr_fqdn_resource_uniq;
DROP INDEX policy_rules_agent_fqdn_resource_uniq;
DROP INDEX policy_rules_agent_group_fqdn_resource_uniq;
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_dst_fqdn_resource_org_fkey;
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_check;
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_dst_kind_check;
ALTER TABLE policy_rules DROP COLUMN dst_fqdn_resource_id;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_dst_kind_check
    CHECK (dst_kind IN ('resource', 'group', 'site', 'k8s_service'));
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_check CHECK (
    (dst_kind = 'resource' AND dst_resource_id IS NOT NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL)
 OR (dst_kind = 'group' AND dst_group_id IS NOT NULL AND dst_resource_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL)
 OR (dst_kind = 'site' AND dst_site_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_k8s_service_id IS NULL)
 OR (dst_kind = 'k8s_service' AND dst_k8s_service_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_site_id IS NULL)
);
