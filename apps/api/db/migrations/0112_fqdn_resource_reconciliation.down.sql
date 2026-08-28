-- Context/rule-reference/opt-in data is operator intent and must not be erased
-- by a downgrade.  An unused schema-only migration remains reversible.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM fqdn_resources WHERE resolver_site_id IS NOT NULL)
       OR EXISTS (SELECT 1 FROM fqdn_resource_answer_generations)
       OR EXISTS (SELECT 1 FROM fqdn_resource_rule_references)
       OR EXISTS (SELECT 1 FROM organizations WHERE fqdn_resources_enabled) THEN
        RAISE EXCEPTION 'cannot roll back 0112: FQDN reconciliation data exists';
    END IF;
END $$;

DROP TRIGGER fqdn_resolver_gateway_rebind_before_write ON nodes;
DROP FUNCTION fqdn_resolver_gateway_rebind_restricted();
DROP TRIGGER fqdn_generation_resolver_context_before_write ON fqdn_resource_answer_generations;
DROP TRIGGER fqdn_resource_resolver_context_before_write ON fqdn_resources;
DROP FUNCTION fqdn_resolver_context_is_selected();
DROP TABLE fqdn_resource_rule_references;
ALTER TABLE fqdn_resource_answer_generations DROP CONSTRAINT fqdn_generations_resolver_context_pair;
ALTER TABLE fqdn_resources DROP CONSTRAINT fqdn_resources_resolver_context_pair;
ALTER TABLE fqdn_resource_answer_generations DROP COLUMN resolver_site_id;
ALTER TABLE fqdn_resources DROP COLUMN resolver_site_id;
ALTER TABLE organizations DROP COLUMN fqdn_resources_enabled;
