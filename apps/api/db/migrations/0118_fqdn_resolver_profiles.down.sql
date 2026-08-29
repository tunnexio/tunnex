DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM fqdn_resolver_context_profiles WHERE NOT legacy_default)
       OR EXISTS (SELECT 1 FROM fqdn_gateway_dns_requests WHERE resolver_profile_id IS NOT NULL)
       OR EXISTS (SELECT 1 FROM fqdn_resource_answer_generations WHERE resolver_profile_id IS NOT NULL) THEN
        RAISE EXCEPTION 'refusing rollback: FQDN resolver profile provenance exists';
    END IF;
END $$;

ALTER TABLE fqdn_resource_answer_generations DROP CONSTRAINT IF EXISTS fqdn_generation_resolver_profile_fk;
ALTER TABLE fqdn_resource_answer_generations DROP COLUMN IF EXISTS resolver_match_suffix;
ALTER TABLE fqdn_resource_answer_generations DROP COLUMN IF EXISTS resolver_profile_id;
ALTER TABLE fqdn_gateway_dns_requests DROP CONSTRAINT IF EXISTS fqdn_gateway_dns_requests_profile_fk;
ALTER TABLE fqdn_gateway_dns_requests DROP COLUMN IF EXISTS resolver_match_suffix;
ALTER TABLE fqdn_gateway_dns_requests DROP COLUMN IF EXISTS resolver_profile_id;
DROP TABLE fqdn_resolver_context_profile_endpoints;
DROP TABLE fqdn_resolver_context_profile_suffixes;
DROP TABLE fqdn_resolver_context_profiles;

CREATE OR REPLACE FUNCTION fqdn_resolver_config_require_endpoint() RETURNS trigger AS $$
BEGIN
    IF NEW.state='active' AND NOT EXISTS (
        SELECT 1 FROM fqdn_resolver_context_endpoints e
        WHERE e.config_id=NEW.id AND e.org_id=NEW.org_id
    ) THEN
        RAISE EXCEPTION 'an active FQDN resolver configuration requires at least one endpoint';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
