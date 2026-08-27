DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM fqdn_gateway_dns_requests WHERE resolver_config_id IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot roll back FQDN gateway DNS resolver config binding after mailbox work exists';
    END IF;
END $$;

DROP INDEX IF EXISTS fqdn_gateway_dns_requests_resolver_config_idx;
ALTER TABLE fqdn_gateway_dns_requests DROP CONSTRAINT IF EXISTS fqdn_gateway_dns_requests_resolver_config_complete;
ALTER TABLE fqdn_gateway_dns_requests DROP CONSTRAINT IF EXISTS fqdn_gateway_dns_requests_resolver_config_fk;
ALTER TABLE fqdn_gateway_dns_requests DROP COLUMN IF EXISTS resolver_endpoints;
ALTER TABLE fqdn_gateway_dns_requests DROP COLUMN IF EXISTS resolver_config_version;
ALTER TABLE fqdn_gateway_dns_requests DROP COLUMN IF EXISTS resolver_config_id;
