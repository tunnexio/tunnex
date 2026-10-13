DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM fqdn_resolver_context_profiles WHERE ipsec_connection_id IS NOT NULL) OR EXISTS(SELECT 1 FROM fqdn_gateway_dns_requests WHERE resolver_ipsec_path IS NOT NULL) THEN
  RAISE EXCEPTION 'cannot remove IPsec DNS profile provenance';
 END IF;
END $$;
DROP TRIGGER fqdn_ipsec_resolver_before_activate ON fqdn_resolver_context_configs;
DROP FUNCTION fqdn_ipsec_resolver_validate_activation();
DROP FUNCTION fqdn_ipsec_resolver_profile_valid(uuid,uuid);
ALTER TABLE fqdn_gateway_dns_requests DROP COLUMN resolver_ipsec_path;
ALTER TABLE fqdn_resolver_context_profiles DROP CONSTRAINT fqdn_resolver_profile_ipsec_connection_fk,DROP CONSTRAINT fqdn_resolver_profile_ipsec_complete,
 DROP COLUMN ipsec_source_address,DROP COLUMN ipsec_configuration_revision,DROP COLUMN ipsec_connection_id;
