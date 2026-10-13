-- Named resolver profiles can explicitly select an IPsec transport. Unbound legacy paths remain unchanged.
ALTER TABLE fqdn_resolver_context_profiles
 ADD COLUMN ipsec_connection_id uuid NULL,
 ADD COLUMN ipsec_configuration_revision bigint NULL,
 ADD COLUMN ipsec_source_address inet NULL,
 ADD CONSTRAINT fqdn_resolver_profile_ipsec_connection_fk FOREIGN KEY (ipsec_connection_id,org_id) REFERENCES ipsec_connections(id,org_id) ON DELETE RESTRICT,
 ADD CONSTRAINT fqdn_resolver_profile_ipsec_complete CHECK (
   (ipsec_connection_id IS NULL AND ipsec_configuration_revision IS NULL AND ipsec_source_address IS NULL)
   OR (ipsec_connection_id IS NOT NULL AND ipsec_configuration_revision IS NOT NULL AND ipsec_configuration_revision>0 AND ipsec_source_address IS NOT NULL
       AND family(ipsec_source_address)=4 AND masklen(ipsec_source_address)=32 AND NOT legacy_default));
ALTER TABLE fqdn_gateway_dns_requests ADD COLUMN resolver_ipsec_path jsonb NULL;
ALTER TABLE fqdn_gateway_dns_requests ADD CONSTRAINT fqdn_gateway_dns_ipsec_path_object CHECK (resolver_ipsec_path IS NULL OR jsonb_typeof(resolver_ipsec_path)='object');

CREATE FUNCTION fqdn_ipsec_resolver_profile_valid(pid uuid, tenant uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS (
  SELECT 1 FROM fqdn_resolver_context_profiles p
  JOIN fqdn_resolver_context_configs cfg ON cfg.id=p.config_id AND cfg.org_id=p.org_id
  JOIN ipsec_connections c ON c.id=p.ipsec_connection_id AND c.org_id=p.org_id
  JOIN ipsec_provider_bindings b ON b.connection_id=c.id AND b.org_id=c.org_id
  JOIN nodes n ON n.id=cfg.gateway_id AND n.org_id=cfg.org_id AND n.site_id=cfg.site_id
  WHERE p.id=pid AND p.org_id=tenant AND c.site_id=cfg.site_id AND c.gateway_node_id=cfg.gateway_id
   AND c.desired_intent='enabled' AND c.deleted_at IS NULL AND c.finalized_at IS NULL
   AND NOT b.withdrawal_started AND b.configuration_revision=p.ipsec_configuration_revision
   AND n.status='active' AND n.revoked_at IS NULL
   AND n.capabilities->'dns_ipsec_resolve_version'='1'::jsonb AND n.capabilities->'dns_resolve_rpc_version'='2'::jsonb
   AND EXISTS(SELECT 1 FROM fqdn_resolver_context_profile_suffixes s WHERE s.profile_id=p.id AND s.org_id=p.org_id)
   AND EXISTS(SELECT 1 FROM fqdn_resolver_context_profile_endpoints e WHERE e.profile_id=p.id AND e.org_id=p.org_id)
   AND EXISTS(SELECT 1 FROM ipsec_aws_local_prefixes lp JOIN site_subnets ss ON ss.id=lp.subnet_id AND ss.site_id=lp.site_id AND ss.status='approved'
              WHERE lp.connection_id=c.id AND lp.org_id=c.org_id AND p.ipsec_source_address <<= lp.cidr)
   AND NOT EXISTS(SELECT 1 FROM fqdn_resolver_context_profile_endpoints e WHERE e.profile_id=p.id AND e.org_id=p.org_id
       AND (family(e.address)<>4 OR e.port<>53 OR NOT EXISTS(SELECT 1 FROM ipsec_aws_remote_prefixes rp
            WHERE rp.connection_id=c.id AND rp.org_id=c.org_id AND e.address <<= rp.cidr)))
 );
$$;

CREATE FUNCTION fqdn_ipsec_resolver_validate_activation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.state='active' AND EXISTS(SELECT 1 FROM fqdn_resolver_context_profiles p WHERE p.config_id=NEW.id AND p.org_id=NEW.org_id
       AND p.ipsec_connection_id IS NOT NULL AND NOT fqdn_ipsec_resolver_profile_valid(p.id,p.org_id)) THEN
   RAISE EXCEPTION 'IPsec resolver profile requires an enabled owned connection and approved DNS path';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER fqdn_ipsec_resolver_before_activate BEFORE UPDATE OF state ON fqdn_resolver_context_configs
 FOR EACH ROW EXECUTE FUNCTION fqdn_ipsec_resolver_validate_activation();
