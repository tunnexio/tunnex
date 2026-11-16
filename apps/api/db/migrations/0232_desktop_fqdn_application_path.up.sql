-- Application routing is separate from the resolver's DNS transport.
ALTER TABLE fqdn_resources ADD COLUMN application_ipsec_connection_id uuid,
 ADD COLUMN application_ipsec_configuration_revision bigint,
 ADD CONSTRAINT fqdn_application_ipsec_pair CHECK (
 (application_ipsec_connection_id IS NULL AND application_ipsec_configuration_revision IS NULL) OR
 (application_ipsec_connection_id IS NOT NULL AND application_ipsec_configuration_revision IS NOT NULL AND application_ipsec_configuration_revision=1 AND resolver_site_id IS NOT NULL AND resolver_node_id IS NOT NULL)),
 ADD CONSTRAINT fqdn_application_ipsec_fk FOREIGN KEY(application_ipsec_connection_id,org_id) REFERENCES ipsec_connections(id,org_id) ON DELETE RESTRICT;
ALTER TABLE fqdn_gateway_dns_requests ADD COLUMN resolver_kind text NOT NULL DEFAULT '' CHECK(resolver_kind IN ('','static_cname')), ADD COLUMN application_desired_revision bigint CHECK(application_desired_revision>0);
ALTER TABLE fqdn_resource_answer_generations ADD COLUMN resolver_kind text NOT NULL DEFAULT '' CHECK(resolver_kind IN ('','static_cname')), ADD COLUMN application_desired_revision bigint CHECK(application_desired_revision>0);
CREATE FUNCTION fqdn_application_ipsec_path_valid(o uuid,s uuid,n uuid,c uuid,v bigint) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT v=1 AND EXISTS(SELECT 1 FROM ipsec_connections x
 JOIN ipsec_org_settings settings ON settings.org_id=x.org_id AND settings.enabled
 JOIN nodes gateway ON gateway.id=x.gateway_node_id AND gateway.org_id=x.org_id AND gateway.site_id=x.site_id
 WHERE x.id=c AND x.org_id=o AND x.site_id=s AND x.gateway_node_id=n AND x.desired_intent='enabled'
 AND x.provider_profile='aws-bgp-ipv4-v1' AND x.deleted_at IS NULL AND x.finalized_at IS NULL
 AND gateway.status='active' AND gateway.revoked_at IS NULL AND gateway.cert_serial<>''
 AND gateway.policy_reported_at BETWEEN statement_timestamp()-interval '90 seconds' AND statement_timestamp()
 AND gateway.capabilities->'ipsec_config_version'='1'::jsonb AND gateway.capabilities->'ipsec_bgp_version'='1'::jsonb
 AND gateway.capabilities->'ipsec_desktop_transit_version'='1'::jsonb AND gateway.capabilities->'ipsec_fqdn_policy_version'='2'::jsonb
 AND gateway.capabilities->'ipsec_desktop_fqdn_version'='1'::jsonb)
$$;
-- Changing application authority cannot reuse a published generation or referenced rule.
CREATE FUNCTION fqdn_application_binding_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' AND (NEW.application_ipsec_connection_id IS DISTINCT FROM OLD.application_ipsec_connection_id OR NEW.application_ipsec_configuration_revision IS DISTINCT FROM OLD.application_ipsec_configuration_revision OR
 ((NEW.application_ipsec_connection_id IS NOT NULL OR OLD.application_ipsec_connection_id IS NOT NULL) AND (NEW.fqdn IS DISTINCT FROM OLD.fqdn OR NEW.protocol IS DISTINCT FROM OLD.protocol OR NEW.port_low IS DISTINCT FROM OLD.port_low OR NEW.port_high IS DISTINCT FROM OLD.port_high OR NEW.resolver_site_id IS DISTINCT FROM OLD.resolver_site_id OR NEW.resolver_node_id IS DISTINCT FROM OLD.resolver_node_id))) THEN
 IF EXISTS(SELECT 1 FROM policy_rules WHERE org_id=OLD.org_id AND dst_fqdn_resource_id=OLD.id) OR EXISTS(SELECT 1 FROM fqdn_resource_answer_generations WHERE org_id=OLD.org_id AND resource_id=OLD.id AND state='active') THEN RAISE EXCEPTION 'withdraw FQDN application authority before rebinding'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER fqdn_application_binding_before_write BEFORE INSERT OR UPDATE ON fqdn_resources FOR EACH ROW EXECUTE FUNCTION fqdn_application_binding_guard();

CREATE FUNCTION fqdn_application_generation_kind_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF OLD.state<>'pending' AND (NEW.resolver_kind IS DISTINCT FROM OLD.resolver_kind OR NEW.application_desired_revision IS DISTINCT FROM OLD.application_desired_revision) THEN RAISE EXCEPTION 'published application resolution provenance is immutable'; END IF; RETURN NEW; END $$;
CREATE TRIGGER fqdn_application_generation_kind_before_update BEFORE UPDATE ON fqdn_resource_answer_generations FOR EACH ROW EXECUTE FUNCTION fqdn_application_generation_kind_immutable();
