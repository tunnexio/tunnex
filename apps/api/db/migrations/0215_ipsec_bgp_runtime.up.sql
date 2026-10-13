-- Additional guards leave historical/static runtime checks unchanged.
CREATE FUNCTION ipsec_bgp_delivery_guard() RETURNS trigger AS $$
DECLARE profile text;
BEGIN
 SELECT COALESCE(provider_profile,'aws-static-ipv4-v1') INTO profile FROM ipsec_connections WHERE id=NEW.connection_id AND org_id=NEW.org_id;
 IF NEW.manifest->>'profile_id' IS DISTINCT FROM profile THEN RAISE EXCEPTION 'IPsec runtime profile mismatch' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding'; END IF;
 IF profile='aws-bgp-ipv4-v1' THEN
  IF NEW.manifest->'bgp_version' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(NEW.manifest->'bgp') IS DISTINCT FROM 'object' OR NEW.manifest ? 'recovery_version'
   OR NOT EXISTS(SELECT 1 FROM ipsec_aws_bgp_configs b WHERE b.connection_id=NEW.connection_id AND b.org_id=NEW.org_id AND NEW.manifest->'bgp'=jsonb_build_object('local_asn',b.local_asn,'remote_asn',b.remote_asn,'router_id',host(b.router_id),'maximum_prefixes',b.maximum_prefixes))
   OR NEW.manifest->'tunnels'->0->'selected' IS DISTINCT FROM 'false'::jsonb OR NEW.manifest->'tunnels'->1->'selected' IS DISTINCT FROM 'false'::jsonb THEN
   RAISE EXCEPTION 'IPsec BGP manifest invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding';
  END IF;
  IF NEW.kind='apply' AND NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.node_id AND org_id=NEW.org_id AND site_id=NEW.site_id AND status='active' AND revoked_at IS NULL AND cert_serial=NEW.certificate_serial AND capabilities->'ipsec_config_version'='1'::jsonb AND capabilities->'ipsec_bgp_version'='1'::jsonb AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp()) THEN
   RAISE EXCEPTION 'IPsec BGP capability unavailable' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_ineligible';
  END IF;
 ELSIF NEW.manifest ? 'bgp_version' OR NEW.manifest ? 'bgp' THEN RAISE EXCEPTION 'IPsec static BGP fields invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding'; END IF;
 RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_bgp_delivery_guard BEFORE INSERT ON ipsec_runtime_deliveries FOR EACH ROW EXECUTE FUNCTION ipsec_bgp_delivery_guard();
CREATE FUNCTION ipsec_bgp_enable_guard() RETURNS trigger AS $$
BEGIN
 IF NEW.provider_profile='aws-bgp-ipv4-v1' AND NEW.desired_intent='enabled' AND NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.gateway_node_id AND org_id=NEW.org_id AND site_id=NEW.site_id AND status='active' AND revoked_at IS NULL AND cert_serial<>'' AND capabilities->'ipsec_config_version'='1'::jsonb AND capabilities->'ipsec_bgp_version'='1'::jsonb AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp()) THEN
  RAISE EXCEPTION 'IPsec BGP enable unavailable' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_ineligible';
 END IF;
 RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_bgp_enable_guard BEFORE INSERT OR UPDATE ON ipsec_connections FOR EACH ROW EXECUTE FUNCTION ipsec_bgp_enable_guard();
