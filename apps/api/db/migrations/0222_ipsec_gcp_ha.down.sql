LOCK TABLE ipsec_connections,ipsec_provider_bindings IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN IF EXISTS(SELECT 1 FROM ipsec_connections WHERE provider_profile='gcp-ha-bgp-ipv4-v1') THEN RAISE EXCEPTION 'GCP HA history must be retained; rollback refused'; END IF; END; $$;
DROP TRIGGER ipsec_provider_cloud_guard ON ipsec_aws_tunnel_configs;
DROP TRIGGER ipsec_provider_cloud_guard ON ipsec_aws_bgp_configs;
DROP FUNCTION ipsec_provider_cloud_guard();
ALTER TABLE ipsec_aws_tunnel_configs ADD CONSTRAINT ipsec_aws_inside_reservation CHECK(inside_cidr NOT IN('169.254.0.0/30','169.254.1.0/30','169.254.2.0/30','169.254.3.0/30','169.254.4.0/30','169.254.5.0/30','169.254.169.252/30'));
ALTER TABLE ipsec_connections DROP CONSTRAINT ipsec_connections_provider_profile_check;
ALTER TABLE ipsec_connections ADD CONSTRAINT ipsec_connections_provider_profile_check CHECK(provider_profile IS NULL OR provider_profile IN('aws-static-ipv4-v1','aws-bgp-ipv4-v1'));
ALTER TABLE ipsec_provider_bindings DROP CONSTRAINT ipsec_provider_bindings_profile_id_check;
ALTER TABLE ipsec_provider_bindings ADD CONSTRAINT ipsec_provider_bindings_profile_id_check CHECK(profile_id IN('aws-static-ipv4-v1','aws-bgp-ipv4-v1'));
CREATE OR REPLACE FUNCTION ipsec_bgp_completeness() RETURNS trigger AS $$
DECLARE c uuid; profile text; finalized timestamptz; n bigint;
BEGIN
 IF TG_TABLE_NAME='ipsec_connections' THEN c:=NEW.id;
 ELSIF TG_OP='DELETE' THEN c:=OLD.connection_id; ELSE c:=NEW.connection_id; END IF;
 SELECT provider_profile,finalized_at INTO profile,finalized FROM ipsec_connections WHERE id=c FOR UPDATE;
 SELECT count(*) INTO n FROM ipsec_aws_bgp_configs WHERE connection_id=c;
 IF (profile='aws-bgp-ipv4-v1' AND ((finalized IS NULL AND n<>1) OR (finalized IS NOT NULL AND n<>0))) OR (profile IS DISTINCT FROM 'aws-bgp-ipv4-v1' AND n<>0) THEN
  RAISE EXCEPTION 'IPsec BGP configuration incomplete' USING ERRCODE='23514',CONSTRAINT='ipsec_bgp_incomplete';
 END IF;
 RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION ipsec_bgp_delivery_guard() RETURNS trigger AS $$
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

CREATE OR REPLACE FUNCTION ipsec_bgp_enable_guard() RETURNS trigger AS $$
BEGIN
 IF NEW.provider_profile='aws-bgp-ipv4-v1' AND NEW.desired_intent='enabled' AND NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.gateway_node_id AND org_id=NEW.org_id AND site_id=NEW.site_id AND status='active' AND revoked_at IS NULL AND cert_serial<>'' AND capabilities->'ipsec_config_version'='1'::jsonb AND capabilities->'ipsec_bgp_version'='1'::jsonb AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp()) THEN
  RAISE EXCEPTION 'IPsec BGP enable unavailable' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_ineligible';
 END IF;
 RETURN NEW;
END; $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION ipsec_bgp_status_guard() RETURNS trigger AS $$
DECLARE d ipsec_runtime_deliveries; c ipsec_connections; bound integer;
BEGIN
 SELECT * INTO c FROM ipsec_connections WHERE id=NEW.connection_id AND org_id=NEW.org_id;
 SELECT * INTO d FROM ipsec_runtime_deliveries WHERE id=NEW.delivery_id AND connection_id=NEW.connection_id AND org_id=NEW.org_id;
 SELECT maximum_prefixes INTO bound FROM ipsec_aws_bgp_configs WHERE connection_id=NEW.connection_id AND org_id=NEW.org_id;
 IF c.provider_profile IS DISTINCT FROM 'aws-bgp-ipv4-v1' OR c.desired_intent<>'enabled' OR c.desired_revision<>NEW.desired_revision OR c.finalized_at IS NOT NULL
  OR d.kind IS DISTINCT FROM 'apply' OR d.manifest->>'profile_id' IS DISTINCT FROM 'aws-bgp-ipv4-v1' OR d.desired_revision<>NEW.desired_revision OR d.node_id<>NEW.node_id OR d.configuration_revision<>NEW.configuration_revision OR NOT EXISTS(SELECT 1 FROM nodes n WHERE n.id=NEW.node_id AND n.org_id=NEW.org_id AND n.id=c.gateway_node_id AND n.site_id=c.site_id AND n.cert_serial=NEW.certificate_serial AND n.status='active' AND n.revoked_at IS NULL)
  OR NEW.report->>'delivery_id' IS DISTINCT FROM NEW.delivery_id::text OR NEW.report->>'desired_revision' IS DISTINCT FROM NEW.desired_revision::text OR NEW.report->>'configuration_revision' IS DISTINCT FROM NEW.configuration_revision::text
  OR NEW.report ? 'active_slot' OR NEW.report ? 'selection_sequence' OR NEW.report ? 'recovery_version'
  OR bound IS NULL OR jsonb_array_length(NEW.report->'bgp'->'routes')>(SELECT count(*) FROM ipsec_aws_remote_prefixes WHERE connection_id=NEW.connection_id AND org_id=NEW.org_id) OR EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.report->'bgp'->'peers') peer WHERE jsonb_typeof(peer->'accepted_prefixes') IS DISTINCT FROM 'number' OR (peer->>'accepted_prefixes')::numeric<0 OR (peer->>'accepted_prefixes')::numeric>bound)
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.report->'bgp'->'routes') r WHERE jsonb_typeof(r->'slot') IS DISTINCT FROM 'number' OR r->'slot' NOT IN('1'::jsonb,'2'::jsonb) OR NOT EXISTS(SELECT 1 FROM ipsec_aws_remote_prefixes p WHERE p.connection_id=NEW.connection_id AND p.org_id=NEW.org_id AND p.cidr::text=r->>'prefix'))
  OR (SELECT count(DISTINCT r->>'prefix') FROM jsonb_array_elements(NEW.report->'bgp'->'routes') r)<>jsonb_array_length(NEW.report->'bgp'->'routes') THEN
  RAISE EXCEPTION 'IPsec BGP observation binding invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding';
 END IF;
 RETURN NEW;
END; $$ LANGUAGE plpgsql;
