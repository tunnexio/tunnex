-- Refuse rollback while Azure rows exist; never destroy provider data.
DO $$ BEGIN IF EXISTS(SELECT 1 FROM ipsec_connections WHERE provider_profile LIKE 'azure-%') THEN RAISE EXCEPTION 'Remove Azure connections before rollback'; END IF; END; $$;
DROP TRIGGER ipsec_azure_status_guard ON ipsec_bgp_status;
DROP FUNCTION ipsec_azure_status_guard();
DROP TRIGGER ipsec_azure_inside_guard ON ipsec_aws_tunnel_configs;
DROP FUNCTION ipsec_azure_inside_guard();
ALTER TABLE ipsec_aws_tunnel_configs ADD CONSTRAINT ipsec_legacy_inside_prefix CHECK(family(inside_cidr)=4 AND masklen(inside_cidr)=30 AND inside_cidr <<= '169.254.0.0/16'::cidr), ADD CONSTRAINT ipsec_legacy_customer_inside CHECK(customer_inside_ipv4 IN(set_masklen(network(inside_cidr)+1,32),set_masklen(network(inside_cidr)+2,32))), ADD CONSTRAINT ipsec_legacy_cloud_inside CHECK(aws_inside_ipv4 IN(set_masklen(network(inside_cidr)+1,32),set_masklen(network(inside_cidr)+2,32))), ADD UNIQUE(gateway_node_id,inside_cidr);
DROP TRIGGER ipsec_azure_delivery_guard ON ipsec_runtime_deliveries;
DROP FUNCTION ipsec_azure_delivery_guard();
DROP TRIGGER ipsec_azure_completeness ON ipsec_connections;
DROP TABLE ipsec_azure_configs;
DROP FUNCTION ipsec_azure_completeness();
DROP FUNCTION ipsec_azure_metadata_guard();
DROP TRIGGER ipsec_azure_capability_guard ON ipsec_connections;
DROP FUNCTION ipsec_azure_capability_guard();
DROP TRIGGER ipsec_azure_config_guard ON ipsec_aws_bgp_configs;
DROP TRIGGER ipsec_azure_config_guard ON ipsec_aws_tunnel_configs;
DROP FUNCTION ipsec_azure_config_guard();
ALTER TABLE ipsec_aws_bgp_configs DROP CONSTRAINT ipsec_aws_bgp_configs_local_asn_check, DROP CONSTRAINT ipsec_aws_bgp_configs_remote_asn_check;
ALTER TABLE ipsec_aws_bgp_configs ADD CONSTRAINT ipsec_aws_bgp_configs_local_asn_check CHECK(local_asn BETWEEN 64512 AND 65534 OR local_asn BETWEEN 4200000000 AND 4294967294), ADD CONSTRAINT ipsec_aws_bgp_configs_remote_asn_check CHECK(remote_asn=7224 OR remote_asn BETWEEN 64512 AND 65534 OR remote_asn BETWEEN 4200000000 AND 4294967294);
-- Azure extends existing provider children and ownership guards; no parallel runtime.
ALTER TABLE ipsec_connections DROP CONSTRAINT ipsec_connections_provider_profile_check;
ALTER TABLE ipsec_connections ADD CONSTRAINT ipsec_connections_provider_profile_check CHECK(provider_profile IS NULL OR provider_profile IN('aws-static-ipv4-v1','aws-bgp-ipv4-v1','gcp-ha-bgp-ipv4-v1','gcp-classic-static-ipv4-v1'));
ALTER TABLE ipsec_provider_bindings DROP CONSTRAINT ipsec_provider_bindings_profile_id_check;
ALTER TABLE ipsec_provider_bindings ADD CONSTRAINT ipsec_provider_bindings_profile_id_check CHECK(profile_id IN('aws-static-ipv4-v1','aws-bgp-ipv4-v1','gcp-ha-bgp-ipv4-v1','gcp-classic-static-ipv4-v1'));
CREATE OR REPLACE FUNCTION ipsec_verify_connection_children() RETURNS trigger AS $$
DECLARE v_id uuid; v_intent text; v_finalized timestamptz; v_tunnels bigint; v_secrets bigint; v_count integer;
BEGIN
    IF TG_TABLE_NAME = 'ipsec_connections' THEN v_id := NEW.id;
    ELSIF TG_OP = 'DELETE' THEN v_id := OLD.connection_id;
    ELSE v_id := NEW.connection_id;
    END IF;
    SELECT desired_intent,finalized_at INTO v_intent,v_finalized FROM ipsec_connections WHERE id = v_id FOR UPDATE;
    SELECT CASE WHEN provider_profile='gcp-classic-static-ipv4-v1' THEN 1 ELSE 2 END INTO v_count FROM ipsec_connections WHERE id=v_id;
    SELECT count(*) INTO v_tunnels FROM ipsec_tunnels WHERE connection_id = v_id;
    SELECT count(*) INTO v_secrets FROM ipsec_tunnel_secrets WHERE connection_id = v_id;
    IF v_intent IS NULL OR (v_finalized IS NULL AND (v_tunnels <> v_count OR v_secrets <> v_count))
       OR (v_finalized IS NOT NULL AND (v_tunnels <> 0 OR v_secrets <> 0)) THEN
        RAISE EXCEPTION 'IPsec connection children incomplete' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION ipsec_provider_completeness() RETURNS trigger AS $$
DECLARE c uuid; profile text; intent text; finalized timestamptz; withdrawn boolean; bindings bigint; configs bigint; tunnels bigint; locals bigint; remotes bigint;
BEGIN
 IF TG_TABLE_NAME='ipsec_connections' THEN c:=NEW.id;
 ELSIF TG_OP='DELETE' THEN c:=OLD.connection_id; ELSE c:=NEW.connection_id; END IF;
 SELECT provider_profile,desired_intent,finalized_at INTO profile,intent,finalized FROM ipsec_connections WHERE id=c FOR UPDATE;
 SELECT count(*),bool_or(withdrawal_started) INTO bindings,withdrawn FROM ipsec_provider_bindings WHERE connection_id=c;
 SELECT count(*) INTO configs FROM ipsec_aws_static_configs WHERE connection_id=c;
 SELECT count(*) INTO tunnels FROM ipsec_aws_tunnel_configs WHERE connection_id=c;
 SELECT count(*) INTO locals FROM ipsec_aws_local_prefixes WHERE connection_id=c;
 SELECT count(*) INTO remotes FROM ipsec_aws_remote_prefixes WHERE connection_id=c;
 IF (profile IS NULL AND bindings<>0) OR (profile IS NOT NULL AND (bindings<>1
  OR (finalized IS NULL AND (withdrawn OR configs<>1 OR tunnels<>CASE WHEN profile='gcp-classic-static-ipv4-v1' THEN 1 ELSE 2 END OR locals NOT BETWEEN 1 AND 64 OR remotes NOT BETWEEN 1 AND 64))
  OR (finalized IS NOT NULL AND (NOT withdrawn OR configs<>0 OR tunnels<>0 OR locals<>0 OR remotes<>0)))) THEN
  RAISE EXCEPTION 'IPsec provider configuration incomplete' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_incomplete';
 END IF;
 -- Intra-local overlap matters even if a historic WG-only DB has approved
 -- overlapping rows. It does not change that existing WG-only acceptance.
 IF EXISTS(SELECT 1 FROM ipsec_aws_local_prefixes a JOIN ipsec_aws_local_prefixes b ON a.connection_id=b.connection_id AND a.subnet_id<b.subnet_id WHERE a.connection_id=c AND a.cidr && b.cidr) THEN RAISE EXCEPTION 'IPsec local prefix conflict' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict'; END IF;
 IF profile IS NOT NULL AND finalized IS NULL THEN UPDATE ipsec_provider_bindings SET configuration_sealed=true WHERE connection_id=c AND NOT configuration_sealed; END IF;
 RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION ipsec_bgp_completeness() RETURNS trigger AS $$
DECLARE c uuid; profile text; finalized timestamptz; n bigint;
BEGIN
 IF TG_TABLE_NAME='ipsec_connections' THEN c:=NEW.id;
 ELSIF TG_OP='DELETE' THEN c:=OLD.connection_id; ELSE c:=NEW.connection_id; END IF;
 SELECT provider_profile,finalized_at INTO profile,finalized FROM ipsec_connections WHERE id=c FOR UPDATE;
 SELECT count(*) INTO n FROM ipsec_aws_bgp_configs WHERE connection_id=c;
 IF (profile IN('aws-bgp-ipv4-v1','gcp-ha-bgp-ipv4-v1') AND ((finalized IS NULL AND n<>1) OR (finalized IS NOT NULL AND n<>0))) OR (COALESCE(profile,'') NOT IN('aws-bgp-ipv4-v1','gcp-ha-bgp-ipv4-v1') AND n<>0) THEN
  RAISE EXCEPTION 'IPsec BGP configuration incomplete' USING ERRCODE='23514',CONSTRAINT='ipsec_bgp_incomplete';
 END IF;
 RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION ipsec_bgp_enable_guard() RETURNS trigger AS $$
BEGIN
 IF NEW.provider_profile IN('aws-bgp-ipv4-v1','gcp-ha-bgp-ipv4-v1') AND NEW.desired_intent='enabled' AND NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.gateway_node_id AND org_id=NEW.org_id AND site_id=NEW.site_id AND status='active' AND revoked_at IS NULL AND cert_serial<>'' AND capabilities->'ipsec_config_version'='1'::jsonb AND capabilities->'ipsec_bgp_version'='1'::jsonb AND (NEW.provider_profile<>'gcp-ha-bgp-ipv4-v1' OR capabilities->'ipsec_gcp_ha_version'='1'::jsonb) AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp()) THEN
  RAISE EXCEPTION 'IPsec BGP enable unavailable' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_ineligible';
 END IF;
 IF NEW.provider_profile='gcp-classic-static-ipv4-v1' AND NEW.desired_intent='enabled' AND NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.gateway_node_id AND org_id=NEW.org_id AND site_id=NEW.site_id AND status='active' AND revoked_at IS NULL AND cert_serial<>'' AND capabilities->'ipsec_config_version'='1'::jsonb AND capabilities->'ipsec_gcp_classic_version'='1'::jsonb AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp()) THEN
 RAISE EXCEPTION 'Classic runtime unavailable' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_ineligible'; END IF;
 RETURN NEW;
END; $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION ipsec_bgp_delivery_guard() RETURNS trigger AS $$
DECLARE profile text;
BEGIN
 SELECT COALESCE(provider_profile,'aws-static-ipv4-v1') INTO profile FROM ipsec_connections WHERE id=NEW.connection_id AND org_id=NEW.org_id;
 IF NEW.manifest->>'profile_id' IS DISTINCT FROM profile THEN RAISE EXCEPTION 'IPsec runtime profile mismatch' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding'; END IF;
 IF profile IN('aws-bgp-ipv4-v1','gcp-ha-bgp-ipv4-v1') THEN
  IF NEW.manifest->'bgp_version' IS DISTINCT FROM to_jsonb(CASE WHEN profile='gcp-ha-bgp-ipv4-v1' THEN 2 ELSE 1 END) OR jsonb_typeof(NEW.manifest->'bgp') IS DISTINCT FROM 'object' OR NEW.manifest ? 'recovery_version'
   OR NOT EXISTS(SELECT 1 FROM ipsec_aws_bgp_configs b WHERE b.connection_id=NEW.connection_id AND b.org_id=NEW.org_id AND NEW.manifest->'bgp'=jsonb_build_object('local_asn',b.local_asn,'remote_asn',b.remote_asn,'router_id',host(b.router_id),'maximum_prefixes',b.maximum_prefixes))
   OR NEW.manifest->'tunnels'->0->'selected' IS DISTINCT FROM 'false'::jsonb OR NEW.manifest->'tunnels'->1->'selected' IS DISTINCT FROM 'false'::jsonb THEN
   RAISE EXCEPTION 'IPsec BGP manifest invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding';
  END IF;
  IF NEW.kind='apply' AND NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.node_id AND org_id=NEW.org_id AND site_id=NEW.site_id AND status='active' AND revoked_at IS NULL AND cert_serial=NEW.certificate_serial AND capabilities->'ipsec_config_version'='1'::jsonb AND capabilities->'ipsec_bgp_version'='1'::jsonb AND (profile<>'gcp-ha-bgp-ipv4-v1' OR capabilities->'ipsec_gcp_ha_version'='1'::jsonb) AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp()) THEN
   RAISE EXCEPTION 'IPsec BGP capability unavailable' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_ineligible';
  END IF;
 ELSIF NEW.manifest ? 'bgp_version' OR NEW.manifest ? 'bgp' THEN RAISE EXCEPTION 'IPsec static BGP fields invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding'; END IF;
 IF profile='gcp-classic-static-ipv4-v1' THEN
 IF NEW.manifest->'transport_version' IS DISTINCT FROM '1'::jsonb OR NEW.manifest->'tunnel_count' IS DISTINCT FROM '1'::jsonb OR NEW.manifest ? 'recovery_version' OR NEW.manifest->'tunnels'->1 IS DISTINCT FROM '{"id": "00000000-0000-0000-0000-000000000000", "slot": 0, "secret_revision": 0, "link_name": "", "xfrm_id": 0, "reqid": 0, "outside_address": "", "inside_cidr": "", "customer_inside_address": "", "cloud_inside_address": "", "route_table": 0, "route_protocol": 0, "route_metric": 0, "selected": false}'::jsonb OR NEW.manifest->'tunnels'->0->>'inside_cidr' IS DISTINCT FROM '' OR NEW.manifest->'tunnels'->0->>'customer_inside_address' IS DISTINCT FROM '' OR NEW.manifest->'tunnels'->0->>'cloud_inside_address' IS DISTINCT FROM '' THEN
 RAISE EXCEPTION 'Classic manifest invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding'; END IF;
 IF NEW.kind='apply' AND NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.node_id AND org_id=NEW.org_id AND site_id=NEW.site_id AND status='active' AND revoked_at IS NULL AND cert_serial=NEW.certificate_serial AND capabilities->'ipsec_config_version'='1'::jsonb AND capabilities->'ipsec_gcp_classic_version'='1'::jsonb AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp()) THEN
 RAISE EXCEPTION 'Classic capability unavailable' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_ineligible'; END IF;
 ELSIF NEW.manifest ? 'transport_version' OR NEW.manifest ? 'tunnel_count' THEN
 RAISE EXCEPTION 'Unexpected transport metadata' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding'; END IF;
 RETURN NEW;
END; $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION ipsec_bgp_status_guard() RETURNS trigger AS $$
DECLARE d ipsec_runtime_deliveries; c ipsec_connections; bound integer;
BEGIN
 SELECT * INTO c FROM ipsec_connections WHERE id=NEW.connection_id AND org_id=NEW.org_id;
 SELECT * INTO d FROM ipsec_runtime_deliveries WHERE id=NEW.delivery_id AND connection_id=NEW.connection_id AND org_id=NEW.org_id;
 SELECT maximum_prefixes INTO bound FROM ipsec_aws_bgp_configs WHERE connection_id=NEW.connection_id AND org_id=NEW.org_id;
 IF COALESCE(c.provider_profile,'') NOT IN('aws-bgp-ipv4-v1','gcp-ha-bgp-ipv4-v1') OR c.desired_intent<>'enabled' OR c.desired_revision<>NEW.desired_revision OR c.finalized_at IS NOT NULL
  OR d.kind IS DISTINCT FROM 'apply' OR d.manifest->>'profile_id' IS DISTINCT FROM c.provider_profile OR d.desired_revision<>NEW.desired_revision OR d.node_id<>NEW.node_id OR d.configuration_revision<>NEW.configuration_revision OR NOT EXISTS(SELECT 1 FROM nodes n WHERE n.id=NEW.node_id AND n.org_id=NEW.org_id AND n.id=c.gateway_node_id AND n.site_id=c.site_id AND n.cert_serial=NEW.certificate_serial AND n.status='active' AND n.revoked_at IS NULL AND (c.provider_profile<>'gcp-ha-bgp-ipv4-v1' OR n.capabilities->'ipsec_gcp_ha_version'='1'::jsonb))
  OR NEW.report->>'delivery_id' IS DISTINCT FROM NEW.delivery_id::text OR NEW.report->>'desired_revision' IS DISTINCT FROM NEW.desired_revision::text OR NEW.report->>'configuration_revision' IS DISTINCT FROM NEW.configuration_revision::text
  OR NEW.report ? 'transport_version' OR NEW.report ? 'tunnel_count' OR NEW.report ? 'active_slot' OR NEW.report ? 'selection_sequence' OR NEW.report ? 'recovery_version'
  OR bound IS NULL OR jsonb_array_length(NEW.report->'bgp'->'routes')>(SELECT count(*) FROM ipsec_aws_remote_prefixes WHERE connection_id=NEW.connection_id AND org_id=NEW.org_id) OR EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.report->'bgp'->'peers') peer WHERE jsonb_typeof(peer->'accepted_prefixes') IS DISTINCT FROM 'number' OR (peer->>'accepted_prefixes')::numeric<0 OR (peer->>'accepted_prefixes')::numeric>bound)
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.report->'bgp'->'routes') r WHERE jsonb_typeof(r->'slot') IS DISTINCT FROM 'number' OR r->'slot' NOT IN('1'::jsonb,'2'::jsonb) OR NOT EXISTS(SELECT 1 FROM ipsec_aws_remote_prefixes p WHERE p.connection_id=NEW.connection_id AND p.org_id=NEW.org_id AND p.cidr::text=r->>'prefix'))
  OR (SELECT count(DISTINCT r->>'prefix') FROM jsonb_array_elements(NEW.report->'bgp'->'routes') r)<>jsonb_array_length(NEW.report->'bgp'->'routes') THEN
  RAISE EXCEPTION 'IPsec BGP observation binding invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding';
 END IF;
 RETURN NEW;
END; $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION ipsec_static_recreation_binding() RETURNS trigger AS $$
DECLARE c ipsec_connections; p ipsec_connections; g ipsec_retained_guards; d ipsec_runtime_deliveries; s ipsec_runtime_state;
BEGIN
 PERFORM ipsec_provider_lock_org(NEW.org_id);
 SELECT * INTO c FROM ipsec_connections WHERE id=NEW.connection_id AND org_id=NEW.org_id FOR UPDATE;
 SELECT * INTO p FROM ipsec_connections WHERE id=NEW.predecessor_connection_id AND org_id=NEW.org_id FOR UPDATE;
 SELECT * INTO g FROM ipsec_retained_guards WHERE cleanup_delivery_id=NEW.cleanup_delivery_id;
 SELECT * INTO d FROM ipsec_runtime_deliveries WHERE id=NEW.cleanup_delivery_id;
 SELECT * INTO s FROM ipsec_runtime_state WHERE connection_id=NEW.predecessor_connection_id;
 IF c.id IS NULL OR p.id IS NULL OR g.cleanup_delivery_id IS NULL OR d.id IS NULL OR s.connection_id IS NULL
  OR COALESCE(c.provider_profile,'') NOT IN('aws-static-ipv4-v1','gcp-classic-static-ipv4-v1') OR p.provider_profile IS DISTINCT FROM c.provider_profile
  OR c.desired_intent<>'disabled' OR c.desired_revision<>1 OR c.finalized_at IS NOT NULL
  OR p.desired_intent<>'deleted' OR p.finalized_at IS NULL
  OR c.historical_site_id<>p.historical_site_id OR c.historical_gateway_node_id<>p.historical_gateway_node_id
  OR g.connection_id<>p.id OR g.org_id<>c.org_id OR g.site_id<>c.historical_site_id OR g.gateway_node_id<>c.historical_gateway_node_id
  OR d.connection_id<>p.id OR d.org_id<>c.org_id OR d.kind<>'cleanup' OR d.ownership_digest<>g.ownership_digest
  OR d.covers_delivery_revision IS DISTINCT FROM s.last_potentially_delivered_revision
  OR s.last_cleaned_delivery_revision IS DISTINCT FROM s.last_potentially_delivered_revision
  OR NOT EXISTS(SELECT 1 FROM nodes WHERE id=c.historical_gateway_node_id AND org_id=c.org_id AND site_id=c.historical_site_id AND status='active' AND revoked_at IS NULL AND capabilities->'ipsec_config_version'='1'::jsonb AND capabilities->'ipsec_retained_guard_version'='1'::jsonb AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp())
  OR EXISTS(SELECT 1 FROM ipsec_runtime_deliveries WHERE connection_id=c.id)
  OR NEW.cleanup_delivery_id IS DISTINCT FROM (
   SELECT rg.cleanup_delivery_id FROM ipsec_retained_guards rg JOIN ipsec_runtime_deliveries rd ON rd.id=rg.cleanup_delivery_id
   WHERE rg.connection_id=p.id ORDER BY rd.covers_delivery_revision DESC,rd.desired_revision DESC,rd.id DESC LIMIT 1
  ) THEN RAISE EXCEPTION 'IPsec static recreation binding invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict'; END IF;
 RETURN NEW;
END; $$ LANGUAGE plpgsql;