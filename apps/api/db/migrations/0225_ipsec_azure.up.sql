-- Azure extends existing provider children and ownership guards; no parallel runtime.
ALTER TABLE ipsec_connections DROP CONSTRAINT ipsec_connections_provider_profile_check;
ALTER TABLE ipsec_connections ADD CONSTRAINT ipsec_connections_provider_profile_check CHECK(provider_profile IS NULL OR provider_profile IN('aws-static-ipv4-v1','aws-bgp-ipv4-v1','gcp-ha-bgp-ipv4-v1','gcp-classic-static-ipv4-v1','azure-active-active-bgp-ipv4-v1','azure-active-active-static-ipv4-v1','azure-active-standby-bgp-ipv4-v1','azure-active-standby-static-ipv4-v1'));
ALTER TABLE ipsec_provider_bindings DROP CONSTRAINT ipsec_provider_bindings_profile_id_check;
ALTER TABLE ipsec_provider_bindings ADD CONSTRAINT ipsec_provider_bindings_profile_id_check CHECK(profile_id IN('aws-static-ipv4-v1','aws-bgp-ipv4-v1','gcp-ha-bgp-ipv4-v1','gcp-classic-static-ipv4-v1','azure-active-active-bgp-ipv4-v1','azure-active-active-static-ipv4-v1','azure-active-standby-bgp-ipv4-v1','azure-active-standby-static-ipv4-v1'));
ALTER TABLE ipsec_aws_bgp_configs DROP CONSTRAINT ipsec_aws_bgp_configs_local_asn_check, DROP CONSTRAINT ipsec_aws_bgp_configs_remote_asn_check;
ALTER TABLE ipsec_aws_bgp_configs ADD CONSTRAINT ipsec_aws_bgp_configs_local_asn_check CHECK(local_asn BETWEEN 1 AND 4294967294), ADD CONSTRAINT ipsec_aws_bgp_configs_remote_asn_check CHECK(remote_asn BETWEEN 1 AND 4294967294);
CREATE OR REPLACE FUNCTION ipsec_verify_connection_children() RETURNS trigger AS $$
DECLARE v_id uuid; v_intent text; v_finalized timestamptz; v_tunnels bigint; v_secrets bigint; v_count integer;
BEGIN
    IF TG_TABLE_NAME = 'ipsec_connections' THEN v_id := NEW.id;
    ELSIF TG_OP = 'DELETE' THEN v_id := OLD.connection_id;
    ELSE v_id := NEW.connection_id;
    END IF;
    SELECT desired_intent,finalized_at INTO v_intent,v_finalized FROM ipsec_connections WHERE id = v_id FOR UPDATE;
    SELECT CASE WHEN provider_profile IN('gcp-classic-static-ipv4-v1','azure-active-standby-bgp-ipv4-v1','azure-active-standby-static-ipv4-v1') THEN 1 ELSE 2 END INTO v_count FROM ipsec_connections WHERE id=v_id;
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
  OR (finalized IS NULL AND (withdrawn OR configs<>1 OR tunnels<>CASE WHEN profile IN('gcp-classic-static-ipv4-v1','azure-active-standby-bgp-ipv4-v1','azure-active-standby-static-ipv4-v1') THEN 1 ELSE 2 END OR locals NOT BETWEEN 1 AND 64 OR remotes NOT BETWEEN 1 AND 64))
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
 IF (profile IN('aws-bgp-ipv4-v1','gcp-ha-bgp-ipv4-v1','azure-active-active-bgp-ipv4-v1','azure-active-standby-bgp-ipv4-v1') AND ((finalized IS NULL AND n<>1) OR (finalized IS NOT NULL AND n<>0))) OR (COALESCE(profile,'') NOT IN('aws-bgp-ipv4-v1','gcp-ha-bgp-ipv4-v1','azure-active-active-bgp-ipv4-v1','azure-active-standby-bgp-ipv4-v1') AND n<>0) THEN
  RAISE EXCEPTION 'IPsec BGP configuration incomplete' USING ERRCODE='23514',CONSTRAINT='ipsec_bgp_incomplete';
 END IF;
 RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION ipsec_bgp_enable_guard() RETURNS trigger AS $$
BEGIN
 IF NEW.provider_profile IN('aws-bgp-ipv4-v1','gcp-ha-bgp-ipv4-v1','azure-active-active-bgp-ipv4-v1','azure-active-standby-bgp-ipv4-v1') AND NEW.desired_intent='enabled' AND NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.gateway_node_id AND org_id=NEW.org_id AND site_id=NEW.site_id AND status='active' AND revoked_at IS NULL AND cert_serial<>'' AND capabilities->'ipsec_config_version'='1'::jsonb AND capabilities->'ipsec_bgp_version'='1'::jsonb AND (NEW.provider_profile<>'gcp-ha-bgp-ipv4-v1' OR capabilities->'ipsec_gcp_ha_version'='1'::jsonb) AND (NEW.provider_profile NOT LIKE 'azure-%' OR capabilities->'ipsec_azure_version'='1'::jsonb) AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp()) THEN
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
 IF profile IN('aws-bgp-ipv4-v1','gcp-ha-bgp-ipv4-v1','azure-active-active-bgp-ipv4-v1','azure-active-standby-bgp-ipv4-v1') THEN
  IF NEW.manifest->'bgp_version' IS DISTINCT FROM to_jsonb(CASE WHEN profile LIKE 'azure-%' THEN 3 WHEN profile='gcp-ha-bgp-ipv4-v1' THEN 2 ELSE 1 END) OR jsonb_typeof(NEW.manifest->'bgp') IS DISTINCT FROM 'object' OR NEW.manifest ? 'recovery_version'
   OR NOT EXISTS(SELECT 1 FROM ipsec_aws_bgp_configs b WHERE b.connection_id=NEW.connection_id AND b.org_id=NEW.org_id AND NEW.manifest->'bgp'=jsonb_build_object('local_asn',b.local_asn,'remote_asn',b.remote_asn,'router_id',host(b.router_id),'maximum_prefixes',b.maximum_prefixes))
   OR NEW.manifest->'tunnels'->0->'selected' IS DISTINCT FROM 'false'::jsonb OR NEW.manifest->'tunnels'->1->'selected' IS DISTINCT FROM 'false'::jsonb THEN
   RAISE EXCEPTION 'IPsec BGP manifest invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding';
  END IF;
  IF NEW.kind='apply' AND NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.node_id AND org_id=NEW.org_id AND site_id=NEW.site_id AND status='active' AND revoked_at IS NULL AND cert_serial=NEW.certificate_serial AND capabilities->'ipsec_config_version'='1'::jsonb AND capabilities->'ipsec_bgp_version'='1'::jsonb AND (profile<>'gcp-ha-bgp-ipv4-v1' OR capabilities->'ipsec_gcp_ha_version'='1'::jsonb) AND (profile NOT LIKE 'azure-%' OR capabilities->'ipsec_azure_version'='1'::jsonb) AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp()) THEN
   RAISE EXCEPTION 'IPsec BGP capability unavailable' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_ineligible';
  END IF;
 ELSIF NEW.manifest ? 'bgp_version' OR NEW.manifest ? 'bgp' THEN RAISE EXCEPTION 'IPsec static BGP fields invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding'; END IF;
 IF profile='gcp-classic-static-ipv4-v1' THEN
 IF NEW.manifest->'transport_version' IS DISTINCT FROM '1'::jsonb OR NEW.manifest->'tunnel_count' IS DISTINCT FROM '1'::jsonb OR NEW.manifest ? 'recovery_version' OR NEW.manifest->'tunnels'->1 IS DISTINCT FROM '{"id": "00000000-0000-0000-0000-000000000000", "slot": 0, "secret_revision": 0, "link_name": "", "xfrm_id": 0, "reqid": 0, "outside_address": "", "inside_cidr": "", "customer_inside_address": "", "cloud_inside_address": "", "route_table": 0, "route_protocol": 0, "route_metric": 0, "selected": false}'::jsonb OR NEW.manifest->'tunnels'->0->>'inside_cidr' IS DISTINCT FROM '' OR NEW.manifest->'tunnels'->0->>'customer_inside_address' IS DISTINCT FROM '' OR NEW.manifest->'tunnels'->0->>'cloud_inside_address' IS DISTINCT FROM '' THEN
 RAISE EXCEPTION 'Classic manifest invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding'; END IF;
 IF NEW.kind='apply' AND NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.node_id AND org_id=NEW.org_id AND site_id=NEW.site_id AND status='active' AND revoked_at IS NULL AND cert_serial=NEW.certificate_serial AND capabilities->'ipsec_config_version'='1'::jsonb AND capabilities->'ipsec_gcp_classic_version'='1'::jsonb AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp()) THEN
 RAISE EXCEPTION 'Classic capability unavailable' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_ineligible'; END IF;
 ELSIF profile IN('azure-active-standby-bgp-ipv4-v1','azure-active-standby-static-ipv4-v1') THEN
 IF NEW.manifest->'transport_version' IS DISTINCT FROM '1'::jsonb OR NEW.manifest->'tunnel_count' IS DISTINCT FROM '1'::jsonb OR NEW.manifest ? 'recovery_version' OR NEW.manifest->'tunnels'->1->>'id' IS DISTINCT FROM '00000000-0000-0000-0000-000000000000' OR NEW.manifest->'tunnels'->1->'slot' IS DISTINCT FROM '0'::jsonb THEN RAISE EXCEPTION 'Azure standby shape invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding'; END IF;
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
 IF COALESCE(c.provider_profile,'') NOT IN('aws-bgp-ipv4-v1','gcp-ha-bgp-ipv4-v1','azure-active-active-bgp-ipv4-v1','azure-active-standby-bgp-ipv4-v1') OR c.desired_intent<>'enabled' OR c.desired_revision<>NEW.desired_revision OR c.finalized_at IS NOT NULL
  OR d.kind IS DISTINCT FROM 'apply' OR d.manifest->>'profile_id' IS DISTINCT FROM c.provider_profile OR d.desired_revision<>NEW.desired_revision OR d.node_id<>NEW.node_id OR d.configuration_revision<>NEW.configuration_revision OR NOT EXISTS(SELECT 1 FROM nodes n WHERE n.id=NEW.node_id AND n.org_id=NEW.org_id AND n.id=c.gateway_node_id AND n.site_id=c.site_id AND n.cert_serial=NEW.certificate_serial AND n.status='active' AND n.revoked_at IS NULL AND (c.provider_profile<>'gcp-ha-bgp-ipv4-v1' OR n.capabilities->'ipsec_gcp_ha_version'='1'::jsonb) AND (c.provider_profile NOT LIKE 'azure-%' OR n.capabilities->'ipsec_azure_version'='1'::jsonb))
  OR NEW.report->>'delivery_id' IS DISTINCT FROM NEW.delivery_id::text OR NEW.report->>'desired_revision' IS DISTINCT FROM NEW.desired_revision::text OR NEW.report->>'configuration_revision' IS DISTINCT FROM NEW.configuration_revision::text
  OR (c.provider_profile<>'azure-active-standby-bgp-ipv4-v1' AND (NEW.report ? 'transport_version' OR NEW.report ? 'tunnel_count')) OR (c.provider_profile='azure-active-standby-bgp-ipv4-v1' AND (NEW.report->'transport_version' IS DISTINCT FROM '1'::jsonb OR NEW.report->'tunnel_count' IS DISTINCT FROM '1'::jsonb)) OR NEW.report ? 'active_slot' OR NEW.report ? 'selection_sequence' OR NEW.report ? 'recovery_version'
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
  OR COALESCE(c.provider_profile,'') NOT IN('aws-static-ipv4-v1','gcp-classic-static-ipv4-v1','azure-active-active-static-ipv4-v1','azure-active-standby-static-ipv4-v1') OR p.provider_profile IS DISTINCT FROM c.provider_profile
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
CREATE FUNCTION ipsec_azure_capability_guard() RETURNS trigger AS $$
BEGIN
 IF NEW.provider_profile LIKE 'azure-%' AND NEW.desired_intent='enabled' AND NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.gateway_node_id AND org_id=NEW.org_id AND site_id=NEW.site_id AND status='active' AND revoked_at IS NULL AND cert_serial<>'' AND capabilities->'ipsec_config_version'='1'::jsonb AND capabilities->'ipsec_azure_version'='1'::jsonb AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp()) THEN RAISE EXCEPTION 'Azure capability unavailable' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_ineligible'; END IF;
 RETURN NEW; END; $$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_azure_capability_guard BEFORE UPDATE ON ipsec_connections FOR EACH ROW EXECUTE FUNCTION ipsec_azure_capability_guard();
CREATE FUNCTION ipsec_azure_config_guard() RETURNS trigger AS $$
DECLARE profile text; BEGIN
 SELECT profile_id INTO profile FROM ipsec_provider_bindings WHERE connection_id=NEW.connection_id AND org_id=NEW.org_id;
 IF TG_TABLE_NAME='ipsec_aws_bgp_configs' THEN
 IF profile LIKE 'azure-%' THEN
 IF NEW.local_asn IN(8074,8075,12076,23456,65515,65517,65518,65519,65520) OR NEW.local_asn BETWEEN 64496 AND 64511 OR NEW.local_asn BETWEEN 65535 AND 65551 OR NEW.remote_asn IN(8074,8075,12076,23456,65517,65518,65519,65520) OR NEW.remote_asn BETWEEN 64496 AND 64511 OR NEW.remote_asn BETWEEN 65535 AND 65551 THEN RAISE EXCEPTION 'Azure ASN invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict'; END IF;
 ELSE
 IF NOT(NEW.local_asn BETWEEN 64512 AND 65534 OR NEW.local_asn BETWEEN 4200000000 AND 4294967294) OR NOT(NEW.remote_asn=7224 OR NEW.remote_asn BETWEEN 64512 AND 65534 OR NEW.remote_asn BETWEEN 4200000000 AND 4294967294) THEN RAISE EXCEPTION 'Legacy ASN invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict'; END IF;
 END IF;
 ELSIF profile LIKE 'azure-%' THEN
 IF profile LIKE 'azure-active-standby-%' AND NEW.slot<>1 THEN RAISE EXCEPTION 'Azure standby slot invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict'; END IF;
 IF profile IN('azure-active-active-bgp-ipv4-v1','azure-active-standby-bgp-ipv4-v1') AND NOT(NEW.aws_inside_ipv4 <<= '169.254.21.0/24'::cidr OR NEW.aws_inside_ipv4 <<= '169.254.22.0/24'::cidr) THEN RAISE EXCEPTION 'Azure APIPA invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict'; END IF;
 END IF;
 RETURN NEW; END; $$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_azure_config_guard BEFORE INSERT ON ipsec_aws_bgp_configs FOR EACH ROW EXECUTE FUNCTION ipsec_azure_config_guard();
CREATE TRIGGER ipsec_azure_config_guard BEFORE INSERT ON ipsec_aws_tunnel_configs FOR EACH ROW EXECUTE FUNCTION ipsec_azure_config_guard();

CREATE TABLE ipsec_azure_configs(
 connection_id uuid PRIMARY KEY, org_id uuid NOT NULL,
 gateway_sku text NOT NULL CHECK(gateway_sku IN('VpnGw1','VpnGw2','VpnGw3','VpnGw4','VpnGw5','VpnGw1AZ','VpnGw2AZ','VpnGw3AZ','VpnGw4AZ','VpnGw5AZ')),
 vpn_type text NOT NULL CHECK(vpn_type='RouteBased'),ike_version integer NOT NULL CHECK(ike_version=2),
 custom_policy text NOT NULL CHECK(custom_policy='aes256-sha256-dh14-pfs2048'),
 use_policy_based_traffic_selectors boolean NOT NULL CHECK(NOT use_policy_based_traffic_selectors),nat_enabled boolean NOT NULL CHECK(NOT nat_enabled),
 FOREIGN KEY(connection_id,org_id) REFERENCES ipsec_provider_bindings(connection_id,org_id)
);
CREATE FUNCTION ipsec_azure_metadata_guard() RETURNS trigger AS $$
DECLARE profile text;withdrawn boolean; BEGIN
 SELECT profile_id,withdrawal_started INTO profile,withdrawn FROM ipsec_provider_bindings WHERE connection_id=OLD.connection_id AND org_id=OLD.org_id;
 IF TG_OP='UPDATE' OR NOT COALESCE(withdrawn,false) THEN RAISE EXCEPTION 'Azure metadata immutable' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict'; END IF;
 RETURN OLD;END;$$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_azure_metadata_guard BEFORE UPDATE OR DELETE ON ipsec_azure_configs FOR EACH ROW EXECUTE FUNCTION ipsec_azure_metadata_guard();
CREATE FUNCTION ipsec_azure_completeness() RETURNS trigger AS $$
DECLARE c uuid;p text;finalized timestamptz;n bigint; BEGIN
 IF TG_TABLE_NAME='ipsec_connections' THEN c:=NEW.id; ELSIF TG_OP='DELETE' THEN c:=OLD.connection_id; ELSE c:=NEW.connection_id; END IF;
 SELECT provider_profile,finalized_at INTO p,finalized FROM ipsec_connections WHERE id=c FOR UPDATE;
 SELECT count(*) INTO n FROM ipsec_azure_configs WHERE connection_id=c;
 IF (p LIKE 'azure-%' AND ((finalized IS NULL AND n<>1) OR (finalized IS NOT NULL AND n<>0))) OR (COALESCE(p,'') NOT LIKE 'azure-%' AND n<>0) THEN RAISE EXCEPTION 'Azure metadata incomplete' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_incomplete'; END IF;
 RETURN NULL;END;$$ LANGUAGE plpgsql;
CREATE CONSTRAINT TRIGGER ipsec_azure_completeness AFTER INSERT OR UPDATE ON ipsec_connections DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ipsec_azure_completeness();
CREATE CONSTRAINT TRIGGER ipsec_azure_completeness AFTER INSERT OR UPDATE OR DELETE ON ipsec_azure_configs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ipsec_azure_completeness();
CREATE FUNCTION ipsec_azure_delivery_guard() RETURNS trigger AS $$
DECLARE p text; BEGIN
 SELECT provider_profile INTO p FROM ipsec_connections WHERE id=NEW.connection_id AND org_id=NEW.org_id;
 IF p NOT LIKE 'azure-%' OR p IS NULL THEN RETURN NEW;END IF;
 IF NEW.kind='apply' AND NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.node_id AND org_id=NEW.org_id AND site_id=NEW.site_id AND status='active' AND revoked_at IS NULL AND cert_serial=NEW.certificate_serial AND capabilities->'ipsec_config_version'='1'::jsonb AND capabilities->'ipsec_azure_version'='1'::jsonb AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp()) THEN RAISE EXCEPTION 'Azure delivery unavailable' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_ineligible';END IF;
 IF p LIKE 'azure-active-standby-%' AND NEW.manifest->'tunnels'->1 IS DISTINCT FROM '{"id":"00000000-0000-0000-0000-000000000000","slot":0,"secret_revision":0,"link_name":"","xfrm_id":0,"reqid":0,"outside_address":"","inside_cidr":"","customer_inside_address":"","cloud_inside_address":"","route_table":0,"route_protocol":0,"route_metric":0,"selected":false}'::jsonb THEN RAISE EXCEPTION 'Azure inactive peer invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding';END IF;
 RETURN NEW;END;$$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_azure_delivery_guard BEFORE INSERT ON ipsec_runtime_deliveries FOR EACH ROW EXECUTE FUNCTION ipsec_azure_delivery_guard();

-- Azure BGP has one on-premises loopback /32 and two independently routed
-- Azure peer /32s. Keep /30 host bounds enforced for every legacy provider.
DO $$ DECLARE n text; BEGIN
 FOR n IN SELECT conname FROM pg_constraint WHERE conrelid='ipsec_aws_tunnel_configs'::regclass AND contype='c' AND (pg_get_constraintdef(oid) LIKE '%masklen(%inside_cidr%'  OR pg_get_constraintdef(oid) LIKE '%network(%inside_cidr%' ) LOOP EXECUTE format('ALTER TABLE ipsec_aws_tunnel_configs DROP CONSTRAINT %I',n);END LOOP;
 FOR n IN SELECT conname FROM pg_constraint WHERE conrelid='ipsec_aws_tunnel_configs'::regclass AND contype='u' AND pg_get_constraintdef(oid)='UNIQUE (gateway_node_id, inside_cidr)' LOOP EXECUTE format('ALTER TABLE ipsec_aws_tunnel_configs DROP CONSTRAINT %I',n);END LOOP;
END;$$;
CREATE FUNCTION ipsec_azure_inside_guard() RETURNS trigger AS $$
DECLARE p text; BEGIN
 PERFORM ipsec_provider_lock_org(NEW.org_id);
 SELECT profile_id INTO p FROM ipsec_provider_bindings WHERE connection_id=NEW.connection_id AND org_id=NEW.org_id;
 IF p IN('azure-active-active-bgp-ipv4-v1','azure-active-standby-bgp-ipv4-v1') THEN
 IF family(NEW.inside_cidr)<>4 OR masklen(NEW.inside_cidr)<>32 OR NOT(NEW.inside_cidr <<= '169.254.0.0/16'::cidr) OR NEW.customer_inside_ipv4::cidr<>NEW.inside_cidr OR NEW.customer_inside_ipv4=NEW.aws_inside_ipv4 THEN RAISE EXCEPTION 'Azure loopback invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict';END IF;
 IF EXISTS(SELECT 1 FROM ipsec_aws_tunnel_configs WHERE connection_id=NEW.connection_id AND (customer_inside_ipv4<>NEW.customer_inside_ipv4 OR aws_inside_ipv4=NEW.aws_inside_ipv4)) THEN RAISE EXCEPTION 'Azure peer identity invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict';END IF;
 ELSIF p<>'gcp-classic-static-ipv4-v1' THEN
 IF family(NEW.inside_cidr)<>4 OR masklen(NEW.inside_cidr)<>30 OR NOT(NEW.inside_cidr <<= '169.254.0.0/16'::cidr) OR NEW.customer_inside_ipv4 NOT IN(set_masklen(network(NEW.inside_cidr)+1,32),set_masklen(network(NEW.inside_cidr)+2,32)) OR NEW.aws_inside_ipv4 NOT IN(set_masklen(network(NEW.inside_cidr)+1,32),set_masklen(network(NEW.inside_cidr)+2,32)) THEN RAISE EXCEPTION 'Legacy inside pair invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict';END IF;
 END IF;
 IF EXISTS(SELECT 1 FROM ipsec_aws_tunnel_configs WHERE gateway_node_id=NEW.gateway_node_id AND inside_cidr=NEW.inside_cidr AND NOT(p='azure-active-active-bgp-ipv4-v1' AND connection_id=NEW.connection_id)) THEN RAISE EXCEPTION 'Inside allocation duplicate' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict';END IF;
 RETURN NEW;END;$$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_azure_inside_guard BEFORE INSERT ON ipsec_aws_tunnel_configs FOR EACH ROW EXECUTE FUNCTION ipsec_azure_inside_guard();
CREATE FUNCTION ipsec_azure_status_guard() RETURNS trigger AS $$
DECLARE p text; BEGIN
 SELECT provider_profile INTO p FROM ipsec_connections WHERE id=NEW.connection_id AND org_id=NEW.org_id;
 IF p='azure-active-standby-bgp-ipv4-v1' AND (NEW.report->'bgp'->'peers'->1 IS DISTINCT FROM '{"slot":0,"state":"","accepted_prefixes":0,"installed_prefixes":0}'::jsonb OR NEW.report->'tunnels'->1 IS DISTINCT FROM '{"id":"00000000-0000-0000-0000-000000000000","slot":0,"status":"","selected":false}'::jsonb OR EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.report->'bgp'->'routes') r WHERE r->'slot' IS DISTINCT FROM '1'::jsonb)) THEN RAISE EXCEPTION 'Azure inactive status invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding';END IF;
 RETURN NEW;END;$$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_azure_status_guard BEFORE INSERT OR UPDATE ON ipsec_bgp_status FOR EACH ROW EXECUTE FUNCTION ipsec_azure_status_guard();
