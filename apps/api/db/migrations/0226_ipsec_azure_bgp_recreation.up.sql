-- Azure AA-BGP extends authenticated recreation, never removes retained history.
CREATE FUNCTION ipsec_azure_bgp_recreation_domains(a text[],b text[]) RETURNS boolean AS $$
 SELECT coalesce(cardinality(a)>0 AND cardinality(b)>0
 AND EXISTS(SELECT 1 FROM unnest(a) x JOIN unnest(b) y ON x=y)
 AND NOT EXISTS(SELECT 1 FROM unnest(a) x CROSS JOIN unnest(b) y WHERE x::cidr && y::cidr AND x<>y),false);
$$ LANGUAGE sql IMMUTABLE;
CREATE FUNCTION ipsec_azure_bgp_recreation_contract(m jsonb,c uuid) RETURNS boolean AS $$
 SELECT CASE WHEN jsonb_typeof(m)='object' AND jsonb_typeof(m->'tunnels')='array' AND jsonb_typeof(m->'bgp')='object' THEN coalesce(m->>'profile_id'='azure-active-active-bgp-ipv4-v1' AND m->'bgp_version'='3'::jsonb
 AND jsonb_array_length(m->'tunnels')=2
 AND m->>'customer_outside_address'=host(sc.customer_outside_ipv4)
 AND ((m->'bgp') - 'maximum_prefixes')=jsonb_build_object('local_asn',bg.local_asn,'remote_asn',bg.remote_asn,'router_id',host(bg.router_id))
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(m->'tunnels') WITH ORDINALITY t(v,i)
 LEFT JOIN ipsec_aws_tunnel_configs tc ON tc.connection_id=c AND tc.slot=t.i
 WHERE tc.connection_id IS NULL OR t.v->'slot' IS DISTINCT FROM to_jsonb(tc.slot)
 OR t.v->>'outside_address' IS DISTINCT FROM host(tc.aws_outside_ipv4)
 OR t.v->>'inside_cidr' IS DISTINCT FROM tc.inside_cidr::text
 OR t.v->>'customer_inside_address' IS DISTINCT FROM host(tc.customer_inside_ipv4)
 OR t.v->>'cloud_inside_address' IS DISTINCT FROM host(tc.aws_inside_ipv4)),false) ELSE false END
 FROM ipsec_aws_static_configs sc JOIN ipsec_aws_bgp_configs bg ON bg.connection_id=sc.connection_id WHERE sc.connection_id=c;
$$ LANGUAGE sql STABLE;
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
  OR COALESCE(c.provider_profile,'') NOT IN('aws-static-ipv4-v1','gcp-classic-static-ipv4-v1','azure-active-active-static-ipv4-v1','azure-active-standby-static-ipv4-v1','azure-active-active-bgp-ipv4-v1') OR p.provider_profile IS DISTINCT FROM c.provider_profile
  OR (c.provider_profile='azure-active-active-bgp-ipv4-v1' AND NOT EXISTS(SELECT 1 FROM nodes WHERE id=c.historical_gateway_node_id AND org_id=c.org_id AND site_id=c.historical_site_id AND status='active' AND revoked_at IS NULL AND cert_serial<>'' AND capabilities->'ipsec_config_version'='1'::jsonb AND capabilities->'ipsec_retained_guard_version'='1'::jsonb AND capabilities->'ipsec_azure_version'='1'::jsonb AND capabilities->'ipsec_bgp_version'='1'::jsonb AND capabilities->'ipsec_azure_bgp_recreation_version'='1'::jsonb AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp()))
 OR c.desired_intent<>'disabled' OR c.desired_revision<>1 OR c.finalized_at IS NOT NULL
  OR p.desired_intent<>'deleted' OR p.finalized_at IS NULL
  OR c.historical_site_id<>p.historical_site_id OR c.historical_gateway_node_id<>p.historical_gateway_node_id
  OR g.connection_id<>p.id OR g.org_id<>c.org_id OR g.site_id<>c.historical_site_id OR g.gateway_node_id<>c.historical_gateway_node_id
  OR d.connection_id<>p.id OR d.org_id<>c.org_id OR d.kind<>'cleanup' OR d.ownership_digest<>g.ownership_digest
  OR d.covers_delivery_revision IS DISTINCT FROM s.last_potentially_delivered_revision
  OR s.last_cleaned_delivery_revision IS DISTINCT FROM s.last_potentially_delivered_revision
  OR NOT EXISTS(SELECT 1 FROM nodes WHERE id=c.historical_gateway_node_id AND org_id=c.org_id AND site_id=c.historical_site_id AND status='active' AND revoked_at IS NULL AND cert_serial<>'' AND capabilities->'ipsec_config_version'='1'::jsonb AND capabilities->'ipsec_retained_guard_version'='1'::jsonb AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp())
  OR EXISTS(SELECT 1 FROM ipsec_runtime_deliveries WHERE connection_id=c.id)
  OR NEW.cleanup_delivery_id IS DISTINCT FROM (
   SELECT rg.cleanup_delivery_id FROM ipsec_retained_guards rg JOIN ipsec_runtime_deliveries rd ON rd.id=rg.cleanup_delivery_id
   WHERE rg.connection_id=p.id ORDER BY rd.covers_delivery_revision DESC,rd.desired_revision DESC,rd.id DESC LIMIT 1
  ) THEN RAISE EXCEPTION 'IPsec static recreation binding invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict'; END IF;
 RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE FUNCTION ipsec_azure_bgp_recreation_validate(c uuid,p uuid,d uuid) RETURNS void AS $$
DECLARE locals text[];remotes text[];oldlocals text[];oldremotes text[];item jsonb; prior jsonb;
BEGIN
 SELECT array_agg(cidr::text ORDER BY cidr::text) INTO locals FROM ipsec_aws_local_prefixes WHERE connection_id=c;
 SELECT array_agg(cidr::text ORDER BY cidr::text) INTO remotes FROM ipsec_aws_remote_prefixes WHERE connection_id=c;
 IF locals IS NULL OR remotes IS NULL THEN RAISE EXCEPTION 'Azure recreation domain absent' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict'; END IF;
 FOR item IN SELECT value FROM ipsec_runtime_deliveries rd CROSS JOIN LATERAL jsonb_array_elements(rd.lineage) WHERE rd.id=d LOOP
 prior:=item->'manifest';
 SELECT array_agg(value ORDER BY value) INTO oldlocals FROM jsonb_array_elements_text(prior->'local_prefixes');
 SELECT array_agg(value ORDER BY value) INTO oldremotes FROM jsonb_array_elements_text(prior->'remote_prefixes');
 IF item->>'kind' IS DISTINCT FROM 'apply' OR prior->>'connection_id' IS DISTINCT FROM p::text
 OR NOT EXISTS(SELECT 1 FROM ipsec_connections n WHERE n.id=c AND prior->>'org_id'=n.org_id::text AND prior->>'site_id'=n.historical_site_id::text AND prior->>'node_id'=n.historical_gateway_node_id::text)
 OR NOT coalesce(ipsec_azure_bgp_recreation_contract(prior,c),false)
 OR locals IS DISTINCT FROM oldlocals OR NOT ipsec_azure_bgp_recreation_domains(oldremotes,remotes)
 THEN RAISE EXCEPTION 'Azure recreation lineage invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict'; END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM ipsec_runtime_deliveries WHERE id=d AND jsonb_array_length(lineage)>0) THEN RAISE EXCEPTION 'Azure recreation lineage absent' USING ERRCODE='23514';END IF;
 IF EXISTS(SELECT 1 FROM ipsec_retained_guards g WHERE g.connection_id=p AND (
 locals IS DISTINCT FROM (SELECT array_agg(cidr::text ORDER BY cidr::text) FROM ipsec_retained_local_prefixes WHERE cleanup_delivery_id=g.cleanup_delivery_id)
 OR NOT ipsec_azure_bgp_recreation_domains(remotes,ARRAY(SELECT cidr::text FROM ipsec_retained_remote_prefixes WHERE cleanup_delivery_id=g.cleanup_delivery_id)))) THEN RAISE EXCEPTION 'Azure recreation historical domain invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict'; END IF;
END; $$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION ipsec_static_recreation_domain() RETURNS trigger AS $$
DECLARE locals text[]; remotes text[];
BEGIN
 IF EXISTS(SELECT 1 FROM ipsec_connections WHERE id=NEW.connection_id AND provider_profile='azure-active-active-bgp-ipv4-v1') THEN
 PERFORM ipsec_azure_bgp_recreation_validate(NEW.connection_id,NEW.predecessor_connection_id,NEW.cleanup_delivery_id); RETURN NULL; END IF;
 SELECT array_agg(cidr::text ORDER BY cidr::text) INTO locals FROM ipsec_retained_local_prefixes WHERE cleanup_delivery_id=NEW.cleanup_delivery_id;
 SELECT array_agg(cidr::text ORDER BY cidr::text) INTO remotes FROM ipsec_retained_remote_prefixes WHERE cleanup_delivery_id=NEW.cleanup_delivery_id;
 IF locals IS NULL OR remotes IS NULL
  OR locals IS DISTINCT FROM (SELECT array_agg(cidr::text ORDER BY cidr::text) FROM ipsec_aws_local_prefixes WHERE connection_id=NEW.connection_id AND org_id=NEW.org_id)
  OR remotes IS DISTINCT FROM (SELECT array_agg(cidr::text ORDER BY cidr::text) FROM ipsec_aws_remote_prefixes WHERE connection_id=NEW.connection_id AND org_id=NEW.org_id)
  OR EXISTS(SELECT 1 FROM ipsec_retained_guards g WHERE g.connection_id=NEW.predecessor_connection_id AND (
   locals IS DISTINCT FROM (SELECT array_agg(cidr::text ORDER BY cidr::text) FROM ipsec_retained_local_prefixes WHERE cleanup_delivery_id=g.cleanup_delivery_id)
   OR remotes IS DISTINCT FROM (SELECT array_agg(cidr::text ORDER BY cidr::text) FROM ipsec_retained_remote_prefixes WHERE cleanup_delivery_id=g.cleanup_delivery_id)))
 THEN RAISE EXCEPTION 'IPsec static recreation domain mismatch' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict'; END IF;
 RETURN NULL;
END; $$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION ipsec_static_recreation_delivery() RETURNS trigger AS $$
DECLARE expected jsonb; azure boolean;
BEGIN
 SELECT provider_profile='azure-active-active-bgp-ipv4-v1' INTO azure FROM ipsec_connections WHERE id=NEW.connection_id;
 IF NEW.kind<>'apply' THEN RETURN NEW; END IF;
 SELECT ipsec_static_recreation_predecessors(NEW.connection_id,NEW.org_id) INTO expected;
 IF (NEW.manifest->'retained_guard_predecessors') IS DISTINCT FROM expected
  OR (expected IS NOT NULL AND (jsonb_array_length(expected)>256 OR (NOT azure AND (NEW.manifest ? 'bgp' OR NEW.manifest ? 'bgp_version')) OR (azure AND (NEW.manifest->'azure_bgp_recreation_version' IS DISTINCT FROM '1'::jsonb OR NEW.manifest->'bgp_version' IS DISTINCT FROM '3'::jsonb OR NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.node_id AND capabilities->'ipsec_azure_bgp_recreation_version'='1'::jsonb)))
   OR NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.node_id AND org_id=NEW.org_id AND site_id=NEW.site_id AND status='active' AND revoked_at IS NULL AND cert_serial<>'' AND capabilities->'ipsec_config_version'='1'::jsonb AND capabilities->'ipsec_retained_guard_version'='1'::jsonb AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp())))
 THEN RAISE EXCEPTION 'IPsec static recreation manifest invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding'; END IF;
 IF expected IS NULL AND NEW.manifest ? 'azure_bgp_recreation_version' OR NOT azure AND NEW.manifest ? 'azure_bgp_recreation_version' THEN RAISE EXCEPTION 'Azure recreation version invalid' USING ERRCODE='23514';END IF;
 RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE FUNCTION ipsec_azure_bgp_recreation_enable() RETURNS trigger AS $$
DECLARE c ipsec_connections;
BEGIN c:=NEW;
 IF NEW.desired_intent='enabled' AND NEW.provider_profile='azure-active-active-bgp-ipv4-v1' AND EXISTS(SELECT 1 FROM ipsec_static_recreations WHERE connection_id=NEW.id) AND NOT EXISTS(SELECT 1 FROM nodes WHERE id=c.historical_gateway_node_id AND org_id=c.org_id AND site_id=c.historical_site_id AND status='active' AND revoked_at IS NULL AND cert_serial<>'' AND capabilities->'ipsec_config_version'='1'::jsonb AND capabilities->'ipsec_retained_guard_version'='1'::jsonb AND capabilities->'ipsec_azure_version'='1'::jsonb AND capabilities->'ipsec_bgp_version'='1'::jsonb AND capabilities->'ipsec_azure_bgp_recreation_version'='1'::jsonb AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp()) THEN RAISE EXCEPTION 'Azure recreation capability unavailable' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_ineligible';END IF;
 RETURN NEW; END; $$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_azure_bgp_recreation_enable BEFORE UPDATE ON ipsec_connections FOR EACH ROW EXECUTE FUNCTION ipsec_azure_bgp_recreation_enable();
