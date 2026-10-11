-- Additive capability for fully finalized Azure cross-profile successors.
CREATE FUNCTION ipsec_azure_profile_recreation_pair(m jsonb,c uuid) RETURNS boolean AS $$
 SELECT coalesce(m->>'profile_id' IN('azure-active-active-bgp-ipv4-v1','azure-active-active-static-ipv4-v1','azure-active-standby-bgp-ipv4-v1','azure-active-standby-static-ipv4-v1')
 AND n.provider_profile IN('azure-active-active-bgp-ipv4-v1','azure-active-active-static-ipv4-v1','azure-active-standby-bgp-ipv4-v1','azure-active-standby-static-ipv4-v1')
 AND m->>'customer_outside_address'=host(sc.customer_outside_ipv4)
 AND ARRAY(SELECT value FROM jsonb_array_elements_text(m->'local_prefixes') ORDER BY value)=ARRAY(SELECT cidr::text FROM ipsec_aws_local_prefixes WHERE connection_id=c ORDER BY cidr::text)
 AND ipsec_azure_bgp_recreation_domains(ARRAY(SELECT value FROM jsonb_array_elements_text(m->'remote_prefixes')),ARRAY(SELECT cidr::text FROM ipsec_aws_remote_prefixes WHERE connection_id=c))
 AND NOT EXISTS(SELECT 1 FROM ipsec_aws_tunnel_configs x WHERE x.connection_id=c AND x.slot<=CASE WHEN m->>'profile_id' LIKE '%-standby-%' THEN 1 ELSE 2 END AND (
 m->'tunnels'->(x.slot-1)->>'outside_address' IS DISTINCT FROM host(x.aws_outside_ipv4)
 OR ((n.provider_profile LIKE '%-bgp-%')=(m->>'profile_id' LIKE '%-bgp-%') AND (
 m->'tunnels'->(x.slot-1)->>'inside_cidr' IS DISTINCT FROM x.inside_cidr::text
 OR m->'tunnels'->(x.slot-1)->>'customer_inside_address' IS DISTINCT FROM host(x.customer_inside_ipv4)
 OR m->'tunnels'->(x.slot-1)->>'cloud_inside_address' IS DISTINCT FROM host(x.aws_inside_ipv4)))))
 AND (n.provider_profile NOT LIKE '%-bgp-%' OR m->>'profile_id' NOT LIKE '%-bgp-%' OR (m->'bgp')-'maximum_prefixes'=jsonb_build_object('local_asn',bg.local_asn,'remote_asn',bg.remote_asn,'router_id',host(bg.router_id))),false)
 FROM ipsec_connections n JOIN ipsec_aws_static_configs sc ON sc.connection_id=n.id LEFT JOIN ipsec_aws_bgp_configs bg ON bg.connection_id=n.id WHERE n.id=c;
$$ LANGUAGE sql STABLE;
CREATE FUNCTION ipsec_azure_profile_historical_contract(m jsonb) RETURNS boolean AS $$
DECLARE profile text; t jsonb;i integer;n integer;prefix cidr;local_ip inet;remote_ip inet;
BEGIN
 profile:=m->>'profile_id';
 IF profile IS NULL OR profile NOT IN('azure-active-active-bgp-ipv4-v1','azure-active-active-static-ipv4-v1','azure-active-standby-bgp-ipv4-v1','azure-active-standby-static-ipv4-v1') OR jsonb_typeof(m->'tunnels') IS DISTINCT FROM 'array' OR jsonb_array_length(m->'tunnels')<>2 THEN RETURN false;END IF;
 n:=CASE WHEN profile LIKE '%-standby-%' THEN 1 ELSE 2 END;
 IF n=1 THEN
 IF m->'transport_version' IS DISTINCT FROM '1'::jsonb OR m->'tunnel_count' IS DISTINCT FROM '1'::jsonb OR m->'tunnels'->1 IS DISTINCT FROM '{"id":"00000000-0000-0000-0000-000000000000","slot":0,"secret_revision":0,"link_name":"","xfrm_id":0,"reqid":0,"outside_address":"","inside_cidr":"","customer_inside_address":"","cloud_inside_address":"","route_table":0,"route_protocol":0,"route_metric":0,"selected":false}'::jsonb THEN RETURN false;END IF;
 ELSIF m ? 'transport_version' OR m ? 'tunnel_count' THEN RETURN false;END IF;
 IF profile LIKE '%-bgp-%' THEN
 IF jsonb_typeof(m->'bgp') IS DISTINCT FROM 'object' OR m->'bgp_version' IS DISTINCT FROM '3'::jsonb OR m ? 'recovery_version' OR NOT coalesce((m->'bgp'->>'local_asn')::bigint BETWEEN 1 AND 4294967294 AND (m->'bgp'->>'remote_asn')::bigint BETWEEN 1 AND 4294967294 AND (m->'bgp'->>'maximum_prefixes')::integer BETWEEN 1 AND 64 AND family((m->'bgp'->>'router_id')::inet)=4,false) THEN RETURN false;END IF;
 IF (m->'bgp'->>'local_asn')::bigint=(m->'bgp'->>'remote_asn')::bigint OR (m->'bgp'->>'local_asn')::bigint IN(8074,8075,12076,23456,65515,65517,65518,65519,65520) OR (m->'bgp'->>'remote_asn')::bigint IN(8074,8075,12076,23456,65517,65518,65519,65520) OR (m->'bgp'->>'local_asn')::bigint BETWEEN 64496 AND 64511 OR (m->'bgp'->>'remote_asn')::bigint BETWEEN 64496 AND 64511 OR (m->'bgp'->>'local_asn')::bigint BETWEEN 65535 AND 65551 OR (m->'bgp'->>'remote_asn')::bigint BETWEEN 65535 AND 65551 THEN RETURN false;END IF;
 IF m->'bgp' IS DISTINCT FROM jsonb_build_object('local_asn',(m->'bgp'->>'local_asn')::bigint,'remote_asn',(m->'bgp'->>'remote_asn')::bigint,'router_id',host((m->'bgp'->>'router_id')::inet),'maximum_prefixes',(m->'bgp'->>'maximum_prefixes')::integer) OR (m->'bgp'->>'router_id')::inet <<= ANY(ARRAY['0.0.0.0/8','127.0.0.0/8','169.254.0.0/16','224.0.0.0/4','240.0.0.0/4']::cidr[]) THEN RETURN false;END IF;
 ELSE IF m ? 'bgp' OR m ? 'bgp_version' OR n=1 AND m ? 'recovery_version' OR m ? 'recovery_version' AND m->'recovery_version' IS DISTINCT FROM '1'::jsonb THEN RETURN false;END IF;END IF;
 FOR i IN 0..n-1 LOOP
 t:=m->'tunnels'->i;
 IF t->'slot' IS DISTINCT FROM to_jsonb(i+1) OR NOT coalesce(family((t->>'outside_address')::inet)=4,false) THEN RETURN false;END IF;
 IF t->>'outside_address' IS DISTINCT FROM host((t->>'outside_address')::inet) OR (t->>'outside_address')::inet <<= ANY(ARRAY['0.0.0.0/8','10.0.0.0/8','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','224.0.0.0/4','240.0.0.0/4']::cidr[]) OR t->>'outside_address'=m->>'customer_outside_address' OR i=1 AND t->>'outside_address'=m->'tunnels'->0->>'outside_address' THEN RETURN false;END IF;
 prefix:=(t->>'inside_cidr')::cidr;local_ip:=(t->>'customer_inside_address')::inet;remote_ip:=(t->>'cloud_inside_address')::inet;
 IF t->>'inside_cidr' IS DISTINCT FROM prefix::text OR t->>'customer_inside_address' IS DISTINCT FROM host(local_ip) OR t->>'cloud_inside_address' IS DISTINCT FROM host(remote_ip) THEN RETURN false;END IF;
 IF prefix IS NULL OR local_ip IS NULL OR remote_ip IS NULL OR NOT(prefix <<= '169.254.0.0/16'::cidr) OR family(local_ip)<>4 OR family(remote_ip)<>4 OR masklen(local_ip)<>32 OR masklen(remote_ip)<>32 OR local_ip=remote_ip THEN RETURN false;END IF;
 IF profile LIKE '%-bgp-%' THEN
 IF masklen(prefix)<>32 OR prefix<>local_ip::cidr OR NOT(remote_ip <<= '169.254.21.0/24'::cidr OR remote_ip <<= '169.254.22.0/24'::cidr) OR t->'selected' IS DISTINCT FROM 'false'::jsonb THEN RETURN false;END IF;
 IF i=1 AND (t->>'customer_inside_address' IS DISTINCT FROM m->'tunnels'->0->>'customer_inside_address' OR t->>'inside_cidr' IS DISTINCT FROM m->'tunnels'->0->>'inside_cidr' OR t->>'cloud_inside_address'=m->'tunnels'->0->>'cloud_inside_address') THEN RETURN false;END IF;
 ELSE IF i=1 AND prefix && (m->'tunnels'->0->>'inside_cidr')::cidr THEN RETURN false;END IF;IF masklen(prefix)<>30 OR local_ip NOT IN(set_masklen(network(prefix)+1,32),set_masklen(network(prefix)+2,32)) OR remote_ip NOT IN(set_masklen(network(prefix)+1,32),set_masklen(network(prefix)+2,32)) THEN RETURN false;END IF;END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END; $$ LANGUAGE plpgsql IMMUTABLE;
CREATE FUNCTION ipsec_azure_profile_manifest_contract(m jsonb,p uuid) RETURNS boolean AS $$
 SELECT CASE WHEN jsonb_typeof(m->'tunnels')='array' THEN coalesce(
 m->>'profile_id'=o.provider_profile AND m->>'customer_outside_address'=host(sc.customer_outside_ipv4)
 AND jsonb_array_length(m->'tunnels')=2
 AND ((o.provider_profile LIKE '%-standby-%' AND m->'transport_version'='1'::jsonb AND m->'tunnel_count'='1'::jsonb AND m->'tunnels'->1='{"id":"00000000-0000-0000-0000-000000000000","slot":0,"secret_revision":0,"link_name":"","xfrm_id":0,"reqid":0,"outside_address":"","inside_cidr":"","customer_inside_address":"","cloud_inside_address":"","route_table":0,"route_protocol":0,"route_metric":0,"selected":false}'::jsonb)
 OR (o.provider_profile LIKE '%-active-%' AND NOT(m ? 'transport_version') AND NOT(m ? 'tunnel_count')))
 AND ((o.provider_profile LIKE '%-bgp-%' AND m->'bgp_version'='3'::jsonb AND m->'bgp'=jsonb_build_object('local_asn',bg.local_asn,'remote_asn',bg.remote_asn,'router_id',host(bg.router_id),'maximum_prefixes',bg.maximum_prefixes) AND NOT(m ? 'recovery_version'))
 OR (o.provider_profile LIKE '%-static-%' AND NOT(m ? 'bgp') AND NOT(m ? 'bgp_version')))
 AND NOT EXISTS(SELECT 1 FROM ipsec_aws_tunnel_configs tc WHERE tc.connection_id=p AND (
 m->'tunnels'->(tc.slot-1)->'slot' IS DISTINCT FROM to_jsonb(tc.slot)
 OR m->'tunnels'->(tc.slot-1)->>'outside_address' IS DISTINCT FROM host(tc.aws_outside_ipv4)
 OR m->'tunnels'->(tc.slot-1)->>'inside_cidr' IS DISTINCT FROM tc.inside_cidr::text
 OR m->'tunnels'->(tc.slot-1)->>'customer_inside_address' IS DISTINCT FROM host(tc.customer_inside_ipv4)
 OR m->'tunnels'->(tc.slot-1)->>'cloud_inside_address' IS DISTINCT FROM host(tc.aws_inside_ipv4)))
 AND (SELECT count(*) FROM ipsec_aws_tunnel_configs WHERE connection_id=p)=CASE WHEN o.provider_profile LIKE '%-standby-%' THEN 1 ELSE 2 END,false) ELSE false END
 FROM ipsec_connections o JOIN ipsec_aws_static_configs sc ON sc.connection_id=o.id LEFT JOIN ipsec_aws_bgp_configs bg ON bg.connection_id=o.id WHERE o.id=p;
$$ LANGUAGE sql STABLE;
CREATE FUNCTION ipsec_azure_profile_recreation_validate(c uuid,p uuid,d uuid) RETURNS void AS $$
DECLARE item jsonb;prior jsonb;
BEGIN
 FOR item IN SELECT value FROM ipsec_runtime_deliveries rd CROSS JOIN LATERAL jsonb_array_elements(rd.lineage) WHERE rd.id=d LOOP
 prior:=item->'manifest';
 IF item->>'kind' IS DISTINCT FROM 'apply' OR prior->>'connection_id' IS DISTINCT FROM p::text
 OR NOT EXISTS(SELECT 1 FROM ipsec_connections n WHERE n.id=c AND prior->>'org_id'=n.org_id::text AND prior->>'site_id'=n.historical_site_id::text AND prior->>'node_id'=n.historical_gateway_node_id::text)
 OR NOT EXISTS(SELECT 1 FROM ipsec_connections old WHERE old.id=p AND prior->>'profile_id'=old.provider_profile)
 OR NOT coalesce(ipsec_azure_profile_historical_contract(prior),false) OR NOT coalesce(ipsec_azure_profile_recreation_pair(prior,c),false)
 OR ARRAY(SELECT value FROM jsonb_array_elements_text(prior->'local_prefixes') ORDER BY value) IS DISTINCT FROM ARRAY(SELECT cidr::text FROM ipsec_retained_local_prefixes WHERE cleanup_delivery_id=d ORDER BY cidr::text)
 OR NOT ipsec_azure_bgp_recreation_domains(ARRAY(SELECT value FROM jsonb_array_elements_text(prior->'remote_prefixes')),ARRAY(SELECT cidr::text FROM ipsec_retained_remote_prefixes WHERE cleanup_delivery_id=d))
 THEN RAISE EXCEPTION 'Azure profile lineage invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict';END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM ipsec_runtime_deliveries WHERE id=d AND jsonb_array_length(lineage)>0) OR EXISTS(SELECT 1 FROM ipsec_retained_guards g WHERE g.connection_id=p AND (
 ARRAY(SELECT cidr::text FROM ipsec_retained_local_prefixes WHERE cleanup_delivery_id=g.cleanup_delivery_id ORDER BY cidr::text) IS DISTINCT FROM ARRAY(SELECT cidr::text FROM ipsec_aws_local_prefixes WHERE connection_id=c ORDER BY cidr::text)
 OR NOT ipsec_azure_bgp_recreation_domains(ARRAY(SELECT cidr::text FROM ipsec_retained_remote_prefixes WHERE cleanup_delivery_id=g.cleanup_delivery_id),ARRAY(SELECT cidr::text FROM ipsec_aws_remote_prefixes WHERE connection_id=c)))) THEN RAISE EXCEPTION 'Azure profile history invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict';END IF;
END; $$ LANGUAGE plpgsql;
CREATE FUNCTION ipsec_azure_profile_recreation_used(c uuid) RETURNS boolean AS $$
 SELECT EXISTS(SELECT 1 FROM ipsec_static_recreations r JOIN ipsec_connections p ON p.id=r.predecessor_connection_id JOIN ipsec_connections n ON n.id=r.connection_id WHERE r.connection_id=c AND p.provider_profile IS DISTINCT FROM n.provider_profile);
$$ LANGUAGE sql STABLE;
CREATE FUNCTION ipsec_azure_profile_recreation_capable(node uuid) RETURNS boolean AS $$
 SELECT coalesce(status='active' AND revoked_at IS NULL AND cert_serial<>'' AND capabilities->'ipsec_config_version'='1'::jsonb AND capabilities->'ipsec_retained_guard_version'='1'::jsonb AND capabilities->'ipsec_azure_version'='1'::jsonb AND capabilities->'ipsec_azure_profile_recreation_version'='1'::jsonb AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp(),false) FROM nodes WHERE id=node;
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
  OR COALESCE(c.provider_profile,'') NOT IN('aws-static-ipv4-v1','gcp-classic-static-ipv4-v1','azure-active-active-static-ipv4-v1','azure-active-standby-static-ipv4-v1','azure-active-active-bgp-ipv4-v1','azure-active-standby-bgp-ipv4-v1') OR (c.provider_profile='azure-active-standby-bgp-ipv4-v1' AND NOT coalesce(ipsec_azure_profile_recreation_capable(c.historical_gateway_node_id),false)) OR (p.provider_profile IS DISTINCT FROM c.provider_profile AND (p.provider_profile NOT IN('azure-active-active-bgp-ipv4-v1','azure-active-active-static-ipv4-v1','azure-active-standby-bgp-ipv4-v1','azure-active-standby-static-ipv4-v1') OR c.provider_profile NOT LIKE 'azure-%' OR NOT coalesce(ipsec_azure_profile_recreation_capable(c.historical_gateway_node_id),false)))
  OR (c.provider_profile='azure-active-active-bgp-ipv4-v1' AND p.provider_profile=c.provider_profile AND NOT EXISTS(SELECT 1 FROM nodes WHERE id=c.historical_gateway_node_id AND org_id=c.org_id AND site_id=c.historical_site_id AND status='active' AND revoked_at IS NULL AND cert_serial<>'' AND capabilities->'ipsec_config_version'='1'::jsonb AND capabilities->'ipsec_retained_guard_version'='1'::jsonb AND capabilities->'ipsec_azure_version'='1'::jsonb AND capabilities->'ipsec_bgp_version'='1'::jsonb AND capabilities->'ipsec_azure_bgp_recreation_version'='1'::jsonb AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp()))
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
CREATE OR REPLACE FUNCTION ipsec_static_recreation_domain() RETURNS trigger AS $$
DECLARE locals text[]; remotes text[];
BEGIN
 IF ipsec_azure_profile_recreation_used(NEW.connection_id) THEN PERFORM ipsec_azure_profile_recreation_validate(NEW.connection_id,NEW.predecessor_connection_id,NEW.cleanup_delivery_id);RETURN NULL;END IF;
 IF EXISTS(SELECT 1 FROM ipsec_connections WHERE id=NEW.connection_id AND provider_profile='azure-active-standby-bgp-ipv4-v1') THEN RAISE EXCEPTION 'Standby BGP requires mixed finalized profile history' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict';END IF;
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
DECLARE expected jsonb; azure boolean; cross_profile boolean;
BEGIN
 SELECT provider_profile='azure-active-active-bgp-ipv4-v1' INTO azure FROM ipsec_connections WHERE id=NEW.connection_id;
 IF NEW.kind<>'apply' THEN RETURN NEW; END IF;
 SELECT ipsec_static_recreation_predecessors(NEW.connection_id,NEW.org_id) INTO expected;
 cross_profile:=ipsec_azure_profile_recreation_used(NEW.connection_id);
 IF cross_profile THEN
 IF expected IS NULL OR NEW.manifest->'retained_guard_predecessors' IS DISTINCT FROM expected OR jsonb_array_length(expected)>256 OR NEW.manifest->'azure_profile_recreation_version' IS DISTINCT FROM '1'::jsonb OR NEW.manifest ? 'azure_bgp_recreation_version' OR NOT coalesce(ipsec_azure_profile_manifest_contract(NEW.manifest,NEW.connection_id),false) OR NOT coalesce(ipsec_azure_profile_recreation_capable(NEW.node_id),false) THEN RAISE EXCEPTION 'Azure profile recreation manifest invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding';END IF; RETURN NEW;END IF;
 IF NEW.manifest ? 'azure_profile_recreation_version' THEN RAISE EXCEPTION 'Azure profile version invalid' USING ERRCODE='23514';END IF;
 IF (NEW.manifest->'retained_guard_predecessors') IS DISTINCT FROM expected
  OR (expected IS NOT NULL AND (jsonb_array_length(expected)>256 OR (NOT azure AND (NEW.manifest ? 'bgp' OR NEW.manifest ? 'bgp_version')) OR (azure AND (NEW.manifest->'azure_bgp_recreation_version' IS DISTINCT FROM '1'::jsonb OR NEW.manifest->'bgp_version' IS DISTINCT FROM '3'::jsonb OR NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.node_id AND capabilities->'ipsec_azure_bgp_recreation_version'='1'::jsonb)))
   OR NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.node_id AND org_id=NEW.org_id AND site_id=NEW.site_id AND status='active' AND revoked_at IS NULL AND cert_serial<>'' AND capabilities->'ipsec_config_version'='1'::jsonb AND capabilities->'ipsec_retained_guard_version'='1'::jsonb AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp())))
 THEN RAISE EXCEPTION 'IPsec static recreation manifest invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding'; END IF;
 IF expected IS NULL AND NEW.manifest ? 'azure_bgp_recreation_version' OR NOT azure AND NEW.manifest ? 'azure_bgp_recreation_version' THEN RAISE EXCEPTION 'Azure recreation version invalid' USING ERRCODE='23514';END IF;
 RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE FUNCTION ipsec_azure_profile_recreation_enable() RETURNS trigger AS $$
BEGIN
 IF NEW.desired_intent='enabled' AND ipsec_azure_profile_recreation_used(NEW.id) AND NOT coalesce(ipsec_azure_profile_recreation_capable(NEW.historical_gateway_node_id),false) THEN RAISE EXCEPTION 'Azure profile recreation capability unavailable' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_ineligible';END IF;RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_azure_profile_recreation_enable BEFORE UPDATE ON ipsec_connections FOR EACH ROW EXECUTE FUNCTION ipsec_azure_profile_recreation_enable();
