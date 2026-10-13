-- Exact-domain static recreation retains every prior refusal and immutable proof.
-- A successor may coalesce only authenticated finalized predecessors on its owner.
CREATE TABLE ipsec_static_recreations (
 connection_id uuid NOT NULL, org_id uuid NOT NULL,
 predecessor_connection_id uuid NOT NULL, cleanup_delivery_id uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(connection_id,predecessor_connection_id),
 CHECK(connection_id<>predecessor_connection_id),
 FOREIGN KEY(connection_id,org_id) REFERENCES ipsec_connections(id,org_id) ON DELETE RESTRICT,
 FOREIGN KEY(predecessor_connection_id,org_id) REFERENCES ipsec_connections(id,org_id) ON DELETE RESTRICT,
 FOREIGN KEY(cleanup_delivery_id) REFERENCES ipsec_retained_guards(cleanup_delivery_id) ON DELETE RESTRICT
);
CREATE TRIGGER ipsec_static_recreation_immutable BEFORE UPDATE OR DELETE ON ipsec_static_recreations FOR EACH ROW EXECUTE FUNCTION ipsec_runtime_immutable();
CREATE TRIGGER ipsec_static_recreation_no_truncate BEFORE TRUNCATE ON ipsec_static_recreations FOR EACH STATEMENT EXECUTE FUNCTION ipsec_refuse_truncate();
CREATE FUNCTION ipsec_static_recreation_binding() RETURNS trigger AS $$
DECLARE c ipsec_connections; p ipsec_connections; g ipsec_retained_guards; d ipsec_runtime_deliveries; s ipsec_runtime_state;
BEGIN
 PERFORM ipsec_provider_lock_org(NEW.org_id);
 SELECT * INTO c FROM ipsec_connections WHERE id=NEW.connection_id AND org_id=NEW.org_id FOR UPDATE;
 SELECT * INTO p FROM ipsec_connections WHERE id=NEW.predecessor_connection_id AND org_id=NEW.org_id FOR UPDATE;
 SELECT * INTO g FROM ipsec_retained_guards WHERE cleanup_delivery_id=NEW.cleanup_delivery_id;
 SELECT * INTO d FROM ipsec_runtime_deliveries WHERE id=NEW.cleanup_delivery_id;
 SELECT * INTO s FROM ipsec_runtime_state WHERE connection_id=NEW.predecessor_connection_id;
 IF c.id IS NULL OR p.id IS NULL OR g.cleanup_delivery_id IS NULL OR d.id IS NULL OR s.connection_id IS NULL
  OR c.provider_profile IS DISTINCT FROM 'aws-static-ipv4-v1' OR p.provider_profile IS DISTINCT FROM 'aws-static-ipv4-v1'
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
CREATE TRIGGER ipsec_static_recreation_binding BEFORE INSERT ON ipsec_static_recreations FOR EACH ROW EXECUTE FUNCTION ipsec_static_recreation_binding();

CREATE FUNCTION ipsec_static_recreation_domain() RETURNS trigger AS $$
DECLARE locals text[]; remotes text[];
BEGIN
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
CREATE CONSTRAINT TRIGGER ipsec_static_recreation_domain AFTER INSERT ON ipsec_static_recreations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ipsec_static_recreation_domain();

-- Only the remote-child insertion gains an owner-scoped exemption. Shared route,
-- pool, subnet, inside and underlay checks continue to refuse retained overlaps.
CREATE FUNCTION ipsec_provider_check_recreated_remote(p_org uuid,p_cidr cidr,p_connection uuid) RETURNS void AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM site_subnets ss JOIN sites s ON s.id=ss.site_id WHERE s.org_id=p_org AND ss.status='approved' AND ss.cidr && p_cidr)
  OR EXISTS(SELECT 1 FROM organizations WHERE id=p_org AND pool_cidr::cidr && p_cidr)
  OR EXISTS(SELECT 1 FROM k8s_clusters WHERE org_id=p_org AND vip_range && p_cidr)
  OR EXISTS(SELECT 1 FROM ipsec_retained_remote_prefixes r WHERE r.org_id=p_org AND r.cidr && p_cidr AND NOT EXISTS(
   SELECT 1 FROM ipsec_static_recreations b WHERE b.connection_id=p_connection AND b.org_id=p_org AND b.predecessor_connection_id=r.connection_id AND r.cidr=p_cidr))
  OR EXISTS(SELECT 1 FROM ipsec_aws_remote_prefixes WHERE org_id=p_org AND cidr && p_cidr)
  OR EXISTS(SELECT 1 FROM ipsec_aws_tunnel_configs WHERE org_id=p_org AND inside_cidr && p_cidr)
  OR EXISTS(SELECT 1 FROM ipsec_aws_static_configs WHERE org_id=p_org AND customer_outside_ipv4::cidr && p_cidr)
  OR EXISTS(SELECT 1 FROM ipsec_aws_tunnel_configs WHERE org_id=p_org AND aws_outside_ipv4::cidr && p_cidr)
 THEN RAISE EXCEPTION 'IPsec reservation conflict' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict'; END IF;
END; $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION ipsec_provider_child_guard() RETURNS trigger AS $$
DECLARE o uuid; c uuid; withdrawing boolean; sealed boolean; intent text;
BEGIN
 IF TG_OP='UPDATE' THEN RAISE EXCEPTION 'IPsec provider configuration immutable' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_immutable'; END IF;
 IF TG_OP='DELETE' THEN o:=OLD.org_id;c:=OLD.connection_id; ELSE o:=NEW.org_id;c:=NEW.connection_id; END IF;
 PERFORM ipsec_provider_lock_org(o);
 SELECT b.withdrawal_started,b.configuration_sealed,p.desired_intent INTO withdrawing,sealed,intent FROM ipsec_provider_bindings b JOIN ipsec_connections p ON p.id=b.connection_id AND p.org_id=b.org_id WHERE b.connection_id=c AND b.org_id=o FOR UPDATE OF b,p;
 IF NOT FOUND THEN RAISE EXCEPTION 'IPsec provider owner unavailable' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_immutable'; END IF;
 IF TG_OP='DELETE' THEN
  IF EXISTS(SELECT 1 FROM ipsec_runtime_state WHERE connection_id=c AND coalesce(last_potentially_delivered_revision,0)>coalesce(last_cleaned_delivery_revision,0)) THEN RAISE EXCEPTION 'IPsec cleanup proof required' USING ERRCODE='23514'; END IF;
  IF NOT withdrawing THEN UPDATE ipsec_provider_bindings SET withdrawal_started=true WHERE connection_id=c; END IF;
  RETURN OLD;
 END IF;
 IF withdrawing OR sealed OR intent<>'disabled' THEN RAISE EXCEPTION 'IPsec provider configuration withdrawn' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_immutable'; END IF;
 IF TG_TABLE_NAME='ipsec_aws_static_configs' THEN PERFORM ipsec_provider_check_range(o,NEW.customer_outside_ipv4::cidr,'underlay');
 ELSIF TG_TABLE_NAME='ipsec_aws_tunnel_configs' THEN
  PERFORM ipsec_provider_check_range(o,NEW.aws_outside_ipv4::cidr,'underlay');
  PERFORM ipsec_provider_check_range(o,NEW.inside_cidr,'inside');
  IF EXISTS(SELECT 1 FROM ipsec_aws_static_configs WHERE connection_id=c AND customer_outside_ipv4=NEW.aws_outside_ipv4) THEN RAISE EXCEPTION 'IPsec outside identity conflict' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict'; END IF;
 ELSIF TG_TABLE_NAME='ipsec_aws_remote_prefixes' THEN PERFORM ipsec_provider_check_recreated_remote(o,NEW.cidr,c);
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- A retained native journal entry keeps the first successful cleanup identity.
-- The binding above still proves the latest finalized, complete cleanup. Each
-- apply reference instead names its earliest acknowledged retained cleanup.
CREATE FUNCTION ipsec_static_recreation_predecessors(p_connection uuid,p_org uuid) RETURNS jsonb AS $$
 SELECT jsonb_agg(jsonb_build_object(
  'connection_id',b.predecessor_connection_id,
  'delivery_id',item->>'delivery_id',
  'cleanup_delivery_id',first_retained.cleanup_delivery_id,
  'ownership_digest',item->>'ownership_digest') ORDER BY item->>'delivery_id')
 FROM ipsec_static_recreations b
 JOIN ipsec_runtime_deliveries latest ON latest.id=b.cleanup_delivery_id
 CROSS JOIN LATERAL jsonb_array_elements(latest.lineage) item
 LEFT JOIN LATERAL (
  SELECT g.cleanup_delivery_id
  FROM ipsec_retained_guards g JOIN ipsec_runtime_deliveries cleaned ON cleaned.id=g.cleanup_delivery_id
  WHERE g.connection_id=b.predecessor_connection_id AND g.org_id=b.org_id
   AND g.site_id=latest.site_id AND g.gateway_node_id=latest.node_id
   AND cleaned.kind='cleanup' AND cleaned.connection_id=g.connection_id AND cleaned.org_id=g.org_id
   AND cleaned.site_id=g.site_id AND cleaned.node_id=g.gateway_node_id AND cleaned.ownership_digest=g.ownership_digest
   AND EXISTS(SELECT 1 FROM jsonb_array_elements(cleaned.lineage) prior WHERE prior=item)
  ORDER BY g.retained_at,cleaned.desired_revision,cleaned.id LIMIT 1
 ) first_retained ON true
 WHERE b.connection_id=p_connection AND b.org_id=p_org;
$$ LANGUAGE sql STABLE;

-- A direct database writer cannot strip, substitute or add successor authority.
CREATE FUNCTION ipsec_static_recreation_delivery() RETURNS trigger AS $$
DECLARE expected jsonb;
BEGIN
 IF NEW.kind<>'apply' THEN RETURN NEW; END IF;
 SELECT ipsec_static_recreation_predecessors(NEW.connection_id,NEW.org_id) INTO expected;
 IF (NEW.manifest->'retained_guard_predecessors') IS DISTINCT FROM expected
  OR (expected IS NOT NULL AND (jsonb_array_length(expected)>256 OR NEW.manifest ? 'bgp' OR NEW.manifest ? 'bgp_version'
   OR NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.node_id AND org_id=NEW.org_id AND site_id=NEW.site_id AND status='active' AND revoked_at IS NULL AND capabilities->'ipsec_config_version'='1'::jsonb AND capabilities->'ipsec_retained_guard_version'='1'::jsonb AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp())))
 THEN RAISE EXCEPTION 'IPsec static recreation manifest invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding'; END IF;
 RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_static_recreation_delivery BEFORE INSERT ON ipsec_runtime_deliveries FOR EACH ROW EXECUTE FUNCTION ipsec_static_recreation_delivery();

CREATE FUNCTION ipsec_static_recreation_enable() RETURNS trigger AS $$
BEGIN
 IF NEW.desired_intent='enabled' AND EXISTS(SELECT 1 FROM ipsec_static_recreations WHERE connection_id=NEW.id) AND NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.historical_gateway_node_id AND org_id=NEW.org_id AND site_id=NEW.historical_site_id AND status='active' AND revoked_at IS NULL AND capabilities->'ipsec_config_version'='1'::jsonb AND capabilities->'ipsec_retained_guard_version'='1'::jsonb AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp()) THEN RAISE EXCEPTION 'IPsec retained guard capability unavailable' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_ineligible'; END IF;
 RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_static_recreation_enable BEFORE UPDATE ON ipsec_connections FOR EACH ROW EXECUTE FUNCTION ipsec_static_recreation_enable();
