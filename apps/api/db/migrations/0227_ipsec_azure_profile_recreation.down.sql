DO $$ BEGIN IF EXISTS(SELECT 1 FROM ipsec_connections WHERE ipsec_azure_profile_recreation_used(id)) THEN RAISE EXCEPTION 'Azure profile recreation history prevents downgrade';END IF;END $$;
DROP TRIGGER ipsec_azure_profile_recreation_enable ON ipsec_connections;
DROP FUNCTION ipsec_azure_profile_recreation_enable();
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
DROP FUNCTION ipsec_azure_profile_recreation_capable(uuid);
DROP FUNCTION ipsec_azure_profile_recreation_used(uuid);
DROP FUNCTION ipsec_azure_profile_recreation_validate(uuid,uuid,uuid);
DROP FUNCTION ipsec_azure_profile_manifest_contract(jsonb,uuid);
DROP FUNCTION ipsec_azure_profile_recreation_pair(jsonb,uuid);
DROP FUNCTION ipsec_azure_profile_historical_contract(jsonb);
