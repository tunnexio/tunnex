DO $$ BEGIN IF EXISTS(SELECT 1 FROM ipsec_bgp_status s JOIN ipsec_aws_bgp_configs b USING(connection_id,org_id) WHERE jsonb_array_length(s.report->'bgp'->'routes')>b.maximum_prefixes) THEN RAISE EXCEPTION 'Cannot downgrade while BGP union exceeds legacy bound'; END IF; END $$;
CREATE OR REPLACE FUNCTION ipsec_bgp_status_guard() RETURNS trigger AS $$
DECLARE d ipsec_runtime_deliveries; c ipsec_connections; bound integer;
BEGIN
 SELECT * INTO c FROM ipsec_connections WHERE id=NEW.connection_id AND org_id=NEW.org_id;
 SELECT * INTO d FROM ipsec_runtime_deliveries WHERE id=NEW.delivery_id AND connection_id=NEW.connection_id AND org_id=NEW.org_id;
 SELECT maximum_prefixes INTO bound FROM ipsec_aws_bgp_configs WHERE connection_id=NEW.connection_id AND org_id=NEW.org_id;
 IF c.provider_profile IS DISTINCT FROM 'aws-bgp-ipv4-v1' OR c.desired_intent<>'enabled' OR c.desired_revision<>NEW.desired_revision OR c.finalized_at IS NOT NULL
  OR d.kind IS DISTINCT FROM 'apply' OR d.manifest->>'profile_id' IS DISTINCT FROM 'aws-bgp-ipv4-v1' OR d.desired_revision<>NEW.desired_revision OR d.node_id<>NEW.node_id OR d.configuration_revision<>NEW.configuration_revision OR d.certificate_serial<>NEW.certificate_serial
  OR NEW.report->>'delivery_id' IS DISTINCT FROM NEW.delivery_id::text OR NEW.report->>'desired_revision' IS DISTINCT FROM NEW.desired_revision::text OR NEW.report->>'configuration_revision' IS DISTINCT FROM NEW.configuration_revision::text
  OR NEW.report ? 'active_slot' OR NEW.report ? 'selection_sequence' OR NEW.report ? 'recovery_version'
  OR bound IS NULL OR jsonb_array_length(NEW.report->'bgp'->'routes')>bound
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.report->'bgp'->'routes') r WHERE jsonb_typeof(r->'slot') IS DISTINCT FROM 'number' OR r->'slot' NOT IN('1'::jsonb,'2'::jsonb) OR NOT EXISTS(SELECT 1 FROM ipsec_aws_remote_prefixes p WHERE p.connection_id=NEW.connection_id AND p.org_id=NEW.org_id AND p.cidr::text=r->>'prefix'))
  OR (SELECT count(DISTINCT r->>'prefix') FROM jsonb_array_elements(NEW.report->'bgp'->'routes') r)<>jsonb_array_length(NEW.report->'bgp'->'routes') THEN
  RAISE EXCEPTION 'IPsec BGP observation binding invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding';
 END IF;
 RETURN NEW;
END; $$ LANGUAGE plpgsql;
