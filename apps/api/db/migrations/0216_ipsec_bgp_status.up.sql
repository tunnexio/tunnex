-- Nonsecret authenticated observations; no forwarding authority.
CREATE TABLE ipsec_bgp_status (
 connection_id uuid PRIMARY KEY,org_id uuid NOT NULL,node_id uuid NOT NULL,
 delivery_id uuid NOT NULL,desired_revision bigint NOT NULL CHECK(desired_revision>0),
 configuration_revision bigint NOT NULL CHECK(configuration_revision=1),
 certificate_serial text NOT NULL CHECK(length(certificate_serial)>0),
 received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 report jsonb NOT NULL CHECK(report ?& ARRAY['bgp','tunnels','delivery_id','desired_revision','configuration_revision'] AND report->'bgp' ?& ARRAY['version','sequence','peers','routes'] AND jsonb_typeof(report)='object' AND octet_length(report::text)<=16384
  AND jsonb_typeof(report->'bgp')='object' AND report->'bgp'->'version'='1'::jsonb
  AND jsonb_typeof(report->'bgp'->'peers')='array' AND jsonb_array_length(report->'bgp'->'peers')=2
  AND jsonb_typeof(report->'bgp'->'routes')='array' AND jsonb_array_length(report->'bgp'->'routes')<=64
  AND jsonb_typeof(report->'tunnels')='array' AND jsonb_array_length(report->'tunnels')=2
  AND report->'bgp'->>'sequence' ~ '^[1-9][0-9]{0,19}$' AND (report->'bgp'->>'sequence')::numeric<=9007199254740991),
 FOREIGN KEY(connection_id,org_id) REFERENCES ipsec_connections(id,org_id) ON DELETE RESTRICT,
 FOREIGN KEY(delivery_id,connection_id,org_id) REFERENCES ipsec_runtime_deliveries(id,connection_id,org_id) ON DELETE RESTRICT
);
CREATE FUNCTION ipsec_bgp_status_guard() RETURNS trigger AS $$
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
CREATE TRIGGER ipsec_bgp_status_guard BEFORE INSERT OR UPDATE ON ipsec_bgp_status FOR EACH ROW EXECUTE FUNCTION ipsec_bgp_status_guard();
