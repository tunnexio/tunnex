-- Runtime intent, committed delivery checkpoints and retained refusal ownership.
-- No TTL/force-forget/transfer exists. Historical evidence is append-only.
ALTER TABLE ipsec_connections DROP CONSTRAINT ipsec_connections_desired_intent_check;
ALTER TABLE ipsec_connections DROP CONSTRAINT ipsec_connections_check;
ALTER TABLE ipsec_connections ADD CONSTRAINT ipsec_connections_desired_intent_check CHECK(desired_intent IN('disabled','enabled','deleted'));
ALTER TABLE ipsec_connections ADD CONSTRAINT ipsec_connections_check CHECK(
 (finalized_at IS NULL AND site_id=historical_site_id AND gateway_node_id=historical_gateway_node_id AND site_id IS NOT NULL AND gateway_node_id IS NOT NULL AND ((desired_intent='deleted' AND deleted_at IS NOT NULL) OR (desired_intent<>'deleted' AND deleted_at IS NULL)))
 OR (desired_intent='deleted' AND finalized_at IS NOT NULL AND deleted_at IS NOT NULL AND site_id IS NULL AND gateway_node_id IS NULL));

CREATE TABLE ipsec_runtime_state (
 connection_id uuid PRIMARY KEY, org_id uuid NOT NULL, node_id uuid NOT NULL, site_id uuid NOT NULL,
 last_potentially_delivered_revision bigint CHECK(last_potentially_delivered_revision>0),
 last_cleaned_delivery_revision bigint CHECK(last_cleaned_delivery_revision>0),
 current_cleanup_id uuid, applied_revision bigint CHECK(applied_revision>0),
 UNIQUE(connection_id,org_id),
 FOREIGN KEY(connection_id,org_id) REFERENCES ipsec_connections(id,org_id) ON DELETE RESTRICT,
 CHECK(last_cleaned_delivery_revision IS NULL OR (last_potentially_delivered_revision IS NOT NULL AND last_cleaned_delivery_revision<=last_potentially_delivered_revision))
);
CREATE TABLE ipsec_runtime_deliveries (
 id uuid PRIMARY KEY, connection_id uuid NOT NULL,org_id uuid NOT NULL,node_id uuid NOT NULL,site_id uuid NOT NULL,
 desired_revision bigint NOT NULL CHECK(desired_revision>0), kind text NOT NULL CHECK(kind IN('apply','cleanup')),
 configuration_revision bigint NOT NULL CHECK(configuration_revision=1), ownership_digest text NOT NULL CHECK(ownership_digest ~ '^[0-9a-f]{64}$'),
 manifest jsonb NOT NULL CHECK(jsonb_typeof(manifest)='object' AND octet_length(manifest::text)<=65536),
 lineage jsonb NOT NULL DEFAULT '[]' CHECK(jsonb_typeof(lineage)='array' AND octet_length(lineage::text)<=524288),
 covers_delivery_revision bigint CHECK(covers_delivery_revision>0), certificate_serial text,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(connection_id,desired_revision,kind), UNIQUE(id,connection_id,org_id),
 FOREIGN KEY(connection_id,org_id) REFERENCES ipsec_runtime_state(connection_id,org_id) ON DELETE RESTRICT,
 CHECK((kind='apply' AND covers_delivery_revision IS NULL AND certificate_serial IS NOT NULL AND length(certificate_serial)>0 AND lineage='[]'::jsonb)
 OR (kind='cleanup' AND covers_delivery_revision IS NOT NULL AND certificate_serial IS NULL AND jsonb_array_length(lineage)>0))
);
ALTER TABLE ipsec_runtime_state ADD CONSTRAINT ipsec_runtime_current_cleanup_fk FOREIGN KEY(current_cleanup_id,connection_id,org_id) REFERENCES ipsec_runtime_deliveries(id,connection_id,org_id) ON DELETE RESTRICT;
CREATE TABLE ipsec_runtime_acknowledgements (
 delivery_id uuid PRIMARY KEY,connection_id uuid NOT NULL,org_id uuid NOT NULL,node_id uuid NOT NULL,site_id uuid NOT NULL,
 desired_revision bigint NOT NULL CHECK(desired_revision>0),kind text NOT NULL CHECK(kind IN('apply','cleanup')),result text NOT NULL CHECK(result IN('applied','cleaned')),
 ownership_digest text NOT NULL CHECK(ownership_digest ~ '^[0-9a-f]{64}$'),guard_retained boolean NOT NULL,
 certificate_serial text NOT NULL CHECK(length(certificate_serial)>0),received_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(delivery_id,connection_id,org_id) REFERENCES ipsec_runtime_deliveries(id,connection_id,org_id) ON DELETE RESTRICT,
 CHECK((kind='apply' AND result='applied' AND NOT guard_retained) OR (kind='cleanup' AND result='cleaned' AND guard_retained))
);
CREATE TABLE ipsec_retained_guards (
 cleanup_delivery_id uuid PRIMARY KEY,connection_id uuid NOT NULL,org_id uuid NOT NULL,site_id uuid NOT NULL,gateway_node_id uuid NOT NULL,
 ownership_digest text NOT NULL CHECK(ownership_digest ~ '^[0-9a-f]{64}$'),retained_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(cleanup_delivery_id,connection_id,org_id,site_id),
 FOREIGN KEY(cleanup_delivery_id) REFERENCES ipsec_runtime_acknowledgements(delivery_id) ON DELETE RESTRICT,
 FOREIGN KEY(connection_id,org_id) REFERENCES ipsec_connections(id,org_id) ON DELETE RESTRICT,
 FOREIGN KEY(site_id,org_id) REFERENCES sites(id,org_id) ON DELETE RESTRICT,
 FOREIGN KEY(gateway_node_id,org_id,site_id) REFERENCES nodes(id,org_id,site_id) ON DELETE RESTRICT
);
CREATE TABLE ipsec_retained_local_prefixes (
 cleanup_delivery_id uuid NOT NULL,connection_id uuid NOT NULL,org_id uuid NOT NULL,site_id uuid NOT NULL,subnet_id uuid NOT NULL,cidr cidr NOT NULL,subnet_status text NOT NULL DEFAULT 'approved' CHECK(subnet_status='approved'),
 PRIMARY KEY(cleanup_delivery_id,subnet_id),
 FOREIGN KEY(cleanup_delivery_id,connection_id,org_id,site_id) REFERENCES ipsec_retained_guards(cleanup_delivery_id,connection_id,org_id,site_id) ON DELETE RESTRICT,
 CONSTRAINT ipsec_retained_local_subnet_fk FOREIGN KEY(subnet_id,site_id,cidr,subnet_status) REFERENCES site_subnets(id,site_id,cidr,status) ON DELETE RESTRICT
);
CREATE TABLE ipsec_retained_remote_prefixes (
 cleanup_delivery_id uuid NOT NULL REFERENCES ipsec_retained_guards(cleanup_delivery_id) ON DELETE RESTRICT,
 connection_id uuid NOT NULL,org_id uuid NOT NULL,cidr cidr NOT NULL,
 PRIMARY KEY(cleanup_delivery_id,cidr),
 FOREIGN KEY(connection_id,org_id) REFERENCES ipsec_connections(id,org_id) ON DELETE RESTRICT
);
CREATE INDEX ipsec_runtime_pending_node_idx ON ipsec_connections(historical_gateway_node_id,id) WHERE finalized_at IS NULL;
CREATE INDEX ipsec_retained_remote_org_idx ON ipsec_retained_remote_prefixes(org_id);

CREATE FUNCTION ipsec_runtime_immutable() RETURNS trigger AS $$
BEGIN
 RAISE EXCEPTION 'IPsec runtime history immutable' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_immutable';
END; $$ LANGUAGE plpgsql;
CREATE FUNCTION ipsec_runtime_state_guard() RETURNS trigger AS $$
DECLARE c ipsec_connections;
BEGIN
 IF TG_OP='DELETE' OR pg_trigger_depth()<2 THEN RAISE EXCEPTION 'IPsec runtime checkpoint unavailable' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_immutable'; END IF;
 SELECT * INTO c FROM ipsec_connections WHERE id=NEW.connection_id AND org_id=NEW.org_id;
 IF NOT FOUND OR NEW.node_id<>c.historical_gateway_node_id OR NEW.site_id<>c.historical_site_id THEN RAISE EXCEPTION 'IPsec runtime owner invalid' USING ERRCODE='23514'; END IF;
 IF TG_OP='UPDATE' AND (NEW.connection_id<>OLD.connection_id OR NEW.org_id<>OLD.org_id OR NEW.node_id<>OLD.node_id OR NEW.site_id<>OLD.site_id OR coalesce(NEW.last_potentially_delivered_revision,0)<coalesce(OLD.last_potentially_delivered_revision,0) OR coalesce(NEW.last_cleaned_delivery_revision,0)<coalesce(OLD.last_cleaned_delivery_revision,0) OR coalesce(NEW.applied_revision,0)<coalesce(OLD.applied_revision,0)) THEN RAISE EXCEPTION 'IPsec runtime checkpoint regression' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_runtime_state_guard BEFORE INSERT OR UPDATE OR DELETE ON ipsec_runtime_state FOR EACH ROW EXECUTE FUNCTION ipsec_runtime_state_guard();

CREATE FUNCTION ipsec_runtime_connection_state() RETURNS trigger AS $$
BEGIN
 IF NEW.desired_intent='enabled' THEN
  INSERT INTO ipsec_runtime_state(connection_id,org_id,node_id,site_id) VALUES(NEW.id,NEW.org_id,NEW.historical_gateway_node_id,NEW.historical_site_id) ON CONFLICT(connection_id) DO NOTHING;
 END IF;
 RETURN NULL;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_runtime_connection_state AFTER INSERT OR UPDATE ON ipsec_connections FOR EACH ROW EXECUTE FUNCTION ipsec_runtime_connection_state();

CREATE FUNCTION ipsec_runtime_delivery_guard() RETURNS trigger AS $$
DECLARE c ipsec_connections; s ipsec_runtime_state;
BEGIN
 PERFORM ipsec_provider_lock_org(NEW.org_id);
 SELECT * INTO c FROM ipsec_connections WHERE id=NEW.connection_id AND org_id=NEW.org_id FOR UPDATE;
 SELECT * INTO s FROM ipsec_runtime_state WHERE connection_id=NEW.connection_id FOR UPDATE;
 IF c.id IS NULL OR s.connection_id IS NULL OR c.finalized_at IS NOT NULL OR NEW.desired_revision<>c.desired_revision OR NEW.node_id<>c.historical_gateway_node_id OR NEW.site_id<>c.historical_site_id OR NEW.configuration_revision<>1
 OR (NEW.manifest->>'connection_id') IS DISTINCT FROM c.id::text OR (NEW.manifest->>'org_id') IS DISTINCT FROM c.org_id::text OR (NEW.manifest->>'node_id') IS DISTINCT FROM c.historical_gateway_node_id::text OR (NEW.manifest->>'site_id') IS DISTINCT FROM c.historical_site_id::text THEN RAISE EXCEPTION 'IPsec delivery binding invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding'; END IF;
 IF NEW.kind='apply' THEN
  IF (SELECT count(*) FROM ipsec_runtime_deliveries WHERE connection_id=NEW.connection_id AND kind='apply')>=64 OR
   (SELECT coalesce(sum(octet_length(jsonb_build_object('delivery_id',id,'desired_revision',desired_revision,'kind',kind,'ownership_digest',ownership_digest,'manifest',manifest)::text)+2),0) FROM ipsec_runtime_deliveries WHERE connection_id=NEW.connection_id AND kind='apply') + octet_length(jsonb_build_object('delivery_id',NEW.id,'desired_revision',NEW.desired_revision,'kind',NEW.kind,'ownership_digest',NEW.ownership_digest,'manifest',NEW.manifest)::text)+2 > 491520
  THEN RAISE EXCEPTION 'IPsec delivery capacity unavailable' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding'; END IF;
  IF (NEW.manifest->>'desired_revision') IS DISTINCT FROM NEW.desired_revision::text OR (NEW.manifest->>'configuration_revision') IS DISTINCT FROM NEW.configuration_revision::text THEN RAISE EXCEPTION 'IPsec manifest revision invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding'; END IF;
  IF c.desired_intent<>'enabled' OR s.current_cleanup_id IS NOT NULL OR NOT EXISTS(SELECT 1 FROM ipsec_org_settings WHERE org_id=c.org_id AND enabled) OR NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.node_id AND org_id=NEW.org_id AND site_id=NEW.site_id AND status='active' AND revoked_at IS NULL AND cert_serial=NEW.certificate_serial AND capabilities->>'ipsec_config_version'='1' AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp()) THEN RAISE EXCEPTION 'IPsec delivery authorization invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding'; END IF;
 ELSE
  -- Cleanup lineage is the exact ordered immutable apply history. A caller cannot
  -- omit an older potentially delivered assignment or substitute another owner.
  IF NEW.lineage IS DISTINCT FROM (
   SELECT jsonb_agg(jsonb_build_object('delivery_id',d.id,'desired_revision',d.desired_revision,'kind',d.kind,'ownership_digest',d.ownership_digest,'manifest',d.manifest) ORDER BY d.desired_revision)
   FROM ipsec_runtime_deliveries d WHERE d.connection_id=NEW.connection_id AND d.org_id=NEW.org_id AND d.kind='apply'
  ) OR NEW.manifest IS DISTINCT FROM (
   SELECT d.manifest FROM ipsec_runtime_deliveries d WHERE d.connection_id=NEW.connection_id AND d.org_id=NEW.org_id AND d.kind='apply' ORDER BY d.desired_revision DESC LIMIT 1
  ) THEN RAISE EXCEPTION 'IPsec cleanup lineage invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding'; END IF;
  IF c.desired_intent NOT IN('disabled','deleted') OR NEW.covers_delivery_revision IS DISTINCT FROM s.last_potentially_delivered_revision OR coalesce(s.last_cleaned_delivery_revision,0)>=NEW.covers_delivery_revision THEN RAISE EXCEPTION 'IPsec cleanup coverage invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding'; END IF;
 END IF;
 RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_runtime_delivery_guard BEFORE INSERT ON ipsec_runtime_deliveries FOR EACH ROW EXECUTE FUNCTION ipsec_runtime_delivery_guard();
CREATE FUNCTION ipsec_runtime_delivery_checkpoint() RETURNS trigger AS $$
BEGIN
 IF NEW.kind='apply' THEN UPDATE ipsec_runtime_state SET last_potentially_delivered_revision=NEW.desired_revision WHERE connection_id=NEW.connection_id;
 ELSE UPDATE ipsec_runtime_state SET current_cleanup_id=NEW.id WHERE connection_id=NEW.connection_id; END IF;
 RETURN NULL;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_runtime_delivery_checkpoint AFTER INSERT ON ipsec_runtime_deliveries FOR EACH ROW EXECUTE FUNCTION ipsec_runtime_delivery_checkpoint();

CREATE FUNCTION ipsec_runtime_ack_guard() RETURNS trigger AS $$
DECLARE d ipsec_runtime_deliveries;c ipsec_connections;s ipsec_runtime_state;
BEGIN
 PERFORM ipsec_provider_lock_org(NEW.org_id);
 SELECT * INTO c FROM ipsec_connections WHERE id=NEW.connection_id AND org_id=NEW.org_id FOR UPDATE;
 SELECT * INTO s FROM ipsec_runtime_state WHERE connection_id=NEW.connection_id FOR UPDATE;
 SELECT * INTO d FROM ipsec_runtime_deliveries WHERE id=NEW.delivery_id;
 IF d.id IS NULL OR d.connection_id<>NEW.connection_id OR d.org_id<>NEW.org_id OR d.node_id<>NEW.node_id OR d.site_id<>NEW.site_id OR d.kind<>NEW.kind OR d.desired_revision<>NEW.desired_revision OR d.ownership_digest<>NEW.ownership_digest OR c.desired_revision<>NEW.desired_revision OR c.finalized_at IS NOT NULL
 OR NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.node_id AND org_id=NEW.org_id AND site_id=NEW.site_id AND status='active' AND revoked_at IS NULL AND cert_serial=NEW.certificate_serial)
 OR (NEW.kind='apply' AND c.desired_intent<>'enabled') OR (NEW.kind='cleanup' AND (s.current_cleanup_id IS DISTINCT FROM d.id OR c.desired_intent NOT IN('disabled','deleted') OR d.covers_delivery_revision IS DISTINCT FROM s.last_potentially_delivered_revision)) THEN RAISE EXCEPTION 'IPsec acknowledgement binding invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding'; END IF;
 RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_runtime_ack_guard BEFORE INSERT ON ipsec_runtime_acknowledgements FOR EACH ROW EXECUTE FUNCTION ipsec_runtime_ack_guard();
CREATE FUNCTION ipsec_runtime_retained_guard() RETURNS trigger AS $$
BEGIN
 IF pg_trigger_depth()<2 THEN RAISE EXCEPTION 'IPsec retained ownership unavailable' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_immutable'; END IF;
 RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_retained_guard BEFORE INSERT ON ipsec_retained_guards FOR EACH ROW EXECUTE FUNCTION ipsec_runtime_retained_guard();
CREATE TRIGGER ipsec_retained_guard BEFORE INSERT ON ipsec_retained_local_prefixes FOR EACH ROW EXECUTE FUNCTION ipsec_runtime_retained_guard();
CREATE TRIGGER ipsec_retained_guard BEFORE INSERT ON ipsec_retained_remote_prefixes FOR EACH ROW EXECUTE FUNCTION ipsec_runtime_retained_guard();
CREATE FUNCTION ipsec_runtime_ack_checkpoint() RETURNS trigger AS $$
DECLARE d ipsec_runtime_deliveries;
BEGIN
 IF NEW.kind='apply' THEN UPDATE ipsec_runtime_state SET applied_revision=NEW.desired_revision WHERE connection_id=NEW.connection_id;
 ELSE
  SELECT * INTO d FROM ipsec_runtime_deliveries WHERE id=NEW.delivery_id;
  INSERT INTO ipsec_retained_guards(cleanup_delivery_id,connection_id,org_id,site_id,gateway_node_id,ownership_digest) VALUES(NEW.delivery_id,NEW.connection_id,NEW.org_id,NEW.site_id,NEW.node_id,NEW.ownership_digest);
  INSERT INTO ipsec_retained_local_prefixes(cleanup_delivery_id,connection_id,org_id,site_id,subnet_id,cidr) SELECT NEW.delivery_id,connection_id,org_id,site_id,subnet_id,cidr FROM ipsec_aws_local_prefixes WHERE connection_id=NEW.connection_id;
  INSERT INTO ipsec_retained_remote_prefixes(cleanup_delivery_id,connection_id,org_id,cidr) SELECT NEW.delivery_id,connection_id,org_id,cidr FROM ipsec_aws_remote_prefixes WHERE connection_id=NEW.connection_id;
  UPDATE ipsec_runtime_state SET last_cleaned_delivery_revision=d.covers_delivery_revision,current_cleanup_id=NULL WHERE connection_id=NEW.connection_id;
 END IF;
 RETURN NULL;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_runtime_ack_checkpoint AFTER INSERT ON ipsec_runtime_acknowledgements FOR EACH ROW EXECUTE FUNCTION ipsec_runtime_ack_checkpoint();

CREATE FUNCTION ipsec_runtime_coherence() RETURNS trigger AS $$
DECLARE v_id uuid;c ipsec_connections;s ipsec_runtime_state;d ipsec_runtime_deliveries;
BEGIN
 IF TG_TABLE_NAME='ipsec_connections' THEN v_id:=NEW.id;ELSE v_id:=NEW.connection_id;END IF;
 SELECT * INTO c FROM ipsec_connections WHERE ipsec_connections.id=v_id;
 SELECT * INTO s FROM ipsec_runtime_state WHERE connection_id=v_id;
 IF s.connection_id IS NULL THEN RETURN NULL;END IF;
 IF c.desired_intent<>'enabled' AND coalesce(s.last_potentially_delivered_revision,0)>coalesce(s.last_cleaned_delivery_revision,0) THEN
  SELECT * INTO d FROM ipsec_runtime_deliveries WHERE ipsec_runtime_deliveries.id=s.current_cleanup_id;
  IF d.id IS NULL OR d.kind<>'cleanup' OR d.desired_revision<>c.desired_revision OR d.covers_delivery_revision<>s.last_potentially_delivered_revision THEN RAISE EXCEPTION 'IPsec cleanup obligation missing' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_binding'; END IF;
 ELSIF s.current_cleanup_id IS NOT NULL THEN RAISE EXCEPTION 'IPsec stale cleanup marker' USING ERRCODE='23514'; END IF;
 IF c.finalized_at IS NOT NULL AND s.last_potentially_delivered_revision IS NOT NULL AND (coalesce(s.last_cleaned_delivery_revision,0)<s.last_potentially_delivered_revision OR NOT EXISTS(SELECT 1 FROM ipsec_retained_guards g JOIN ipsec_runtime_deliveries r ON r.id=g.cleanup_delivery_id WHERE g.connection_id=v_id AND r.covers_delivery_revision=s.last_potentially_delivered_revision)) THEN RAISE EXCEPTION 'IPsec finalization proof missing' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END; $$ LANGUAGE plpgsql;
CREATE CONSTRAINT TRIGGER ipsec_runtime_coherence AFTER INSERT OR UPDATE ON ipsec_connections DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ipsec_runtime_coherence();
CREATE CONSTRAINT TRIGGER ipsec_runtime_coherence AFTER INSERT OR UPDATE ON ipsec_runtime_state DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ipsec_runtime_coherence();

CREATE OR REPLACE FUNCTION ipsec_connection_guard() RETURNS trigger AS $$
DECLARE s ipsec_runtime_state;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'IPsec connection erasure unavailable' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.desired_intent<>'disabled' OR NEW.desired_revision<>1 THEN RAISE EXCEPTION 'IPsec initial state invalid' USING ERRCODE='23514'; END IF;
  PERFORM ipsec_require_live_org(NEW.org_id);
 ELSE
  SELECT * INTO s FROM ipsec_runtime_state WHERE connection_id=OLD.id;
  IF NEW.id<>OLD.id OR NEW.org_id<>OLD.org_id OR NEW.historical_site_id<>OLD.historical_site_id OR NEW.historical_gateway_node_id<>OLD.historical_gateway_node_id OR NEW.created_at<>OLD.created_at THEN RAISE EXCEPTION 'IPsec connection identity immutable' USING ERRCODE='23514'; END IF;
  IF OLD.desired_intent='deleted' THEN
   IF OLD.finalized_at IS NOT NULL OR NEW.desired_intent<>'deleted' OR NEW.desired_revision<>OLD.desired_revision OR NEW.finalized_at IS NULL OR NEW.name<>OLD.name OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at THEN RAISE EXCEPTION 'IPsec deleted intent terminal' USING ERRCODE='23514'; END IF;
  ELSIF OLD.desired_revision=9223372036854775807 OR NEW.desired_revision<>OLD.desired_revision+1 OR (NEW.desired_intent=OLD.desired_intent AND NOT(NEW.desired_intent='disabled' AND NEW.name<>OLD.name AND coalesce(s.last_potentially_delivered_revision,0)=0)) THEN RAISE EXCEPTION 'IPsec intent transition invalid' USING ERRCODE='23514'; END IF;
  IF NEW.finalized_at IS NOT NULL AND coalesce(s.last_potentially_delivered_revision,0)>coalesce(s.last_cleaned_delivery_revision,0) THEN RAISE EXCEPTION 'IPsec cleanup proof required' USING ERRCODE='23514'; END IF;
 END IF;
 IF NEW.desired_intent='enabled' THEN
  PERFORM ipsec_provider_lock_org(NEW.org_id);
  IF NEW.provider_profile IS NULL OR s.current_cleanup_id IS NOT NULL OR NOT EXISTS(SELECT 1 FROM ipsec_provider_bindings WHERE connection_id=NEW.id AND configuration_sealed AND NOT withdrawal_started)
  OR NOT EXISTS(SELECT 1 FROM organizations WHERE id=NEW.org_id AND deleted_at IS NULL)
  OR NOT EXISTS(SELECT 1 FROM ipsec_org_settings WHERE org_id=NEW.org_id AND enabled)
  OR NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.gateway_node_id AND org_id=NEW.org_id AND site_id=NEW.site_id AND status='active' AND revoked_at IS NULL AND cert_serial<>'' AND capabilities->>'ipsec_config_version'='1' AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp()) THEN RAISE EXCEPTION 'IPsec enable prerequisites unavailable' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_ineligible'; END IF;
 END IF;
 NEW.updated_at:=now();RETURN NEW;
END; $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION ipsec_org_soft_delete_guard() RETURNS trigger AS $$
BEGIN
 IF NEW.deleted_at IS NOT NULL AND (EXISTS(SELECT 1 FROM ipsec_connections WHERE org_id=OLD.id AND finalized_at IS NULL) OR EXISTS(SELECT 1 FROM ipsec_retained_guards WHERE org_id=OLD.id)) THEN RAISE EXCEPTION 'IPsec ownership prevents organization deletion' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION ipsec_setting_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'IPsec setting erasure unavailable' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.revision <> 1 THEN
            RAISE EXCEPTION 'IPsec initial revision invalid' USING ERRCODE = '23514';
        END IF;
    ELSE
        IF NEW.org_id IS DISTINCT FROM OLD.org_id OR NEW.created_at IS DISTINCT FROM OLD.created_at
           OR OLD.revision = 9223372036854775807 OR NEW.revision <> OLD.revision + 1 THEN
            RAISE EXCEPTION 'IPsec setting update invalid' USING ERRCODE = '23514';
        END IF;
    END IF;
    PERFORM ipsec_require_live_org(NEW.org_id);
    IF NOT NEW.enabled AND (EXISTS(SELECT 1 FROM ipsec_connections WHERE org_id=NEW.org_id AND desired_intent='enabled') OR EXISTS(SELECT 1 FROM ipsec_runtime_state WHERE org_id=NEW.org_id AND current_cleanup_id IS NOT NULL) OR EXISTS(SELECT 1 FROM ipsec_retained_guards WHERE org_id=NEW.org_id)) THEN RAISE EXCEPTION 'IPsec obligations prevent opt out' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_obligation'; END IF;
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION ipsec_child_guard() RETURNS trigger AS $$
DECLARE v_id uuid; v_intent text; v_finalized timestamptz;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'IPsec tunnel mutation unavailable' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'DELETE' THEN v_id := OLD.connection_id;
    ELSE v_id := NEW.connection_id;
    END IF;
    SELECT desired_intent,finalized_at INTO v_intent,v_finalized FROM ipsec_connections WHERE id = v_id FOR UPDATE;
    IF NOT FOUND OR (TG_OP = 'INSERT' AND v_intent <> 'disabled')
                 OR (TG_OP = 'DELETE' AND v_finalized IS NULL) THEN
        RAISE EXCEPTION 'IPsec tunnel lifecycle invalid' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION ipsec_verify_connection_children() RETURNS trigger AS $$
DECLARE v_id uuid; v_intent text; v_finalized timestamptz; v_tunnels bigint; v_secrets bigint;
BEGIN
    IF TG_TABLE_NAME = 'ipsec_connections' THEN v_id := NEW.id;
    ELSIF TG_OP = 'DELETE' THEN v_id := OLD.connection_id;
    ELSE v_id := NEW.connection_id;
    END IF;
    SELECT desired_intent,finalized_at INTO v_intent,v_finalized FROM ipsec_connections WHERE id = v_id FOR UPDATE;
    SELECT count(*) INTO v_tunnels FROM ipsec_tunnels WHERE connection_id = v_id;
    SELECT count(*) INTO v_secrets FROM ipsec_tunnel_secrets WHERE connection_id = v_id;
    IF v_intent IS NULL OR (v_finalized IS NULL AND (v_tunnels <> 2 OR v_secrets <> 2))
       OR (v_finalized IS NOT NULL AND (v_tunnels <> 0 OR v_secrets <> 0)) THEN
        RAISE EXCEPTION 'IPsec connection children incomplete' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

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
 ELSIF TG_TABLE_NAME='ipsec_aws_remote_prefixes' THEN PERFORM ipsec_provider_check_range(o,NEW.cidr,'remote');
 END IF;
 RETURN NEW;
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
  OR (finalized IS NULL AND (withdrawn OR configs<>1 OR tunnels<>2 OR locals NOT BETWEEN 1 AND 64 OR remotes NOT BETWEEN 1 AND 64))
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

CREATE OR REPLACE FUNCTION ipsec_provider_check_range(p_org uuid,p_cidr cidr,p_kind text) RETURNS void AS $$
BEGIN
 IF p_kind<>'route' AND (
  EXISTS(SELECT 1 FROM site_subnets ss JOIN sites s ON s.id=ss.site_id WHERE s.org_id=p_org AND ss.status='approved' AND ss.cidr && p_cidr)
  OR EXISTS(SELECT 1 FROM organizations WHERE id=p_org AND pool_cidr::cidr && p_cidr)
  OR EXISTS(SELECT 1 FROM k8s_clusters WHERE org_id=p_org AND vip_range && p_cidr)
 ) THEN RAISE EXCEPTION 'IPsec range conflict' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict'; END IF;
 IF EXISTS(SELECT 1 FROM ipsec_retained_remote_prefixes WHERE org_id=p_org AND cidr && p_cidr)
  OR EXISTS(SELECT 1 FROM ipsec_aws_remote_prefixes WHERE org_id=p_org AND cidr && p_cidr)
  OR (p_kind<>'inside' AND EXISTS(SELECT 1 FROM ipsec_aws_tunnel_configs WHERE org_id=p_org AND inside_cidr && p_cidr))
  OR (p_kind<>'underlay' AND (
   EXISTS(SELECT 1 FROM ipsec_aws_static_configs WHERE org_id=p_org AND customer_outside_ipv4::cidr && p_cidr)
   OR EXISTS(SELECT 1 FROM ipsec_aws_tunnel_configs WHERE org_id=p_org AND aws_outside_ipv4::cidr && p_cidr)
  )) THEN RAISE EXCEPTION 'IPsec reservation conflict' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict'; END IF;
END;
$$ LANGUAGE plpgsql;

-- Shared policy inputs used by runtime grant compilation serialize with leases.
-- No WG acceptance rule changes: these mirrors only acquire/version ownership.
CREATE FUNCTION ipsec_runtime_policy_mirror() RETURNS trigger AS $$
DECLARE a uuid;b uuid;
BEGIN
 IF TG_OP='DELETE' THEN a:=OLD.org_id;
 ELSIF TG_OP='INSERT' THEN a:=NEW.org_id;
 ELSE a:=OLD.org_id;b:=NEW.org_id;END IF;
 IF b IS NOT NULL AND a<>b THEN
  IF a<b THEN PERFORM ipsec_provider_lock_org(a);PERFORM ipsec_provider_lock_org(b);
  ELSE PERFORM ipsec_provider_lock_org(b);PERFORM ipsec_provider_lock_org(a);END IF;
 ELSE PERFORM ipsec_provider_lock_org(a);END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_runtime_policy_mirror BEFORE INSERT OR UPDATE OR DELETE ON policy_rules FOR EACH ROW EXECUTE FUNCTION ipsec_runtime_policy_mirror();
CREATE TRIGGER ipsec_runtime_policy_mirror BEFORE INSERT OR UPDATE OR DELETE ON resources FOR EACH ROW EXECUTE FUNCTION ipsec_runtime_policy_mirror();
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['ipsec_runtime_deliveries','ipsec_runtime_acknowledgements','ipsec_retained_guards','ipsec_retained_local_prefixes','ipsec_retained_remote_prefixes'] LOOP
  EXECUTE format('CREATE TRIGGER ipsec_runtime_immutable BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION ipsec_runtime_immutable()',t);
 END LOOP;
 FOREACH t IN ARRAY ARRAY['ipsec_runtime_state','ipsec_runtime_deliveries','ipsec_runtime_acknowledgements','ipsec_retained_guards','ipsec_retained_local_prefixes','ipsec_retained_remote_prefixes'] LOOP
  EXECUTE format('CREATE TRIGGER ipsec_runtime_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION ipsec_refuse_truncate()',t);
 END LOOP;
END $$;
