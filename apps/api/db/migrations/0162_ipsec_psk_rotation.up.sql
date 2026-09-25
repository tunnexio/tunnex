-- Maintenance-only replacement; history contains no credentials.
DO $$ DECLARE n text; BEGIN SELECT conname INTO n FROM pg_constraint WHERE conrelid='ipsec_tunnel_secrets'::regclass AND contype='f' AND confrelid='ipsec_tunnels'::regclass; EXECUTE format('ALTER TABLE ipsec_tunnel_secrets DROP CONSTRAINT %I',n); END $$;
ALTER TABLE ipsec_tunnel_secrets ADD CONSTRAINT ipsec_secret_revision_fk FOREIGN KEY(tunnel_id,org_id,connection_id,secret_revision) REFERENCES ipsec_tunnels(id,org_id,connection_id,secret_revision) ON DELETE RESTRICT DEFERRABLE INITIALLY IMMEDIATE;
-- Actor/audit UUIDs are historical evidence, not live FKs: account deletion and
-- configured audit retention must remain possible after this transaction.
CREATE TABLE ipsec_psk_rotations (
 connection_id uuid NOT NULL,org_id uuid NOT NULL,desired_revision bigint NOT NULL,
 previous_revision bigint NOT NULL,actor_id uuid NOT NULL,
 audit_id uuid NOT NULL,tunnel_ids uuid[] NOT NULL,
 previous_secret_revisions bigint[] NOT NULL DEFAULT '{}',transaction_id bigint NOT NULL DEFAULT txid_current(),
 PRIMARY KEY(connection_id,desired_revision),UNIQUE(connection_id,transaction_id),
 FOREIGN KEY(connection_id,org_id) REFERENCES ipsec_connections(id,org_id),
 CHECK(cardinality(tunnel_ids) BETWEEN 1 AND 2)
);
CREATE INDEX ipsec_rotation_audit_transaction_idx ON ipsec_psk_rotations(audit_id,transaction_id);
CREATE FUNCTION ipsec_rotation_before() RETURNS trigger AS $$
DECLARE c ipsec_connections;s ipsec_runtime_state;t uuid;r bigint;
BEGIN
 PERFORM ipsec_provider_lock_org(NEW.org_id);
 SELECT * INTO c FROM ipsec_connections WHERE id=NEW.connection_id AND org_id=NEW.org_id FOR UPDATE;
 SELECT * INTO s FROM ipsec_runtime_state WHERE connection_id=NEW.connection_id FOR UPDATE;
 IF c.id IS NULL OR c.desired_intent<>'disabled' OR c.finalized_at IS NOT NULL OR c.provider_profile IS NULL OR c.desired_revision=9223372036854775807 OR NEW.previous_revision<>c.desired_revision OR NEW.desired_revision<>c.desired_revision+1 OR s.current_cleanup_id IS NOT NULL OR coalesce(s.last_cleaned_delivery_revision,0)<>coalesce(s.last_potentially_delivered_revision,0)
 OR (s.last_potentially_delivered_revision IS NOT NULL AND NOT EXISTS(SELECT 1 FROM ipsec_retained_guards g JOIN ipsec_runtime_deliveries d ON d.id=g.cleanup_delivery_id WHERE g.connection_id=c.id AND g.org_id=c.org_id AND d.covers_delivery_revision=s.last_potentially_delivered_revision))
 OR NOT EXISTS(SELECT 1 FROM organizations WHERE id=c.org_id AND deleted_at IS NULL)
 OR NOT EXISTS(SELECT 1 FROM audit_logs WHERE id=NEW.audit_id AND org_id=NEW.org_id AND actor_user_id=NEW.actor_id AND action='ipsec.psk_rotated' AND target_type='ipsec_connection' AND target_id=c.id::text AND metadata->>'revision'=NEW.desired_revision::text)
 THEN RAISE EXCEPTION 'IPsec rotation state invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_rotation_binding';END IF;
 IF cardinality(NEW.tunnel_ids) NOT BETWEEN 1 AND 2 OR cardinality(NEW.tunnel_ids)<>(SELECT count(DISTINCT x) FROM unnest(NEW.tunnel_ids)x) THEN RAISE EXCEPTION 'IPsec rotation tunnels invalid' USING ERRCODE='23514';END IF;
 NEW.previous_secret_revisions:='{}';NEW.transaction_id:=txid_current();
 FOREACH t IN ARRAY NEW.tunnel_ids LOOP
  SELECT secret_revision INTO r FROM ipsec_tunnels WHERE id=t AND connection_id=c.id AND org_id=c.org_id FOR UPDATE;
  IF r IS NULL OR r=9223372036854775807 THEN RAISE EXCEPTION 'IPsec rotation tunnel invalid' USING ERRCODE='23514';END IF;
  NEW.previous_secret_revisions:=array_append(NEW.previous_secret_revisions,r);
 END LOOP;
 RETURN NEW;
END;$$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_rotation_before BEFORE INSERT ON ipsec_psk_rotations FOR EACH ROW EXECUTE FUNCTION ipsec_rotation_before();
CREATE TRIGGER ipsec_rotation_immutable BEFORE UPDATE OR DELETE ON ipsec_psk_rotations FOR EACH ROW EXECUTE FUNCTION ipsec_runtime_immutable();
CREATE TRIGGER ipsec_rotation_no_truncate BEFORE TRUNCATE ON ipsec_psk_rotations FOR EACH STATEMENT EXECUTE FUNCTION ipsec_refuse_truncate();
CREATE FUNCTION ipsec_rotation_parent_allowed(o ipsec_connections,n ipsec_connections) RETURNS boolean AS $$
 SELECT o.desired_intent='disabled' AND n.desired_intent='disabled' AND (to_jsonb(o)-'desired_revision'-'updated_at')=(to_jsonb(n)-'desired_revision'-'updated_at') AND EXISTS(SELECT 1 FROM ipsec_psk_rotations r WHERE r.connection_id=o.id AND r.org_id=o.org_id AND r.previous_revision=o.desired_revision AND r.desired_revision=n.desired_revision AND r.transaction_id=txid_current());
$$ LANGUAGE sql;
CREATE FUNCTION ipsec_rotation_child_allowed(tbl text,o jsonb,n jsonb) RETURNS boolean AS $$
DECLARE r ipsec_psk_rotations;tid uuid;i int;
BEGIN
 tid:=CASE WHEN tbl='ipsec_tunnels' THEN (o->>'id')::uuid ELSE (o->>'tunnel_id')::uuid END;
 SELECT * INTO r FROM ipsec_psk_rotations WHERE connection_id=(o->>'connection_id')::uuid AND org_id=(o->>'org_id')::uuid AND transaction_id=txid_current();
 i:=array_position(r.tunnel_ids,tid);
 IF i IS NULL OR (o->>'secret_revision')::bigint<>r.previous_secret_revisions[i] OR (n->>'secret_revision')::bigint<>r.previous_secret_revisions[i]+1 THEN RETURN false;END IF;
 IF tbl='ipsec_tunnels' THEN RETURN (o-'secret_revision')=(n-'secret_revision');END IF;
 RETURN (o-'secret_revision'-'sealed_psk')=(n-'secret_revision'-'sealed_psk') AND o->>'sealed_psk'<>n->>'sealed_psk';
END;$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION ipsec_connection_guard() RETURNS trigger AS $$
DECLARE s ipsec_runtime_state;
BEGIN
 IF TG_OP='UPDATE' AND EXISTS(SELECT 1 FROM ipsec_psk_rotations WHERE connection_id=OLD.id AND transaction_id=txid_current() AND desired_revision=OLD.desired_revision) THEN RAISE EXCEPTION 'IPsec rotation parent already advanced' USING ERRCODE='23514',CONSTRAINT='ipsec_rotation_binding'; END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'IPsec connection erasure unavailable' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.desired_intent<>'disabled' OR NEW.desired_revision<>1 THEN RAISE EXCEPTION 'IPsec initial state invalid' USING ERRCODE='23514'; END IF;
  PERFORM ipsec_require_live_org(NEW.org_id);
 ELSE
  SELECT * INTO s FROM ipsec_runtime_state WHERE connection_id=OLD.id;
  IF NEW.id<>OLD.id OR NEW.org_id<>OLD.org_id OR NEW.historical_site_id<>OLD.historical_site_id OR NEW.historical_gateway_node_id<>OLD.historical_gateway_node_id OR NEW.created_at<>OLD.created_at THEN RAISE EXCEPTION 'IPsec connection identity immutable' USING ERRCODE='23514'; END IF;
  IF OLD.desired_intent='deleted' THEN
   IF OLD.finalized_at IS NOT NULL OR NEW.desired_intent<>'deleted' OR NEW.desired_revision<>OLD.desired_revision OR NEW.finalized_at IS NULL OR NEW.name<>OLD.name OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at THEN RAISE EXCEPTION 'IPsec deleted intent terminal' USING ERRCODE='23514'; END IF;
  ELSIF OLD.desired_revision=9223372036854775807 OR NEW.desired_revision<>OLD.desired_revision+1 OR (NEW.desired_intent=OLD.desired_intent AND NOT(NEW.desired_intent='disabled' AND NEW.name<>OLD.name AND coalesce(s.last_potentially_delivered_revision,0)=0) AND NOT ipsec_rotation_parent_allowed(OLD,NEW)) THEN RAISE EXCEPTION 'IPsec intent transition invalid' USING ERRCODE='23514'; END IF;
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
CREATE OR REPLACE FUNCTION ipsec_child_guard() RETURNS trigger AS $$
DECLARE v_id uuid; v_intent text; v_finalized timestamptz;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NOT ipsec_rotation_child_allowed(TG_TABLE_NAME,to_jsonb(OLD),to_jsonb(NEW)) THEN RAISE EXCEPTION 'IPsec tunnel mutation unavailable' USING ERRCODE='23514',CONSTRAINT='ipsec_rotation_binding'; END IF; RETURN NEW;
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
CREATE FUNCTION ipsec_rotation_complete() RETURNS trigger AS $$
DECLARE r ipsec_psk_rotations;c ipsec_connections;i int;v_id uuid;
BEGIN
 IF TG_TABLE_NAME='ipsec_connections' THEN v_id:=NEW.id;ELSE v_id:=NEW.connection_id;END IF;
 SELECT * INTO r FROM ipsec_psk_rotations WHERE connection_id=v_id AND transaction_id=txid_current();
 IF NOT FOUND THEN RETURN NULL;END IF;
 SELECT * INTO c FROM ipsec_connections WHERE id=r.connection_id;
 IF c.desired_revision<>r.desired_revision OR c.desired_intent<>'disabled' OR NOT EXISTS(SELECT 1 FROM audit_logs WHERE id=r.audit_id AND org_id=r.org_id AND actor_user_id=r.actor_id AND action='ipsec.psk_rotated' AND target_type='ipsec_connection' AND target_id=r.connection_id::text AND metadata->>'revision'=r.desired_revision::text) THEN RAISE EXCEPTION 'IPsec rotation incomplete' USING ERRCODE='23514';END IF;
 FOR i IN 1..cardinality(r.tunnel_ids) LOOP
  IF NOT EXISTS(SELECT 1 FROM ipsec_tunnels t JOIN ipsec_tunnel_secrets s ON s.tunnel_id=t.id AND s.org_id=t.org_id AND s.connection_id=t.connection_id AND s.secret_revision=t.secret_revision WHERE t.id=r.tunnel_ids[i] AND t.connection_id=r.connection_id AND t.secret_revision=r.previous_secret_revisions[i]+1) THEN RAISE EXCEPTION 'IPsec rotation incomplete' USING ERRCODE='23514';END IF;
 END LOOP;
 RETURN NULL;
END;$$ LANGUAGE plpgsql;
CREATE CONSTRAINT TRIGGER ipsec_rotation_complete AFTER INSERT ON ipsec_psk_rotations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ipsec_rotation_complete();

-- Standard schema convention; lifecycle guards already assign the same now().
CREATE TRIGGER set_updated_at BEFORE UPDATE ON ipsec_connections FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER set_updated_at BEFORE UPDATE ON ipsec_org_settings FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE CONSTRAINT TRIGGER ipsec_rotation_parent_complete AFTER UPDATE ON ipsec_connections DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ipsec_rotation_complete();
CREATE CONSTRAINT TRIGGER ipsec_rotation_tunnel_complete AFTER UPDATE ON ipsec_tunnels DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ipsec_rotation_complete();
CREATE CONSTRAINT TRIGGER ipsec_rotation_secret_complete AFTER UPDATE ON ipsec_tunnel_secrets DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ipsec_rotation_complete();
CREATE FUNCTION ipsec_rotation_audit_guard() RETURNS trigger AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM ipsec_psk_rotations WHERE audit_id=OLD.id AND transaction_id=txid_current()) THEN RAISE EXCEPTION 'IPsec rotation audit required until commit' USING ERRCODE='23514';END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END;$$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_rotation_audit_guard BEFORE UPDATE OR DELETE ON audit_logs FOR EACH ROW EXECUTE FUNCTION ipsec_rotation_audit_guard();
