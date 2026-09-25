DO $$ BEGIN IF EXISTS(SELECT 1 FROM ipsec_psk_rotations) OR EXISTS(SELECT 1 FROM ipsec_tunnels WHERE secret_revision<>1) THEN RAISE EXCEPTION 'IPsec rotation history prevents downgrade';END IF;END $$;
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
DROP TRIGGER ipsec_rotation_parent_complete ON ipsec_connections;
DROP TRIGGER ipsec_rotation_tunnel_complete ON ipsec_tunnels;
DROP TRIGGER ipsec_rotation_secret_complete ON ipsec_tunnel_secrets;
DROP TRIGGER ipsec_rotation_audit_guard ON audit_logs;
DROP FUNCTION ipsec_rotation_audit_guard();
DROP TABLE ipsec_psk_rotations;
DROP FUNCTION ipsec_rotation_complete();
DROP FUNCTION ipsec_rotation_before();
DROP FUNCTION ipsec_rotation_parent_allowed(ipsec_connections,ipsec_connections);
DROP FUNCTION ipsec_rotation_child_allowed(text,jsonb,jsonb);
ALTER TABLE ipsec_tunnel_secrets ALTER CONSTRAINT ipsec_secret_revision_fk NOT DEFERRABLE;
DROP TRIGGER set_updated_at ON ipsec_connections;
DROP TRIGGER set_updated_at ON ipsec_org_settings;
