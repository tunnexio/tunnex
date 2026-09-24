DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM ipsec_runtime_state) OR EXISTS(SELECT 1 FROM ipsec_runtime_deliveries) OR EXISTS(SELECT 1 FROM ipsec_runtime_acknowledgements) OR EXISTS(SELECT 1 FROM ipsec_retained_guards) OR EXISTS(SELECT 1 FROM ipsec_connections WHERE desired_intent='enabled' OR (desired_intent='deleted' AND finalized_at IS NULL)) THEN RAISE EXCEPTION 'IPsec runtime history prevents rollback'; END IF;
END $$;
DROP INDEX ipsec_runtime_pending_node_idx;
DROP TRIGGER ipsec_runtime_coherence ON ipsec_connections;
DROP TRIGGER ipsec_runtime_connection_state ON ipsec_connections;
DROP TRIGGER ipsec_runtime_policy_mirror ON policy_rules;
DROP TRIGGER ipsec_runtime_policy_mirror ON resources;
DROP TABLE ipsec_retained_local_prefixes,ipsec_retained_remote_prefixes,ipsec_retained_guards;
DROP TABLE ipsec_runtime_acknowledgements;
ALTER TABLE ipsec_runtime_state DROP CONSTRAINT ipsec_runtime_current_cleanup_fk;
DROP TABLE ipsec_runtime_deliveries,ipsec_runtime_state;
DROP FUNCTION ipsec_runtime_coherence(),ipsec_runtime_connection_state(),ipsec_runtime_state_guard(),ipsec_runtime_delivery_guard(),ipsec_runtime_delivery_checkpoint(),ipsec_runtime_ack_guard(),ipsec_runtime_ack_checkpoint(),ipsec_runtime_retained_guard(),ipsec_runtime_immutable(),ipsec_runtime_policy_mirror();
ALTER TABLE ipsec_connections DROP CONSTRAINT ipsec_connections_desired_intent_check;
ALTER TABLE ipsec_connections DROP CONSTRAINT ipsec_connections_check;
ALTER TABLE ipsec_connections ADD CONSTRAINT ipsec_connections_desired_intent_check CHECK(desired_intent IN('disabled','deleted'));
ALTER TABLE ipsec_connections ADD CONSTRAINT ipsec_connections_check CHECK((desired_intent='disabled' AND site_id IS NOT NULL AND gateway_node_id IS NOT NULL AND site_id=historical_site_id AND gateway_node_id=historical_gateway_node_id AND deleted_at IS NULL AND finalized_at IS NULL) OR (desired_intent='deleted' AND site_id IS NULL AND gateway_node_id IS NULL AND deleted_at IS NOT NULL AND finalized_at IS NOT NULL));
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
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION ipsec_connection_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'IPsec connection erasure unavailable' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.desired_intent <> 'disabled' OR NEW.desired_revision <> 1 THEN
            RAISE EXCEPTION 'IPsec initial state invalid' USING ERRCODE = '23514';
        END IF;
        PERFORM ipsec_require_live_org(NEW.org_id);
    ELSE
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.org_id IS DISTINCT FROM OLD.org_id
           OR NEW.historical_site_id IS DISTINCT FROM OLD.historical_site_id
           OR NEW.historical_gateway_node_id IS DISTINCT FROM OLD.historical_gateway_node_id
           OR NEW.created_at IS DISTINCT FROM OLD.created_at
           OR OLD.desired_intent = 'deleted'
           OR OLD.desired_revision = 9223372036854775807
           OR NEW.desired_revision <> OLD.desired_revision + 1 THEN
            RAISE EXCEPTION 'IPsec connection update invalid' USING ERRCODE = '23514';
        END IF;
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION ipsec_org_soft_delete_guard() RETURNS trigger AS $$
BEGIN
    IF NEW.deleted_at IS NOT NULL AND EXISTS (
        SELECT 1 FROM ipsec_connections WHERE org_id = OLD.id AND desired_intent <> 'deleted'
    ) THEN
        RAISE EXCEPTION 'IPsec connections prevent organization deletion' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION ipsec_child_guard() RETURNS trigger AS $$
DECLARE v_id uuid; v_intent text;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'IPsec tunnel mutation unavailable' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'DELETE' THEN v_id := OLD.connection_id;
    ELSE v_id := NEW.connection_id;
    END IF;
    SELECT desired_intent INTO v_intent FROM ipsec_connections WHERE id = v_id FOR UPDATE;
    IF NOT FOUND OR (TG_OP = 'INSERT' AND v_intent <> 'disabled')
                 OR (TG_OP = 'DELETE' AND v_intent <> 'deleted') THEN
        RAISE EXCEPTION 'IPsec tunnel lifecycle invalid' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION ipsec_verify_connection_children() RETURNS trigger AS $$
DECLARE v_id uuid; v_intent text; v_tunnels bigint; v_secrets bigint;
BEGIN
    IF TG_TABLE_NAME = 'ipsec_connections' THEN v_id := NEW.id;
    ELSIF TG_OP = 'DELETE' THEN v_id := OLD.connection_id;
    ELSE v_id := NEW.connection_id;
    END IF;
    SELECT desired_intent INTO v_intent FROM ipsec_connections WHERE id = v_id FOR UPDATE;
    SELECT count(*) INTO v_tunnels FROM ipsec_tunnels WHERE connection_id = v_id;
    SELECT count(*) INTO v_secrets FROM ipsec_tunnel_secrets WHERE connection_id = v_id;
    IF v_intent IS NULL OR (v_intent = 'disabled' AND (v_tunnels <> 2 OR v_secrets <> 2))
       OR (v_intent = 'deleted' AND (v_tunnels <> 0 OR v_secrets <> 0)) THEN
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
DECLARE c uuid; profile text; intent text; withdrawn boolean; bindings bigint; configs bigint; tunnels bigint; locals bigint; remotes bigint;
BEGIN
 IF TG_TABLE_NAME='ipsec_connections' THEN c:=NEW.id;
 ELSIF TG_OP='DELETE' THEN c:=OLD.connection_id; ELSE c:=NEW.connection_id; END IF;
 SELECT provider_profile,desired_intent INTO profile,intent FROM ipsec_connections WHERE id=c FOR UPDATE;
 SELECT count(*),bool_or(withdrawal_started) INTO bindings,withdrawn FROM ipsec_provider_bindings WHERE connection_id=c;
 SELECT count(*) INTO configs FROM ipsec_aws_static_configs WHERE connection_id=c;
 SELECT count(*) INTO tunnels FROM ipsec_aws_tunnel_configs WHERE connection_id=c;
 SELECT count(*) INTO locals FROM ipsec_aws_local_prefixes WHERE connection_id=c;
 SELECT count(*) INTO remotes FROM ipsec_aws_remote_prefixes WHERE connection_id=c;
 IF (profile IS NULL AND bindings<>0) OR (profile IS NOT NULL AND (bindings<>1
  OR (intent='disabled' AND (withdrawn OR configs<>1 OR tunnels<>2 OR locals NOT BETWEEN 1 AND 64 OR remotes NOT BETWEEN 1 AND 64))
  OR (intent='deleted' AND (NOT withdrawn OR configs<>0 OR tunnels<>0 OR locals<>0 OR remotes<>0)))) THEN
  RAISE EXCEPTION 'IPsec provider configuration incomplete' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_incomplete';
 END IF;
 -- Intra-local overlap matters even if a historic WG-only DB has approved
 -- overlapping rows. It does not change that existing WG-only acceptance.
 IF EXISTS(SELECT 1 FROM ipsec_aws_local_prefixes a JOIN ipsec_aws_local_prefixes b ON a.connection_id=b.connection_id AND a.subnet_id<b.subnet_id WHERE a.connection_id=c AND a.cidr && b.cidr) THEN RAISE EXCEPTION 'IPsec local prefix conflict' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict'; END IF;
 IF profile IS NOT NULL AND intent='disabled' THEN UPDATE ipsec_provider_bindings SET configuration_sealed=true WHERE connection_id=c AND NOT configuration_sealed; END IF;
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
 IF EXISTS(SELECT 1 FROM ipsec_aws_remote_prefixes WHERE org_id=p_org AND cidr && p_cidr)
  OR (p_kind<>'inside' AND EXISTS(SELECT 1 FROM ipsec_aws_tunnel_configs WHERE org_id=p_org AND inside_cidr && p_cidr))
  OR (p_kind<>'underlay' AND (
   EXISTS(SELECT 1 FROM ipsec_aws_static_configs WHERE org_id=p_org AND customer_outside_ipv4::cidr && p_cidr)
   OR EXISTS(SELECT 1 FROM ipsec_aws_tunnel_configs WHERE org_id=p_org AND aws_outside_ipv4::cidr && p_cidr)
  )) THEN RAISE EXCEPTION 'IPsec reservation conflict' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_conflict'; END IF;
END;
$$ LANGUAGE plpgsql;
