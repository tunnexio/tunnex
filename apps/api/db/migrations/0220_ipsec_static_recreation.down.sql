-- Rollback may not discard successor authority while immutable bindings exist.
DO $$ BEGIN IF EXISTS(SELECT 1 FROM ipsec_static_recreations) THEN RAISE EXCEPTION 'IPsec static recreation history prevents rollback'; END IF; END $$;
DROP TRIGGER ipsec_static_recreation_enable ON ipsec_connections;
DROP FUNCTION ipsec_static_recreation_enable();
DROP TRIGGER ipsec_static_recreation_delivery ON ipsec_runtime_deliveries;
DROP FUNCTION ipsec_static_recreation_delivery();
DROP FUNCTION ipsec_static_recreation_predecessors(uuid,uuid);
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


DROP FUNCTION ipsec_provider_check_recreated_remote(uuid,cidr,uuid);
DROP TABLE ipsec_static_recreations;
DROP FUNCTION ipsec_static_recreation_domain();
DROP FUNCTION ipsec_static_recreation_binding();
