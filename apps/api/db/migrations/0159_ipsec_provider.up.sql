-- Profile bounds mirror the reviewed pure validator; not Internet reachability.
CREATE FUNCTION ipsec_provider_public_ipv4(p inet) RETURNS boolean AS $$
 SELECT family(p)=4 AND masklen(p)=32 AND NOT EXISTS(
  SELECT 1 FROM unnest(ARRAY['0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.0.0.0/24','192.0.2.0/24','192.31.196.0/24','192.52.193.0/24','192.88.99.0/24','192.168.0.0/16','192.175.48.0/24','198.18.0.0/15','198.51.100.0/24','203.0.113.0/24','224.0.0.0/4','240.0.0.0/4']::cidr[]) s WHERE p <<= s);
$$ LANGUAGE sql IMMUTABLE STRICT;
CREATE FUNCTION ipsec_provider_routed_ipv4(p cidr) RETURNS boolean AS $$
 SELECT family(p)=4 AND masklen(p)>0 AND NOT EXISTS(
  SELECT 1 FROM unnest(ARRAY['0.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','192.0.0.0/24','192.0.2.0/24','192.31.196.0/24','192.52.193.0/24','192.88.99.0/24','192.175.48.0/24','198.18.0.0/15','198.51.100.0/24','203.0.113.0/24','224.0.0.0/4','240.0.0.0/4']::cidr[]) s WHERE p && s);
$$ LANGUAGE sql IMMUTABLE STRICT;

-- Immutable never-delivered provider configuration. No runtime or routes.
-- The parent marker prevents later attachment to a legacy identity; terminal
-- withdrawal_started prevents DELETE/reINSERT from becoming an edit bypass.
ALTER TABLE ipsec_connections ADD COLUMN provider_profile text
    CHECK(provider_profile IS NULL OR provider_profile='aws-static-ipv4-v1');
ALTER TABLE ipsec_connections ADD CONSTRAINT ipsec_provider_parent_assignment_key
    UNIQUE(id,org_id,site_id,gateway_node_id);
ALTER TABLE ipsec_tunnels ADD CONSTRAINT ipsec_provider_tunnel_owner_key UNIQUE(id,org_id,connection_id,slot);
ALTER TABLE site_subnets ADD CONSTRAINT ipsec_provider_subnet_owner_key UNIQUE(id,site_id,cidr,status);

CREATE TABLE ipsec_provider_bindings (
 connection_id uuid PRIMARY KEY,
 org_id uuid NOT NULL,
 profile_id text NOT NULL DEFAULT 'aws-static-ipv4-v1' CHECK(profile_id='aws-static-ipv4-v1'),
 configuration_revision bigint NOT NULL DEFAULT 1 CHECK(configuration_revision=1),
 withdrawal_started boolean NOT NULL DEFAULT false,
 configuration_sealed boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(connection_id,org_id),
 FOREIGN KEY(connection_id,org_id) REFERENCES ipsec_connections(id,org_id) ON DELETE RESTRICT
);
CREATE TABLE ipsec_aws_static_configs (
 connection_id uuid PRIMARY KEY,
 org_id uuid NOT NULL,
 site_id uuid NOT NULL,
 gateway_node_id uuid NOT NULL,
 customer_outside_ipv4 inet NOT NULL CHECK(ipsec_provider_public_ipv4(customer_outside_ipv4)),
 UNIQUE(connection_id,org_id,site_id),
 UNIQUE(connection_id,org_id,gateway_node_id),
 FOREIGN KEY(connection_id,org_id) REFERENCES ipsec_provider_bindings(connection_id,org_id) ON DELETE RESTRICT,
 FOREIGN KEY(connection_id,org_id,site_id,gateway_node_id) REFERENCES ipsec_connections(id,org_id,site_id,gateway_node_id) ON DELETE RESTRICT
);
CREATE TABLE ipsec_aws_tunnel_configs (
 tunnel_id uuid PRIMARY KEY,
 org_id uuid NOT NULL,
 connection_id uuid NOT NULL,
 slot smallint NOT NULL CHECK(slot IN(1,2)),
 gateway_node_id uuid NOT NULL,
 aws_outside_ipv4 inet NOT NULL CHECK(ipsec_provider_public_ipv4(aws_outside_ipv4)),
 inside_cidr cidr NOT NULL CHECK(family(inside_cidr)=4 AND masklen(inside_cidr)=30 AND inside_cidr <<= '169.254.0.0/16'::cidr),
 customer_inside_ipv4 inet NOT NULL CHECK(family(customer_inside_ipv4)=4 AND masklen(customer_inside_ipv4)=32),
 aws_inside_ipv4 inet NOT NULL CHECK(family(aws_inside_ipv4)=4 AND masklen(aws_inside_ipv4)=32),
 UNIQUE(connection_id,slot),
 UNIQUE(gateway_node_id,inside_cidr),
 UNIQUE(gateway_node_id,aws_outside_ipv4),
 CHECK(customer_inside_ipv4<>aws_inside_ipv4),
 CHECK(customer_inside_ipv4 IN(set_masklen(network(inside_cidr)+1,32),set_masklen(network(inside_cidr)+2,32))),
 CHECK(aws_inside_ipv4 IN(set_masklen(network(inside_cidr)+1,32),set_masklen(network(inside_cidr)+2,32))),
 CHECK(inside_cidr NOT IN('169.254.0.0/30','169.254.1.0/30','169.254.2.0/30','169.254.3.0/30','169.254.4.0/30','169.254.5.0/30','169.254.169.252/30')),
 FOREIGN KEY(tunnel_id,org_id,connection_id,slot) REFERENCES ipsec_tunnels(id,org_id,connection_id,slot) ON DELETE RESTRICT,
 FOREIGN KEY(connection_id,org_id,gateway_node_id) REFERENCES ipsec_aws_static_configs(connection_id,org_id,gateway_node_id) ON DELETE RESTRICT
);
CREATE TABLE ipsec_aws_local_prefixes (
 connection_id uuid NOT NULL,
 org_id uuid NOT NULL,
 site_id uuid NOT NULL,
 subnet_id uuid NOT NULL,
 cidr cidr NOT NULL CHECK(ipsec_provider_routed_ipv4(cidr)),
 subnet_status text NOT NULL DEFAULT 'approved' CHECK(subnet_status='approved'),
 PRIMARY KEY(connection_id,subnet_id),
 UNIQUE(connection_id,cidr),
 FOREIGN KEY(connection_id,org_id,site_id) REFERENCES ipsec_aws_static_configs(connection_id,org_id,site_id) ON DELETE RESTRICT,
 CONSTRAINT ipsec_provider_local_subnet_fk FOREIGN KEY(subnet_id,site_id,cidr,subnet_status) REFERENCES site_subnets(id,site_id,cidr,status) ON DELETE RESTRICT
);
CREATE TABLE ipsec_aws_remote_prefixes (
 connection_id uuid NOT NULL,
 org_id uuid NOT NULL,
 cidr cidr NOT NULL CHECK(ipsec_provider_routed_ipv4(cidr)),
 PRIMARY KEY(connection_id,cidr),
 FOREIGN KEY(connection_id,org_id) REFERENCES ipsec_provider_bindings(connection_id,org_id) ON DELETE RESTRICT
);
CREATE INDEX ipsec_provider_remote_org_idx ON ipsec_aws_remote_prefixes(org_id);
CREATE INDEX ipsec_provider_static_org_idx ON ipsec_aws_static_configs(org_id);
CREATE INDEX ipsec_provider_tunnel_org_idx ON ipsec_aws_tunnel_configs(org_id);

-- Advisory first in service transactions. Versioning defeats stale RR snapshots,
-- including absence of a provider row; an org timestamp update is intentional.
CREATE FUNCTION ipsec_provider_lock_org(p_org uuid) RETURNS void AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(p_org::text,0));
 -- Mirrors preserve WG-only cleanup of soft-deleted/deleting organizations.
 -- Provider creation separately requires a live org in the 0158 parent guard.
 UPDATE organizations SET updated_at=updated_at WHERE id=p_org;
END;
$$ LANGUAGE plpgsql;

-- route checks are mirrors for existing range writers: only provider conflicts
-- are added, never new WG-versus-WG validation. remote/inside/underlay admission
-- also sees the complete existing allocation set. Underlay duplicates are legal.
CREATE FUNCTION ipsec_provider_check_range(p_org uuid,p_cidr cidr,p_kind text) RETURNS void AS $$
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

CREATE FUNCTION ipsec_provider_binding_guard() RETURNS trigger AS $$
DECLARE profile text; intent text;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'IPsec provider identity immutable' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_immutable'; END IF;
 IF TG_OP='UPDATE' THEN
  IF NOT ((NOT OLD.withdrawal_started AND NEW.withdrawal_started AND NEW.configuration_sealed=OLD.configuration_sealed)
    OR (NOT OLD.configuration_sealed AND NEW.configuration_sealed AND NEW.withdrawal_started=OLD.withdrawal_started))
    OR NEW.connection_id<>OLD.connection_id OR NEW.org_id<>OLD.org_id OR NEW.profile_id<>OLD.profile_id OR NEW.configuration_revision<>OLD.configuration_revision OR NEW.created_at<>OLD.created_at THEN
   RAISE EXCEPTION 'IPsec provider binding immutable' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_immutable';
  END IF;
 ELSE
  IF NEW.withdrawal_started OR NEW.configuration_sealed THEN RAISE EXCEPTION 'IPsec provider initial state invalid' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_immutable'; END IF;
  PERFORM ipsec_provider_lock_org(NEW.org_id);
  SELECT provider_profile,desired_intent INTO profile,intent FROM ipsec_connections WHERE id=NEW.connection_id AND org_id=NEW.org_id FOR UPDATE;
  IF NOT FOUND OR profile IS DISTINCT FROM NEW.profile_id OR intent<>'disabled' THEN RAISE EXCEPTION 'IPsec provider attachment unavailable' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_immutable'; END IF;
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_provider_binding_guard BEFORE INSERT OR UPDATE OR DELETE ON ipsec_provider_bindings FOR EACH ROW EXECUTE FUNCTION ipsec_provider_binding_guard();

CREATE FUNCTION ipsec_provider_child_guard() RETURNS trigger AS $$
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
CREATE TRIGGER ipsec_provider_child_guard BEFORE INSERT OR UPDATE OR DELETE ON ipsec_aws_static_configs FOR EACH ROW EXECUTE FUNCTION ipsec_provider_child_guard();
CREATE TRIGGER ipsec_provider_child_guard BEFORE INSERT OR UPDATE OR DELETE ON ipsec_aws_tunnel_configs FOR EACH ROW EXECUTE FUNCTION ipsec_provider_child_guard();
CREATE TRIGGER ipsec_provider_child_guard BEFORE INSERT OR UPDATE OR DELETE ON ipsec_aws_local_prefixes FOR EACH ROW EXECUTE FUNCTION ipsec_provider_child_guard();
CREATE TRIGGER ipsec_provider_child_guard BEFORE INSERT OR UPDATE OR DELETE ON ipsec_aws_remote_prefixes FOR EACH ROW EXECUTE FUNCTION ipsec_provider_child_guard();

CREATE FUNCTION ipsec_provider_parent_guard() RETURNS trigger AS $$
BEGIN
 IF TG_OP='UPDATE' AND NEW.provider_profile IS DISTINCT FROM OLD.provider_profile THEN RAISE EXCEPTION 'IPsec provider profile immutable' USING ERRCODE='23514',CONSTRAINT='ipsec_provider_immutable'; END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_provider_parent_guard BEFORE UPDATE ON ipsec_connections FOR EACH ROW EXECUTE FUNCTION ipsec_provider_parent_guard();

CREATE FUNCTION ipsec_provider_completeness() RETURNS trigger AS $$
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
CREATE CONSTRAINT TRIGGER ipsec_provider_completeness AFTER INSERT OR UPDATE ON ipsec_connections DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ipsec_provider_completeness();
CREATE CONSTRAINT TRIGGER ipsec_provider_completeness AFTER INSERT OR UPDATE OR DELETE ON ipsec_provider_bindings DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ipsec_provider_completeness();
CREATE CONSTRAINT TRIGGER ipsec_provider_completeness AFTER INSERT OR UPDATE OR DELETE ON ipsec_aws_static_configs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ipsec_provider_completeness();
CREATE CONSTRAINT TRIGGER ipsec_provider_completeness AFTER INSERT OR UPDATE OR DELETE ON ipsec_aws_tunnel_configs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ipsec_provider_completeness();
CREATE CONSTRAINT TRIGGER ipsec_provider_completeness AFTER INSERT OR UPDATE OR DELETE ON ipsec_aws_local_prefixes DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ipsec_provider_completeness();
CREATE CONSTRAINT TRIGGER ipsec_provider_completeness AFTER INSERT OR UPDATE OR DELETE ON ipsec_aws_remote_prefixes DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ipsec_provider_completeness();

-- Existing writers acquire range advisory then org in application code. A raw
-- tuple mutation may arrive in reverse order; deadlock/serialization is a safe
-- refusal, never permission to bypass the overlap check. Pending ads unchanged.
CREATE FUNCTION ipsec_provider_subnet_mirror() RETURNS trigger AS $$
DECLARE org uuid; old_org uuid; current_org uuid;
BEGIN
 IF TG_OP='DELETE' THEN
  IF OLD.status='approved' THEN SELECT org_id INTO org FROM sites WHERE id=OLD.site_id; PERFORM ipsec_provider_lock_org(org); END IF;
  RETURN OLD;
 END IF;
 IF TG_OP='UPDATE' AND OLD.status='approved' THEN SELECT org_id INTO old_org FROM sites WHERE id=OLD.site_id; END IF;
 SELECT org_id INTO org FROM sites WHERE id=NEW.site_id;
 IF old_org IS NOT NULL AND old_org<>org THEN
  IF old_org<org THEN PERFORM ipsec_provider_lock_org(old_org);PERFORM ipsec_provider_lock_org(org);
  ELSE PERFORM ipsec_provider_lock_org(org);PERFORM ipsec_provider_lock_org(old_org);END IF;
 ELSIF NEW.status='approved' OR old_org IS NOT NULL THEN PERFORM ipsec_provider_lock_org(org);
 END IF;
 IF NEW.status='approved' THEN
  -- Site ownership could move while this statement waited for the range lock.
  -- Hold the Site stable and refuse an ownership change rather than checking
  -- reservations under a stale org captured before acquiring serialization.
  SELECT org_id INTO current_org FROM sites WHERE id=NEW.site_id FOR SHARE;
  IF current_org IS DISTINCT FROM org THEN RAISE EXCEPTION 'IPsec range ownership changed' USING ERRCODE='40001'; END IF;
  PERFORM ipsec_provider_check_range(org,NEW.cidr,'route');
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_provider_subnet_mirror BEFORE INSERT OR UPDATE OR DELETE ON site_subnets FOR EACH ROW EXECUTE FUNCTION ipsec_provider_subnet_mirror();

CREATE FUNCTION ipsec_provider_pool_mirror() RETURNS trigger AS $$
BEGIN
 IF NEW.pool_cidr IS DISTINCT FROM OLD.pool_cidr THEN
  -- This UPDATE already versions the organization. A nested org UPDATE in its
  -- own BEFORE trigger would recursively modify the same target tuple.
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.id::text,0));
  PERFORM ipsec_provider_check_range(NEW.id,NEW.pool_cidr::cidr,'route');
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_provider_pool_mirror BEFORE UPDATE OF pool_cidr ON organizations FOR EACH ROW EXECUTE FUNCTION ipsec_provider_pool_mirror();

CREATE FUNCTION ipsec_provider_vip_mirror() RETURNS trigger AS $$
BEGIN
 IF TG_OP='DELETE' THEN PERFORM ipsec_provider_lock_org(OLD.org_id);RETURN OLD; END IF;
 IF TG_OP='UPDATE' AND OLD.org_id<>NEW.org_id THEN
  IF OLD.org_id<NEW.org_id THEN PERFORM ipsec_provider_lock_org(OLD.org_id);PERFORM ipsec_provider_lock_org(NEW.org_id);
  ELSE PERFORM ipsec_provider_lock_org(NEW.org_id);PERFORM ipsec_provider_lock_org(OLD.org_id);END IF;
 ELSE PERFORM ipsec_provider_lock_org(NEW.org_id);END IF;
 PERFORM ipsec_provider_check_range(NEW.org_id,NEW.vip_range,'route');
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_provider_vip_mirror BEFORE INSERT OR DELETE OR UPDATE OF org_id,vip_range ON k8s_clusters FOR EACH ROW EXECUTE FUNCTION ipsec_provider_vip_mirror();

CREATE TRIGGER ipsec_provider_no_truncate BEFORE TRUNCATE ON ipsec_provider_bindings FOR EACH STATEMENT EXECUTE FUNCTION ipsec_refuse_truncate();
CREATE TRIGGER ipsec_provider_no_truncate BEFORE TRUNCATE ON ipsec_aws_static_configs FOR EACH STATEMENT EXECUTE FUNCTION ipsec_refuse_truncate();
CREATE TRIGGER ipsec_provider_no_truncate BEFORE TRUNCATE ON ipsec_aws_tunnel_configs FOR EACH STATEMENT EXECUTE FUNCTION ipsec_refuse_truncate();
CREATE TRIGGER ipsec_provider_no_truncate BEFORE TRUNCATE ON ipsec_aws_local_prefixes FOR EACH STATEMENT EXECUTE FUNCTION ipsec_refuse_truncate();
CREATE TRIGGER ipsec_provider_no_truncate BEFORE TRUNCATE ON ipsec_aws_remote_prefixes FOR EACH STATEMENT EXECUTE FUNCTION ipsec_refuse_truncate();

-- Moving an unrelated Site also moves its approved ranges between collectors.
-- The subnet row itself need not change, so it needs a separate mirror seam.
CREATE FUNCTION ipsec_provider_site_org_mirror() RETURNS trigger AS $$
DECLARE r record;
BEGIN
 IF NEW.org_id IS DISTINCT FROM OLD.org_id THEN
  IF OLD.org_id<NEW.org_id THEN PERFORM ipsec_provider_lock_org(OLD.org_id);PERFORM ipsec_provider_lock_org(NEW.org_id);
  ELSE PERFORM ipsec_provider_lock_org(NEW.org_id);PERFORM ipsec_provider_lock_org(OLD.org_id);END IF;
  FOR r IN SELECT cidr FROM site_subnets WHERE site_id=OLD.id AND status='approved' LOOP
   PERFORM ipsec_provider_check_range(NEW.org_id,r.cidr,'route');
  END LOOP;
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_provider_site_org_mirror BEFORE UPDATE OF org_id ON sites FOR EACH ROW EXECUTE FUNCTION ipsec_provider_site_org_mirror();
