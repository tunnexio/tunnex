-- Disabled BGP intent only; activation remains refused until runtime qualification.
ALTER TABLE ipsec_connections DROP CONSTRAINT ipsec_connections_provider_profile_check;
ALTER TABLE ipsec_connections ADD CONSTRAINT ipsec_connections_provider_profile_check CHECK(provider_profile IS NULL OR provider_profile IN('aws-static-ipv4-v1','aws-bgp-ipv4-v1'));
ALTER TABLE ipsec_provider_bindings DROP CONSTRAINT ipsec_provider_bindings_profile_id_check;
ALTER TABLE ipsec_provider_bindings ADD CONSTRAINT ipsec_provider_bindings_profile_id_check CHECK(profile_id IN('aws-static-ipv4-v1','aws-bgp-ipv4-v1'));
CREATE TABLE ipsec_aws_bgp_configs (
 connection_id uuid PRIMARY KEY,
 org_id uuid NOT NULL,
 local_asn bigint NOT NULL CHECK(local_asn BETWEEN 64512 AND 65534 OR local_asn BETWEEN 4200000000 AND 4294967294),
 remote_asn bigint NOT NULL CHECK(remote_asn=7224 OR remote_asn BETWEEN 64512 AND 65534 OR remote_asn BETWEEN 4200000000 AND 4294967294),
 router_id inet NOT NULL CHECK(family(router_id)=4 AND masklen(router_id)=32 AND NOT(router_id <<= '0.0.0.0/8'::cidr OR router_id <<= '127.0.0.0/8'::cidr OR router_id <<= '169.254.0.0/16'::cidr OR router_id <<= '224.0.0.0/3'::cidr)),
 maximum_prefixes integer NOT NULL CHECK(maximum_prefixes BETWEEN 1 AND 64),
 CHECK(local_asn<>remote_asn),
 FOREIGN KEY(connection_id,org_id) REFERENCES ipsec_provider_bindings(connection_id,org_id) ON DELETE RESTRICT
);
CREATE INDEX ipsec_bgp_org_idx ON ipsec_aws_bgp_configs(org_id);
CREATE TRIGGER ipsec_provider_child_guard BEFORE INSERT OR UPDATE OR DELETE ON ipsec_aws_bgp_configs FOR EACH ROW EXECUTE FUNCTION ipsec_provider_child_guard();
CREATE TRIGGER ipsec_provider_no_truncate BEFORE TRUNCATE ON ipsec_aws_bgp_configs FOR EACH STATEMENT EXECUTE FUNCTION ipsec_refuse_truncate();
CREATE FUNCTION ipsec_bgp_completeness() RETURNS trigger AS $$
DECLARE c uuid; profile text; finalized timestamptz; n bigint;
BEGIN
 IF TG_TABLE_NAME='ipsec_connections' THEN c:=NEW.id;
 ELSIF TG_OP='DELETE' THEN c:=OLD.connection_id; ELSE c:=NEW.connection_id; END IF;
 SELECT provider_profile,finalized_at INTO profile,finalized FROM ipsec_connections WHERE id=c FOR UPDATE;
 SELECT count(*) INTO n FROM ipsec_aws_bgp_configs WHERE connection_id=c;
 IF (profile='aws-bgp-ipv4-v1' AND ((finalized IS NULL AND n<>1) OR (finalized IS NOT NULL AND n<>0))) OR (profile IS DISTINCT FROM 'aws-bgp-ipv4-v1' AND n<>0) THEN
  RAISE EXCEPTION 'IPsec BGP configuration incomplete' USING ERRCODE='23514',CONSTRAINT='ipsec_bgp_incomplete';
 END IF;
 RETURN NULL;
END;
$$ LANGUAGE plpgsql;
CREATE CONSTRAINT TRIGGER ipsec_bgp_completeness AFTER INSERT OR UPDATE ON ipsec_connections DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ipsec_bgp_completeness();
CREATE CONSTRAINT TRIGGER ipsec_bgp_completeness AFTER INSERT OR UPDATE OR DELETE ON ipsec_provider_bindings DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ipsec_bgp_completeness();
CREATE CONSTRAINT TRIGGER ipsec_bgp_completeness AFTER INSERT OR UPDATE OR DELETE ON ipsec_aws_bgp_configs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ipsec_bgp_completeness();
