LOCK TABLE ipsec_provider_bindings,ipsec_aws_static_configs,ipsec_aws_tunnel_configs,ipsec_aws_local_prefixes,ipsec_aws_remote_prefixes IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM ipsec_provider_bindings) OR EXISTS(SELECT 1 FROM ipsec_aws_static_configs) OR EXISTS(SELECT 1 FROM ipsec_aws_tunnel_configs) OR EXISTS(SELECT 1 FROM ipsec_aws_local_prefixes) OR EXISTS(SELECT 1 FROM ipsec_aws_remote_prefixes) OR EXISTS(SELECT 1 FROM ipsec_connections WHERE provider_profile IS NOT NULL) THEN
  RAISE EXCEPTION '0159 rollback refused: provider configuration or tombstone exists';
 END IF;
END $$;
DROP TRIGGER ipsec_provider_site_org_mirror ON sites;
DROP TRIGGER ipsec_provider_pool_mirror ON organizations;
DROP TRIGGER ipsec_provider_subnet_mirror ON site_subnets;
DROP TRIGGER ipsec_provider_vip_mirror ON k8s_clusters;
DROP TRIGGER ipsec_provider_completeness ON ipsec_connections;
DROP TRIGGER ipsec_provider_parent_guard ON ipsec_connections;
DROP TABLE ipsec_aws_local_prefixes;
DROP TABLE ipsec_aws_remote_prefixes;
DROP TABLE ipsec_aws_tunnel_configs;
DROP TABLE ipsec_aws_static_configs;
DROP TABLE ipsec_provider_bindings;
ALTER TABLE site_subnets DROP CONSTRAINT ipsec_provider_subnet_owner_key;
ALTER TABLE ipsec_tunnels DROP CONSTRAINT ipsec_provider_tunnel_owner_key;
ALTER TABLE ipsec_connections DROP CONSTRAINT ipsec_provider_parent_assignment_key;
ALTER TABLE ipsec_connections DROP COLUMN provider_profile;
DROP FUNCTION ipsec_provider_site_org_mirror();
DROP FUNCTION ipsec_provider_vip_mirror();
DROP FUNCTION ipsec_provider_pool_mirror();
DROP FUNCTION ipsec_provider_subnet_mirror();
DROP FUNCTION ipsec_provider_completeness();
DROP FUNCTION ipsec_provider_parent_guard();
DROP FUNCTION ipsec_provider_child_guard();
DROP FUNCTION ipsec_provider_binding_guard();
DROP FUNCTION ipsec_provider_check_range(uuid,cidr,text);
DROP FUNCTION ipsec_provider_lock_org(uuid);

DROP FUNCTION ipsec_provider_public_ipv4(inet);
DROP FUNCTION ipsec_provider_routed_ipv4(cidr);
