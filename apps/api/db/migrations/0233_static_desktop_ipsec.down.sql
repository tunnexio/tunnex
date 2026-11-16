-- Retain static application records but fail them closed under the previous BGP-only contract.
CREATE OR REPLACE FUNCTION fqdn_application_ipsec_path_valid(o uuid,s uuid,n uuid,c uuid,v bigint) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT v=1 AND EXISTS(SELECT 1 FROM ipsec_connections x
 JOIN ipsec_org_settings settings ON settings.org_id=x.org_id AND settings.enabled
 JOIN nodes gateway ON gateway.id=x.gateway_node_id AND gateway.org_id=x.org_id AND gateway.site_id=x.site_id
 WHERE x.id=c AND x.org_id=o AND x.site_id=s AND x.gateway_node_id=n AND x.desired_intent='enabled'
 AND x.provider_profile='aws-bgp-ipv4-v1' AND x.deleted_at IS NULL AND x.finalized_at IS NULL
 AND gateway.status='active' AND gateway.revoked_at IS NULL AND gateway.cert_serial<>''
 AND gateway.policy_reported_at BETWEEN statement_timestamp()-interval '90 seconds' AND statement_timestamp()
 AND gateway.capabilities->'ipsec_config_version'='1'::jsonb AND gateway.capabilities->'ipsec_bgp_version'='1'::jsonb
 AND gateway.capabilities->'ipsec_desktop_transit_version'='1'::jsonb AND gateway.capabilities->'ipsec_fqdn_policy_version'='2'::jsonb
 AND gateway.capabilities->'ipsec_desktop_fqdn_version'='1'::jsonb)
$$;
