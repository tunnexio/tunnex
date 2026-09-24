-- No populated setting, disabled connection or tombstone may be discarded.
LOCK TABLE ipsec_org_settings, ipsec_connections, ipsec_tunnels, ipsec_tunnel_secrets
    IN ACCESS EXCLUSIVE MODE;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM ipsec_org_settings)
       OR EXISTS (SELECT 1 FROM ipsec_connections)
       OR EXISTS (SELECT 1 FROM ipsec_tunnels)
       OR EXISTS (SELECT 1 FROM ipsec_tunnel_secrets) THEN
        RAISE EXCEPTION '0158 rollback refused: IPsec data exists';
    END IF;
END;
$$;
DROP TRIGGER ipsec_org_before_soft_delete ON organizations;
DROP TABLE ipsec_tunnel_secrets;
DROP TABLE ipsec_tunnels;
DROP TABLE ipsec_connections;
DROP TABLE ipsec_org_settings;
DROP FUNCTION ipsec_refuse_truncate();
DROP FUNCTION ipsec_verify_connection_children();
DROP FUNCTION ipsec_child_guard();
DROP FUNCTION ipsec_org_soft_delete_guard();
DROP FUNCTION ipsec_connection_guard();
DROP FUNCTION ipsec_setting_guard();
DROP FUNCTION ipsec_require_live_org(uuid);
