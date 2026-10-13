DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM ipsec_runtime_deliveries d LEFT JOIN ipsec_runtime_state s ON s.connection_id=d.connection_id WHERE d.kind='apply' AND d.manifest->>'profile_id'='aws-bgp-ipv4-v1' AND COALESCE(s.last_cleaned_delivery_revision,0)<d.desired_revision) THEN RAISE EXCEPTION 'Cannot downgrade while BGP deliveries exist'; END IF;
END $$;
DROP TRIGGER ipsec_bgp_delivery_guard ON ipsec_runtime_deliveries;
DROP FUNCTION ipsec_bgp_delivery_guard();
DROP TRIGGER ipsec_bgp_enable_guard ON ipsec_connections;
DROP FUNCTION ipsec_bgp_enable_guard();
