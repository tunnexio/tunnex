-- Immutable BGP binding/tombstone identities require this schema even after deletion.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM ipsec_connections WHERE provider_profile='aws-bgp-ipv4-v1') OR EXISTS(SELECT 1 FROM ipsec_provider_bindings WHERE profile_id='aws-bgp-ipv4-v1') THEN
  RAISE EXCEPTION 'Cannot downgrade while BGP identities exist';
 END IF;
END $$;
DROP TRIGGER ipsec_bgp_completeness ON ipsec_connections;
DROP TRIGGER ipsec_bgp_completeness ON ipsec_provider_bindings;
DROP TABLE ipsec_aws_bgp_configs;
DROP FUNCTION ipsec_bgp_completeness();
ALTER TABLE ipsec_connections DROP CONSTRAINT ipsec_connections_provider_profile_check;
ALTER TABLE ipsec_connections ADD CONSTRAINT ipsec_connections_provider_profile_check CHECK(provider_profile IS NULL OR provider_profile='aws-static-ipv4-v1');
ALTER TABLE ipsec_provider_bindings DROP CONSTRAINT ipsec_provider_bindings_profile_id_check;
ALTER TABLE ipsec_provider_bindings ADD CONSTRAINT ipsec_provider_bindings_profile_id_check CHECK(profile_id='aws-static-ipv4-v1');
