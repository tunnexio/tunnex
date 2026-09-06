-- Removing custom SSO removes all associated identity links. Disable connections
-- and verify alternate administrator access before rolling back this migration.
DROP TABLE sso_connection_identities;
DROP TABLE sso_connections;
