-- Reverse 0002_tenancy. Tested: run down then up (make e2e / DoD).
DROP TABLE IF EXISTS audit_logs;      -- triggers drop with the table
DROP FUNCTION IF EXISTS audit_logs_prevent_mutation();
DROP TABLE IF EXISTS invitations;
DROP TABLE IF EXISTS memberships;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS organizations;
-- citext left installed; harmless and may be used by later migrations.
