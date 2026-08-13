DROP INDEX IF EXISTS devices_node_ip_key;
ALTER TABLE nodes DROP COLUMN IF EXISTS endpoint;
