DROP INDEX IF EXISTS devices_org_ip_key;
CREATE UNIQUE INDEX devices_node_ip_key ON devices (node_id, assigned_ip)
    WHERE assigned_ip IS NOT NULL AND status = 'active' AND deleted_at IS NULL;
ALTER TABLE organizations DROP COLUMN IF EXISTS pool_cidr;
