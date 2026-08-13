DROP INDEX IF EXISTS devices_node_pubkey_key;
CREATE UNIQUE INDEX devices_node_pubkey_key ON devices (node_id, public_key)
    WHERE status = 'active' AND deleted_at IS NULL;
