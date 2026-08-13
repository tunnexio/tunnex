-- 0011 node endpoint + device address uniqueness (S3.4).
--
-- endpoint is the node's PUBLIC WireGuard endpoint (host:port) that peer configs
-- dial. It cannot be known from inside the container, so the agent reports it
-- from its TUNNEX_NODE_ENDPOINT env (bootstrap default; editable later).
ALTER TABLE nodes ADD COLUMN endpoint text NOT NULL DEFAULT '';

-- Peers now carry a real tunnel address (minimal lowest-free allocation until
-- S3.5's pool allocator). Guard against two active peers on a node sharing an
-- IP at the source of truth (S3.5 adds release/reuse/resize on top of this).
CREATE UNIQUE INDEX devices_node_ip_key ON devices (node_id, assigned_ip)
    WHERE assigned_ip IS NOT NULL AND status = 'active' AND deleted_at IS NULL;
