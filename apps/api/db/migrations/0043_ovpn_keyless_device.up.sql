-- S9.1 Slice 4b-wiring (D-S9.4-MODEL): an OpenVPN device has NO WireGuard public key — its
-- credential is a client cert, so public_key stays ''. The per-gateway WG-pubkey uniqueness must
-- therefore apply ONLY to devices that HAVE a WG key; else two keyless OVPN devices on one node
-- would collide on ''. Adding `public_key <> ''` scopes the uniqueness to its actual invariant (a
-- WG-only property), which is why the OVPN fork needs NO transport branch here — it keys on
-- key-presence, not transport.
DROP INDEX IF EXISTS devices_node_pubkey_key;
CREATE UNIQUE INDEX devices_node_pubkey_key ON devices (node_id, public_key)
    WHERE status = 'active' AND deleted_at IS NULL AND public_key <> '';
