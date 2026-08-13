-- 0010 devices (S3.3) — user-owned WireGuard peers that connect through a node.
--
-- Identity<->credential binding is STRUCTURAL here: user_id is NOT NULL, so a
-- peer can never be unowned. The control plane stores only the peer's PUBLIC
-- key — there is deliberately NO private_key column (client-generated keys never
-- leave the device; server-generated keys are delivered once and discarded).

CREATE TABLE devices (
    id             uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id         uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id        uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,   -- owner; no unowned peers
    node_id        uuid NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,   -- gateway it connects through
    name           text NOT NULL,
    platform       text NOT NULL DEFAULT '',
    public_key     text NOT NULL,                                          -- peer WG pubkey (never the private key)
    assigned_ip    text,                                                   -- TODO(S3.5): from the org pool allocator
    status         text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    last_handshake_at timestamptz,                                         -- populated in S3.6
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    revoked_at     timestamptz,
    deleted_at     timestamptz
);
-- A public key is unique per gateway among ACTIVE devices (keyed on status, not
-- deleted_at, since revocation flips status — so a revoked key can be re-added).
CREATE UNIQUE INDEX devices_node_pubkey_key ON devices (node_id, public_key)
    WHERE status = 'active' AND deleted_at IS NULL;
-- Partial composite indexes backing the hot paths: the agent's per-node peer
-- fetch (every reconcile) and the per-user active-device cap check.
CREATE INDEX devices_node_active_idx ON devices (node_id) WHERE status = 'active' AND deleted_at IS NULL;
CREATE INDEX devices_org_user_active_idx ON devices (org_id, user_id) WHERE status = 'active' AND deleted_at IS NULL;
CREATE INDEX devices_org_id_idx ON devices (org_id);
CREATE INDEX devices_user_id_idx ON devices (user_id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON devices
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Per-user device cap (an org setting): bounds how many peers one user — or one
-- compromised session — can mint. 0 means unlimited (honored in the service);
-- the default is a real cap so the guard is on out of the box. Negatives are
-- nonsensical, so constrain to >= 0.
ALTER TABLE organizations ADD COLUMN max_devices_per_user integer NOT NULL DEFAULT 10
    CHECK (max_devices_per_user >= 0);
