-- 0008 nodes (S3.1) — the control-plane side of the tunnex-node agent:
-- the agent CA, node records, and single-use join tokens.

-- platform_secrets: global (not org-scoped) home for platform-wide sealed
-- material. The agent CA lives here: private key sealed under the master key
-- (AES-GCM), certificate in the clear.
CREATE TABLE platform_secrets (
    name         text PRIMARY KEY,
    secret_sealed bytea,           -- AES-GCM ciphertext (e.g. CA private key)
    public_pem   text,             -- plaintext (e.g. CA certificate)
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON platform_secrets
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- nodes: an enrolled tunnex-node agent. Tenant-owned. The control plane
-- authorizes by cert identity (cert_serial), never by a claimed id in a message.
CREATE TABLE nodes (
    id            uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id        uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name          text NOT NULL,
    status        text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    cert_serial   text NOT NULL,   -- serial of the currently-valid mTLS cert
    agent_version text NOT NULL DEFAULT '',
    enrolled_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz,
    revoked_at    timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);
CREATE UNIQUE INDEX nodes_cert_serial_key ON nodes (cert_serial);
CREATE INDEX nodes_org_id_idx ON nodes (org_id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON nodes
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- node_join_tokens: hashed, single-use, expiring, org-bound (optional name pin).
CREATE TABLE node_join_tokens (
    id              uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id          uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    node_name       text,           -- optional pin: token enrolls only this name
    token_hash      bytea NOT NULL,
    expires_at      timestamptz NOT NULL,
    consumed_at     timestamptz,
    consumed_node_id uuid REFERENCES nodes (id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX node_join_tokens_hash_key ON node_join_tokens (token_hash);
CREATE INDEX node_join_tokens_org_id_idx ON node_join_tokens (org_id);
