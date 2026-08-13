-- 0005 sso_configs (S2.3) — per-org SSO provider configuration.
--
-- Tenant-owned (org_id scoped). The client secret is stored ENCRYPTED
-- (AES-GCM under the bootstrap master key, see internal/crypto) — the plaintext
-- never touches the database. The schema lives in core; the SSO *feature* is
-- enterprise-gated in the application layer.
CREATE TABLE sso_configs (
    id                     uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id                 uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    provider               text NOT NULL CHECK (provider IN ('google', 'microsoft')),
    client_id              text NOT NULL,
    client_secret_sealed   bytea NOT NULL,   -- AES-GCM ciphertext (never plaintext)
    enabled                boolean NOT NULL DEFAULT true,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, provider)
);
CREATE INDEX sso_configs_org_id_idx ON sso_configs (org_id);

CREATE TRIGGER set_updated_at BEFORE UPDATE ON sso_configs
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
