-- S7.5.2: IdP-group sync — groups from the IdP become policy SUBJECTS.
-- Provenance markers make an IdP-synced group DISJOINT from a hand-managed one (D1), enforced at
-- the schema layer, not by convention.

-- A user_group is either 'manual' (S7.1 behavior, unchanged) or 'idp_sync'. An idp_sync group maps
-- to exactly one IdP group (idp_provider + idp_group_id) — the row IS the mapping (no side table).
ALTER TABLE user_groups
    ADD COLUMN origin       text NOT NULL DEFAULT 'manual' CHECK (origin IN ('manual', 'idp_sync')),
    ADD COLUMN idp_provider text NULL CHECK (idp_provider IS NULL OR idp_provider IN ('microsoft', 'google')),
    ADD COLUMN idp_group_id text NULL;

-- Shape guard (D1): a manual group carries NO IdP identity; an idp_sync group MUST carry both its
-- provider and its external id. The two kinds can never blur.
ALTER TABLE user_groups ADD CONSTRAINT user_groups_origin_shape CHECK (
    (origin = 'manual'   AND idp_provider IS NULL     AND idp_group_id IS NULL) OR
    (origin = 'idp_sync' AND idp_provider IS NOT NULL AND idp_group_id IS NOT NULL)
);

-- One Tunnex group per IdP group per org.
CREATE UNIQUE INDEX user_groups_idp_unique ON user_groups (org_id, idp_provider, idp_group_id)
    WHERE origin = 'idp_sync';

-- group_members gains origin so the reconcile only ever touches its own 'idp_sync' rows and can
-- NEVER stomp a hand-added member (belt over the disjoint-group rule).
ALTER TABLE group_members
    ADD COLUMN origin text NOT NULL DEFAULT 'manual' CHECK (origin IN ('manual', 'idp_sync'));

-- Per-org, per-provider directory-sync credential + two-tier sync-health status (D2). The app
-- credential (client id + sealed secret/cert) mirrors sso_configs AES-GCM sealing — plaintext is
-- never stored. last_sync_* are stamped by the reconciler; last_sync_at NULL = never synced yet.
CREATE TABLE idp_sync_configs (
    id              uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id          uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    provider        text NOT NULL CHECK (provider IN ('microsoft', 'google')),
    client_id       text NOT NULL,
    secret_sealed   bytea NOT NULL, -- AES-GCM ciphertext under the S0.3 master key; plaintext never in the DB
    tenant_id       text NULL,      -- Entra tenant id (google leaves null)
    enabled         boolean NOT NULL DEFAULT true,
    last_sync_at    timestamptz NULL,
    last_sync_ok    boolean NOT NULL DEFAULT false,
    last_sync_error text NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, provider)
);

CREATE TRIGGER set_updated_at BEFORE UPDATE ON idp_sync_configs
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
