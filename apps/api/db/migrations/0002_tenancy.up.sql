-- 0002 tenancy — the multi-tenant core (S1.1).
-- Conforms to the conventions in README.md: UUIDv7 PKs, timestamptz +
-- created_at/updated_at + set_updated_at trigger, org_id scoping for
-- tenant-owned tables. See README "Global vs tenant-owned tables".

-- Case-insensitive email (login is email-first; org resolved after login).
CREATE EXTENSION IF NOT EXISTS citext;

-- organizations — the tenant root. Not org-scoped (it IS the tenant).
CREATE TABLE organizations (
    id         uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    name       text NOT NULL,
    slug       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz
);
-- Slug unique among live orgs (soft-deleted slugs may be reused).
CREATE UNIQUE INDEX organizations_slug_key ON organizations (slug) WHERE deleted_at IS NULL;

CREATE TRIGGER set_updated_at BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- users — GLOBAL (not org-scoped): a user logs in by email, then their org is
-- resolved from memberships. Email is globally unique.
CREATE TABLE users (
    id              uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    email           citext NOT NULL,
    name            text NOT NULL DEFAULT '',
    password_hash   text,               -- null for SSO-only users (set in S2.1)
    email_verified_at timestamptz,
    status          text NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active', 'deactivated')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz
);
CREATE UNIQUE INDEX users_email_key ON users (email) WHERE deleted_at IS NULL;

CREATE TRIGGER set_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- memberships — tenant-owned join of users to orgs with a role.
CREATE TABLE memberships (
    id         uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role       text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    -- A user holds at most one membership per org.
    UNIQUE (org_id, user_id)
);
-- Composite index leads with org_id (every query is tenant-scoped).
CREATE INDEX memberships_org_id_user_id_idx ON memberships (org_id, user_id);
CREATE INDEX memberships_user_id_idx ON memberships (user_id);

CREATE TRIGGER set_updated_at BEFORE UPDATE ON memberships
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- invitations — tenant-owned. Token is stored HASHED, single-use, expiring,
-- revocable. Substrate for S2.5 (SSO provisioning) and S2.6 (manual invites).
CREATE TABLE invitations (
    id                 uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id             uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    email              citext NOT NULL,
    role               text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    token_hash         bytea NOT NULL,          -- sha-256 of the token; never store plaintext
    expires_at         timestamptz NOT NULL,
    accepted_at        timestamptz,             -- set once; single-use
    revoked_at         timestamptz,
    invited_by_user_id uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX invitations_token_hash_key ON invitations (token_hash);
-- At most one pending invite per (org, email).
CREATE UNIQUE INDEX invitations_org_email_pending_idx
    ON invitations (org_id, email)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;
CREATE INDEX invitations_org_id_idx ON invitations (org_id);

CREATE TRIGGER set_updated_at BEFORE UPDATE ON invitations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- audit_logs — append-only. No updated_at (immutable). org_id and actor are
-- nullable because some events precede org resolution (e.g. a failed login).
CREATE TABLE audit_logs (
    id            uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id        uuid REFERENCES organizations (id) ON DELETE SET NULL,
    actor_user_id uuid REFERENCES users (id) ON DELETE SET NULL,
    action        text NOT NULL,
    target_type   text,
    target_id     text,
    metadata      jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_logs_org_id_created_at_idx ON audit_logs (org_id, created_at DESC);

-- Append-only enforcement at the DB layer: UPDATE/DELETE are impossible, not
-- merely un-exposed. An audit table that can be edited is a liability.
CREATE OR REPLACE FUNCTION audit_logs_prevent_mutation()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_logs_no_update BEFORE UPDATE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_prevent_mutation();
CREATE TRIGGER audit_logs_no_delete BEFORE DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_prevent_mutation();
-- TRUNCATE is statement-level and bypasses row triggers — block it too.
CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_prevent_mutation();
