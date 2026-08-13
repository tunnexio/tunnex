-- S10.2 Slice 1: machine credentials — a first-class, NON-USER org principal for the GitOps operator
-- (and future automation). DISTINCT from cli_credentials (user-bound): a machine credential is
-- ORG-scoped, holds a fixed 'operator' role (k8s:manage + policy:manage + org:view — scoped to EXACTLY
-- what the operator needs, D3), carries NO user_id (keeping a non-human OUT of the identity-binding
-- subject space, D4 — it is a caller identity, never a policy SUBJECT), and attributes audit as a SYSTEM
-- actor with a cause (migration 0027). Revocable; revocation severs on the very next request (no session
-- cache). The token is stored as a sha256 hash; the fingerprint is for display/audit only — the secret is
-- shown ONCE at mint (the one-time-secret ceremony, like every other credential).
CREATE TABLE machine_credentials (
    id           uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id       uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name         text NOT NULL,                    -- operator-chosen label; appears in audit as "operator:<name>"
    role         text NOT NULL DEFAULT 'operator', -- the org role it holds (RBAC scope); fixed 'operator' at mint (D3)
    token_hash   bytea NOT NULL,
    fingerprint  text NOT NULL,                    -- short display id (NEVER the secret)
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at   timestamptz
);
CREATE UNIQUE INDEX machine_credentials_token_hash_key ON machine_credentials (token_hash);
CREATE INDEX machine_credentials_org_idx ON machine_credentials (org_id);
