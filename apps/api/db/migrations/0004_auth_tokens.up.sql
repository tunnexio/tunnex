-- 0004 auth_tokens (S2.1) — email verification & password reset tokens.
--
-- Security properties (mirrors the invitations design):
--   * token stored HASHED (sha-256), never plaintext;
--   * PURPOSE-bound (a reset token cannot act as a verification token);
--   * single-use (consumed_at) and expiring (expires_at).
--
-- Global (user-scoped, not org-scoped): auth predates org context, so this table
-- is on the query-lint globalTables allowlist.
CREATE TABLE auth_tokens (
    id         uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    purpose    text NOT NULL CHECK (purpose IN ('email_verification', 'password_reset')),
    token_hash bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX auth_tokens_token_hash_key ON auth_tokens (token_hash);
CREATE INDEX auth_tokens_user_purpose_idx ON auth_tokens (user_id, purpose);
