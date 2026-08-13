-- 0016 CLI credential flow (S5.1) — dedicated header-borne CLI credentials plus
-- the one-time codes that mint them (loopback authorization codes and the
-- device-code fallback).
--
-- Security properties (join-token / auth_tokens hygiene class):
--   * every secret stored HASHED (sha-256), never plaintext;
--   * codes are single-use (consumed_at) and short-lived (expires_at);
--   * credentials are identity-bound (user_id, CASCADE), expiring, revocable;
--   * fingerprint is the KEYED proof-of-secret (HMAC subkey, 12 hex) — safe to
--     store/display and the only correlate that ever appears in audit rows.
--
-- Global (user-scoped, not org-scoped): CLI credentials belong to a user across
-- all their orgs — querylint globalTables allowlist.

CREATE TABLE cli_credentials (
    id           uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name         text NOT NULL DEFAULT 'tunnex-cli',
    token_hash   bytea NOT NULL,
    fingerprint  text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz
);
CREATE UNIQUE INDEX cli_credentials_token_hash_key ON cli_credentials (token_hash);
CREATE INDEX cli_credentials_user_idx ON cli_credentials (user_id);

-- One-time loopback authorization codes (mint via the browser consent leg).
CREATE TABLE cli_auth_codes (
    id             uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    user_id        uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash      bytea NOT NULL,
    redirect_uri   text NOT NULL,
    code_challenge text NOT NULL,
    expires_at     timestamptz NOT NULL,
    consumed_at    timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX cli_auth_codes_code_hash_key ON cli_auth_codes (code_hash);

-- Device-code fallback (browserless hosts): the CLI polls device_code while a
-- browser session approves user_code. user_id is set at approval.
CREATE TABLE cli_device_codes (
    id               uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    device_code_hash bytea NOT NULL,
    user_code_hash   bytea NOT NULL,
    user_id          uuid REFERENCES users (id) ON DELETE CASCADE,
    approved_at      timestamptz,
    expires_at       timestamptz NOT NULL,
    consumed_at      timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX cli_device_codes_device_hash_key ON cli_device_codes (device_code_hash);
CREATE UNIQUE INDEX cli_device_codes_user_hash_key ON cli_device_codes (user_code_hash);
