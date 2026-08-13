-- S7.5.5 MFA / TOTP. Auth-plane only (no data-plane, no compiled artifact). Four tables:
--   user_totp            — one TOTP enrollment per user (secret SEALED at rest, verify-before-arm).
--   user_recovery_codes  — single-use recovery codes, HASHED (cliauth hygiene).
--   mfa_challenges       — the login-time second-step challenge (NOT a session — D6): a short-lived
--                          token with an attempt counter, burned on success OR cap exhaustion.
--   org_mfa              — per-org ENFORCE flag (enterprise + opt-in, default OFF; slice-2 logic).
-- D1: enrollment is OPEN (all editions); only org enforce is enterprise-gated (app layer).

-- ── user_totp (verify-before-arm: confirmed=false until a valid code) ──────────────
CREATE TABLE user_totp (
    user_id            uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    secret_enc         bytea NOT NULL,               -- TOTP secret, SEALED (S4.5 sealer) — never plaintext
    confirmed          boolean NOT NULL DEFAULT false,
    -- Replay guard (RFC-6238): the last timestep a code was accepted for. A code (or its ±1-window
    -- neighbor) that already succeeded must never succeed again — verify rejects any timestep <= this.
    last_used_timestep bigint,
    created_at         timestamptz NOT NULL DEFAULT now(),
    confirmed_at       timestamptz
);

-- ── user_recovery_codes (single-use, hashed — join-token-class hygiene) ────────────
CREATE TABLE user_recovery_codes (
    id         uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash  bytea NOT NULL,
    used_at    timestamptz,                          -- NULL = unused; set atomically on consume
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX user_recovery_codes_hash_key ON user_recovery_codes (code_hash);
CREATE INDEX user_recovery_codes_user_idx ON user_recovery_codes (user_id);

-- ── mfa_challenges (the half-auth state as a TOKEN, not a session — D6) ────────────
CREATE TABLE mfa_challenges (
    id         uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash bytea NOT NULL,
    attempts   integer NOT NULL DEFAULT 0,           -- D7 terminal per-challenge cap
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX mfa_challenges_token_hash_key ON mfa_challenges (token_hash);

-- ── org_mfa (per-org enforce — enterprise + opt-in, default OFF) ───────────────────
CREATE TABLE org_mfa (
    org_id     uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    enforce    boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON org_mfa
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
