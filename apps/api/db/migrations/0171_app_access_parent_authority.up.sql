ALTER TABLE users ADD COLUMN app_auth_epoch bigint NOT NULL DEFAULT 1 CHECK (app_auth_epoch > 0);
ALTER TABLE mfa_challenges ADD COLUMN verified_app_auth_epoch bigint CHECK (verified_app_auth_epoch > 0);
CREATE TABLE app_access_parent_logout_tombstones (
 parent_hash bytea PRIMARY KEY CHECK (octet_length(parent_hash) = 32),
 user_id uuid NOT NULL REFERENCES users(id),
 parent_expires_at timestamptz NOT NULL,
 revoked_at timestamptz NOT NULL DEFAULT now()
);
