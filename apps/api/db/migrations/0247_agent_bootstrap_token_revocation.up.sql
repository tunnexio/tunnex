-- AI-SEC-1 item 6: a pending agent bootstrap token can be revoked before it is
-- used. Additive: two nullable columns, no existing row changes meaning.
-- A token is either used or revoked, never both.
ALTER TABLE agent_bootstrap_tokens
    ADD COLUMN revoked_at timestamptz,
    ADD COLUMN revoked_by uuid REFERENCES users (id) ON DELETE SET NULL,
    ADD CONSTRAINT agent_bootstrap_tokens_revoked_ck
      CHECK (revoked_at IS NULL OR (consumed_at IS NULL AND revoked_at >= created_at));
