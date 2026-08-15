-- F03: one-time managed AI-agent bootstrap credentials. These are distinct from
-- node_join_tokens: those redeem into gateway mTLS identities, while this row
-- redeems into a WireGuard device peer on one specific gateway.
ALTER TABLE nodes ADD CONSTRAINT nodes_org_id_id_f03_key UNIQUE (org_id, id);
ALTER TABLE devices ADD CONSTRAINT devices_org_id_id_f03_key UNIQUE (org_id, id);

CREATE TABLE agent_bootstrap_tokens (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    gateway_node_id uuid NOT NULL,
    agent_name text NOT NULL,
    token_hash bytea NOT NULL CHECK (octet_length(token_hash) = 32),
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
    consumed_at timestamptz,
    consumed_device_id uuid REFERENCES devices (id) ON DELETE SET NULL,
    issued_by uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_bootstrap_tokens_org_gateway_fk
      FOREIGN KEY (org_id, gateway_node_id) REFERENCES nodes (org_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_bootstrap_tokens_consumed_at_ck
      CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);
CREATE UNIQUE INDEX agent_bootstrap_tokens_hash_key ON agent_bootstrap_tokens (token_hash);
CREATE INDEX agent_bootstrap_tokens_org_id_idx ON agent_bootstrap_tokens (org_id);

-- F04 consumes this later for agent-only poll/report authentication. It is not
-- a user credential and is never accepted by session/org-policy endpoints.
CREATE TABLE agent_runtime_credentials (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    device_id uuid NOT NULL,
    token_hash bytea NOT NULL CHECK (octet_length(token_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    CONSTRAINT agent_runtime_credentials_org_device_fk
      FOREIGN KEY (org_id, device_id) REFERENCES devices (org_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX agent_runtime_credentials_hash_key ON agent_runtime_credentials (token_hash);
CREATE UNIQUE INDEX agent_runtime_credentials_device_key ON agent_runtime_credentials (device_id);

CREATE FUNCTION f03_runtime_credential_agent_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM devices WHERE id = NEW.device_id AND org_id = NEW.org_id AND kind = 'agent' AND deleted_at IS NULL) THEN
        RAISE EXCEPTION 'agent runtime credential requires an active agent device';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER agent_runtime_credentials_agent_only
BEFORE INSERT OR UPDATE ON agent_runtime_credentials
FOR EACH ROW EXECUTE FUNCTION f03_runtime_credential_agent_only();
