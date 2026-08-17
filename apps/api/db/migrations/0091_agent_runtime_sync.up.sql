-- F04: server-owned revision state for a managed AI-agent runtime.
--
-- Identity, ownership, WireGuard material and lifecycle stay on devices. This
-- table records only the control loop: what revision the CP wants, what the
-- runtime last applied, and the last bounded diagnostic it reported. It never
-- stores a private key, bootstrap token or runtime bearer credential.
CREATE TABLE agent_runtime_state (
    device_id               uuid PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    desired_revision        bigint NOT NULL DEFAULT 1 CHECK (desired_revision >= 1),
    applied_revision        bigint NOT NULL DEFAULT 0 CHECK (applied_revision >= 0),
    last_attempted_revision bigint NOT NULL DEFAULT 0 CHECK (last_attempted_revision >= 0),
    client_version          text NOT NULL DEFAULT '' CHECK (char_length(client_version) <= 128),
    last_seen_at            timestamptz,
    last_error_code         text CHECK (last_error_code IS NULL OR char_length(last_error_code) <= 128),
    last_error_revision     bigint CHECK (last_error_revision IS NULL OR last_error_revision >= 1),
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    CHECK (applied_revision <= last_attempted_revision),
    CHECK (last_attempted_revision <= desired_revision),
    CHECK ((last_error_code IS NULL) = (last_error_revision IS NULL))
);

CREATE TRIGGER set_updated_at BEFORE UPDATE ON agent_runtime_state
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- A plain FK proves that the device exists, but not that it is an agent. Keep
-- that discriminator invariant at the database boundary so no human device can
-- accidentally acquire a managed-agent credential or configuration channel.
CREATE FUNCTION ensure_agent_runtime_device() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM devices
        WHERE id = NEW.device_id AND kind = 'agent' AND deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'agent runtime state requires a live agent device';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER agent_runtime_state_agent_only
AFTER INSERT OR UPDATE ON agent_runtime_state
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION ensure_agent_runtime_device();

COMMENT ON TABLE agent_runtime_state IS
    'F04 managed-agent desired/applied revision and bounded runtime health; never credential or private-key material.';
