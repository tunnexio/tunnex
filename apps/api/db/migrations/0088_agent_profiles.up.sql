-- F01: metadata belongs to the agent profile, while identity, ownership and
-- lifecycle remain on the canonical devices row.
CREATE TABLE agent_profiles (
    device_id   uuid PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    environment text NOT NULL DEFAULT '',
    runtime     text NOT NULL DEFAULT '',
    labels      jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(labels) = 'object'),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER set_updated_at BEFORE UPDATE ON agent_profiles
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- A foreign key alone cannot enforce the discriminator on the referenced row.
-- Keep the profile agent-only at the database boundary as well as in the API.
CREATE FUNCTION ensure_agent_profile_device() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM devices WHERE id = NEW.device_id AND kind = 'agent') THEN
        RAISE EXCEPTION 'agent profile requires an agent device';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER agent_profiles_agent_only
AFTER INSERT OR UPDATE ON agent_profiles
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION ensure_agent_profile_device();

-- Suspended is an agent lifecycle state, never a human-device state.
CREATE FUNCTION ensure_suspended_agent_device() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status = 'suspended' AND NEW.kind <> 'agent' THEN
        RAISE EXCEPTION 'suspended status is only valid for agent devices';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER suspended_agent_only
BEFORE INSERT OR UPDATE OF status, kind ON devices
FOR EACH ROW EXECUTE FUNCTION ensure_suspended_agent_device();

-- Existing agent rows must receive a profile without changing their canonical
-- device identity, owner, status, or telemetry.
INSERT INTO agent_profiles (device_id)
SELECT id FROM devices WHERE kind = 'agent' AND deleted_at IS NULL
ON CONFLICT (device_id) DO NOTHING;

ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_status_check;
ALTER TABLE devices ADD CONSTRAINT devices_status_check
    CHECK (status IN ('active', 'pending', 'suspended', 'revoked'));

COMMENT ON TABLE agent_profiles IS
    'F01 metadata keyed by the canonical agent device; owner/status/telemetry are deliberately not duplicated here.';
