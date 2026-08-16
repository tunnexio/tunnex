-- F06: one optional existing organization group may manage an agent. The
-- accountable owner remains devices.user_id; this column is delegation only.
-- Repair the F05 table for already-upgraded schema-94 installations and give
-- fresh installs the same canonical trigger as they advance through 0095.
-- DROP/CREATE keeps both paths aligned without changing F05 row data.
DROP TRIGGER IF EXISTS agent_wireguard_rotations_set_updated_at ON agent_wireguard_rotations;
DROP TRIGGER IF EXISTS set_updated_at ON agent_wireguard_rotations;
CREATE TRIGGER set_updated_at
BEFORE UPDATE ON agent_wireguard_rotations
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

ALTER TABLE agent_profiles
    ADD COLUMN managing_group_id uuid NULL REFERENCES user_groups (id) ON DELETE SET NULL;

CREATE INDEX agent_profiles_managing_group_idx
    ON agent_profiles (managing_group_id)
    WHERE managing_group_id IS NOT NULL;

CREATE FUNCTION enforce_agent_profile_managing_group_org() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    device_org uuid;
    group_org uuid;
BEGIN
    IF NEW.managing_group_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT org_id INTO device_org FROM devices WHERE id = NEW.device_id;
    SELECT org_id INTO group_org FROM user_groups WHERE id = NEW.managing_group_id;
    IF device_org IS NULL OR group_org IS NULL OR device_org <> group_org THEN
        RAISE EXCEPTION 'agent managing group must belong to the agent organization';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER agent_profiles_managing_group_same_org
AFTER INSERT OR UPDATE OF device_id, managing_group_id ON agent_profiles
DEFERRABLE INITIALLY IMMEDIATE
FOR EACH ROW EXECUTE FUNCTION enforce_agent_profile_managing_group_org();

COMMENT ON COLUMN agent_profiles.managing_group_id IS
    'Optional existing organization group whose current members may view and manage this agent; not an ownership or policy grant.';
