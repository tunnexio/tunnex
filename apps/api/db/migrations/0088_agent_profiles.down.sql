DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM devices WHERE status = 'suspended') THEN
        RAISE EXCEPTION '0088 rollback refused: suspended agent/device rows must be resumed or revoked first';
    END IF;
    IF EXISTS (SELECT 1 FROM agent_profiles) THEN
        IF EXISTS (SELECT 1 FROM agent_profiles WHERE environment <> '' OR runtime <> '' OR labels <> '{}'::jsonb) THEN
            RAISE EXCEPTION '0088 rollback refused: non-default agent profile metadata would be lost';
        END IF;
    END IF;
END
$$;

DROP TRIGGER IF EXISTS agent_profiles_agent_only ON agent_profiles;
DROP FUNCTION IF EXISTS ensure_agent_profile_device();
DROP TRIGGER IF EXISTS suspended_agent_only ON devices;
DROP FUNCTION IF EXISTS ensure_suspended_agent_device();
DROP TABLE IF EXISTS agent_profiles;

ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_status_check;
ALTER TABLE devices ADD CONSTRAINT devices_status_check
    CHECK (status IN ('active', 'pending', 'revoked'));
