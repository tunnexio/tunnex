DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM agent_profiles WHERE managing_group_id IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot roll back 0095: agent managing-group assignments exist';
    END IF;
END;
$$;

DROP TRIGGER IF EXISTS agent_profiles_managing_group_same_org ON agent_profiles;
DROP FUNCTION IF EXISTS enforce_agent_profile_managing_group_org();
DROP INDEX IF EXISTS agent_profiles_managing_group_idx;
ALTER TABLE agent_profiles DROP COLUMN managing_group_id;
