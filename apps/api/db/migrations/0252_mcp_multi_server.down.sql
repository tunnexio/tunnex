-- The previous version gives an agent exactly one MCP server and fails the
-- runtime poll when it finds two. Rolling back must stop rather than pick one.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM agent_group_members m
        JOIN agent_mcp_profile_assignments a
          ON a.org_id = m.org_id AND a.agent_group_id = m.agent_group_id AND a.state = 'active'
        GROUP BY m.org_id, m.device_id
        HAVING count(a.id) > 1
    ) THEN
        RAISE EXCEPTION 'cannot roll back 0252: an agent has more than one MCP server';
    END IF;
    IF EXISTS (
        SELECT 1 FROM agent_mcp_profile_assignments
        WHERE state = 'active'
        GROUP BY org_id, agent_group_id
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'cannot roll back 0252: an agent group has more than one MCP server';
    END IF;
END $$;

CREATE UNIQUE INDEX agent_mcp_profile_one_active_group
    ON agent_mcp_profile_assignments (org_id, agent_group_id)
    WHERE state = 'active';

-- The function exactly as 0109 left it.
CREATE FUNCTION agent_mcp_profile_one_per_agent() RETURNS trigger AS $$
DECLARE
    locked_device_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'agent_mcp_profile_assignments' THEN
        IF NEW.state <> 'active' THEN RETURN NEW; END IF;
        -- Serialize assignment and membership writes for one group before
        -- taking per-device locks; this closes empty-group races.
        PERFORM pg_advisory_xact_lock(
            hashtextextended(NEW.org_id::text || ':group:' || NEW.agent_group_id::text, 0)
        );
        -- Acquire every affected device lock in a stable order. This closes
        -- assignment/member-write races without introducing a lock-order
        -- deadlock when a group has many members.
        FOR locked_device_id IN
            SELECT m.device_id
            FROM agent_group_members m
            WHERE m.org_id = NEW.org_id AND m.agent_group_id = NEW.agent_group_id
            ORDER BY m.device_id
        LOOP
            PERFORM pg_advisory_xact_lock(
                hashtextextended(NEW.org_id::text || ':' || locked_device_id::text, 0)
            );
        END LOOP;
        IF EXISTS (
            SELECT 1
            FROM agent_group_members target_member
            JOIN agent_mcp_profile_assignments existing
              ON existing.org_id = target_member.org_id AND existing.state = 'active'
            JOIN agent_group_members existing_member
              ON existing_member.org_id = existing.org_id
             AND existing_member.agent_group_id = existing.agent_group_id
            WHERE target_member.org_id = NEW.org_id
              AND target_member.agent_group_id = NEW.agent_group_id
              AND existing_member.device_id = target_member.device_id
              AND existing.agent_group_id <> NEW.agent_group_id
        ) THEN RAISE EXCEPTION 'an agent may have only one MCP profile'; END IF;
    ELSE
        PERFORM pg_advisory_xact_lock(
            hashtextextended(NEW.org_id::text || ':group:' || NEW.agent_group_id::text, 0)
        );
        PERFORM pg_advisory_xact_lock(hashtextextended(NEW.org_id::text || ':' || NEW.device_id::text, 0));
        IF EXISTS (
            SELECT 1 FROM agent_mcp_profile_assignments incoming
            JOIN agent_mcp_profile_assignments existing
              ON existing.org_id = incoming.org_id AND existing.state = 'active'
            JOIN agent_group_members existing_member
              ON existing_member.org_id = existing.org_id
             AND existing_member.agent_group_id = existing.agent_group_id
            WHERE incoming.org_id = NEW.org_id AND incoming.state = 'active'
              AND incoming.agent_group_id = NEW.agent_group_id
              AND existing_member.device_id = NEW.device_id
              AND existing.agent_group_id <> incoming.agent_group_id
        ) THEN RAISE EXCEPTION 'an agent may have only one MCP profile'; END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER agent_mcp_profile_assignment_one_per_agent
    BEFORE INSERT OR UPDATE OF profile_id, agent_group_id ON agent_mcp_profile_assignments
    FOR EACH ROW EXECUTE FUNCTION agent_mcp_profile_one_per_agent();
CREATE TRIGGER agent_mcp_profile_member_one_per_agent
    BEFORE INSERT OR UPDATE OF device_id, agent_group_id ON agent_group_members
    FOR EACH ROW EXECUTE FUNCTION agent_mcp_profile_one_per_agent();

DROP TRIGGER IF EXISTS agent_mcp_profile_default_server_name ON agent_mcp_profiles;
DROP FUNCTION IF EXISTS agent_mcp_profile_default_server_name();
DROP INDEX IF EXISTS agent_mcp_profiles_org_active_server_name_key;
ALTER TABLE agent_mcp_profiles
    DROP CONSTRAINT IF EXISTS agent_mcp_profiles_server_name_ck,
    DROP COLUMN IF EXISTS server_name;
DROP FUNCTION IF EXISTS agent_mcp_free_server_name(uuid, text, uuid);
DROP FUNCTION IF EXISTS agent_mcp_server_slug(text);
