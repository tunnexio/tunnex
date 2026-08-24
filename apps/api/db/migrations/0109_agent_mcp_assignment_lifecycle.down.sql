-- History and lifecycle state are intentionally non-lossy. A downgrade must
-- stop rather than collapse replaced/unassigned/quarantined assignment evidence.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM agent_mcp_profile_assignments
        WHERE state <> 'active' OR ended_at IS NOT NULL OR quarantine_reason IS NOT NULL
    ) OR EXISTS (SELECT 1 FROM agent_mcp_profiles WHERE archived_at IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot roll back 0109: MCP lifecycle history exists';
    END IF;
END $$;

DROP INDEX agent_mcp_profile_assignments_org_group_state_idx;
DROP INDEX agent_mcp_profile_one_active_group;
CREATE OR REPLACE FUNCTION agent_mcp_profile_one_per_agent() RETURNS trigger AS $$
BEGIN
    IF TG_TABLE_NAME = 'agent_mcp_profile_assignments' THEN
        IF EXISTS (
            SELECT 1 FROM agent_group_members target_member
            JOIN agent_mcp_profile_assignments existing ON existing.org_id = target_member.org_id
            JOIN agent_group_members existing_member ON existing_member.org_id = existing.org_id
              AND existing_member.agent_group_id = existing.agent_group_id
            WHERE target_member.org_id = NEW.org_id AND target_member.agent_group_id = NEW.agent_group_id
              AND existing.profile_id <> NEW.profile_id AND existing_member.device_id = target_member.device_id
        ) THEN RAISE EXCEPTION 'an agent may have only one MCP profile'; END IF;
    ELSE
        IF EXISTS (
            SELECT 1 FROM agent_mcp_profile_assignments incoming
            JOIN agent_mcp_profile_assignments existing ON existing.org_id = incoming.org_id
            JOIN agent_group_members existing_member ON existing_member.org_id = existing.org_id
              AND existing_member.agent_group_id = existing.agent_group_id
            WHERE incoming.org_id = NEW.org_id AND incoming.agent_group_id = NEW.agent_group_id
              AND existing.profile_id <> incoming.profile_id AND existing_member.device_id = NEW.device_id
        ) THEN RAISE EXCEPTION 'an agent may have only one MCP profile'; END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
ALTER TABLE agent_mcp_profile_assignments
    DROP COLUMN quarantine_reason,
    DROP COLUMN ended_by_user_id,
    DROP COLUMN ended_at,
    DROP COLUMN state;
ALTER TABLE agent_mcp_profiles DROP COLUMN archived_at;
