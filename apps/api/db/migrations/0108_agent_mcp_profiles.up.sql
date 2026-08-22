-- F19: one reusable MCP upstream profile can be assigned to one or more
-- managed-agent groups. The endpoint is configuration, never a credential.
CREATE TABLE agent_mcp_profiles (
    id         uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    endpoint   text NOT NULL CHECK (length(endpoint) BETWEEN 1 AND 2048),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, org_id)
);
CREATE UNIQUE INDEX agent_mcp_profiles_org_active_name_key
    ON agent_mcp_profiles (org_id, lower(name));
CREATE TRIGGER set_updated_at BEFORE UPDATE ON agent_mcp_profiles
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE agent_mcp_profile_assignments (
    id             uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id         uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    profile_id     uuid NOT NULL,
    agent_group_id uuid NOT NULL,
    assigned_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (profile_id, agent_group_id),
    FOREIGN KEY (profile_id, org_id)
        REFERENCES agent_mcp_profiles (id, org_id) ON DELETE CASCADE,
    FOREIGN KEY (agent_group_id, org_id)
        REFERENCES agent_groups (id, org_id) ON DELETE CASCADE
);
CREATE INDEX agent_mcp_profile_assignments_org_group_idx
    ON agent_mcp_profile_assignments (org_id, agent_group_id);

-- A device can inherit only one active profile across all its groups. Enforce
-- this at both assignment and later group-membership writes; never pick one.
CREATE FUNCTION agent_mcp_profile_one_per_agent() RETURNS trigger AS $$
BEGIN
    IF TG_TABLE_NAME = 'agent_mcp_profile_assignments' THEN
        IF EXISTS (
            SELECT 1
            FROM agent_group_members target_member
            JOIN agent_mcp_profile_assignments existing
              ON existing.org_id = target_member.org_id
            JOIN agent_group_members existing_member
              ON existing_member.org_id = existing.org_id
             AND existing_member.agent_group_id = existing.agent_group_id
             AND existing_member.device_id = target_member.device_id
            WHERE target_member.org_id = NEW.org_id
              AND target_member.agent_group_id = NEW.agent_group_id
              AND existing.profile_id <> NEW.profile_id
        ) THEN
            RAISE EXCEPTION 'an agent may have only one MCP profile';
        END IF;
    ELSE
        IF EXISTS (
            SELECT 1
            FROM agent_mcp_profile_assignments incoming
            JOIN agent_mcp_profile_assignments existing
              ON existing.org_id = incoming.org_id
            JOIN agent_group_members existing_member
              ON existing_member.org_id = existing.org_id
             AND existing_member.agent_group_id = existing.agent_group_id
             AND existing_member.device_id = NEW.device_id
            WHERE incoming.org_id = NEW.org_id
              AND incoming.agent_group_id = NEW.agent_group_id
              AND existing.profile_id <> incoming.profile_id
        ) THEN
            RAISE EXCEPTION 'an agent may have only one MCP profile';
        END IF;
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
