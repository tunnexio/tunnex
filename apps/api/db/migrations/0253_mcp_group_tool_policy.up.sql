-- AI-UX-1: tool policy is set on the agent group, per MCP server, and applies
-- to every agent in the group. A per-agent policy keeps deciding for the
-- servers it already covers, so current installations do not change.

-- Immutable policy versions for one (group, MCP server). Rules have the same
-- shape as agent_mcp_tool_policy_versions.rules: a rule with
-- step_up_required=false is "Allow", with step_up_required=true "Ask first",
-- and a tool with no rule is "Off". Version numbers are per (group, server) and
-- therefore collide with per-agent version numbers; anything that records a
-- policy version also records which policy it came from (policy_source below).
CREATE TABLE agent_group_mcp_tool_policy_versions (
    id                    uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id                uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    agent_group_id        uuid NOT NULL,
    profile_id            uuid NOT NULL,
    version               bigint NOT NULL CHECK (version > 0),
    rules                 jsonb NOT NULL CHECK (jsonb_typeof(rules) = 'array'),
    inventory_observed_at timestamptz NOT NULL,
    created_by_user_id    uuid NOT NULL REFERENCES users (id),
    created_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_group_id, profile_id, version),
    FOREIGN KEY (agent_group_id, org_id)
        REFERENCES agent_groups (id, org_id) ON DELETE CASCADE,
    FOREIGN KEY (profile_id, org_id)
        REFERENCES agent_mcp_profiles (id, org_id) ON DELETE CASCADE
);
CREATE INDEX agent_group_mcp_tool_policy_versions_current_idx
    ON agent_group_mcp_tool_policy_versions (org_id, agent_group_id, profile_id, version DESC);

COMMENT ON TABLE agent_group_mcp_tool_policy_versions IS
    'AI-UX-1 immutable MCP tool allow policies for one agent group and MCP server. Rules contain only stable inventory identities; never arguments, results, OAuth tokens, or client secrets.';

-- What a tool does, as the administrator marked it. Kept apart from the rules
-- so a tool that is Off can carry a marker and the marker survives policy
-- versions. Nothing is inferred from a tool's name.
CREATE TABLE agent_mcp_tool_markers (
    org_id         uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    profile_id     uuid NOT NULL,
    tool_name      text NOT NULL CHECK (char_length(tool_name) BETWEEN 1 AND 512),
    effect         text NOT NULL CHECK (effect IN ('reads', 'changes', 'destructive')),
    set_by_user_id uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (profile_id, tool_name),
    FOREIGN KEY (profile_id, org_id)
        REFERENCES agent_mcp_profiles (id, org_id) ON DELETE CASCADE
);
CREATE INDEX agent_mcp_tool_markers_org_profile_idx
    ON agent_mcp_tool_markers (org_id, profile_id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON agent_mcp_tool_markers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- The endpoints a per-agent policy decides for. For an endpoint listed on the
-- agent's latest version, that version decides (an empty rule list still denies
-- everything). For any other endpoint the group policy decides.
ALTER TABLE agent_mcp_tool_policy_versions
    ADD COLUMN override_endpoints text[] NOT NULL DEFAULT '{}';

-- Every agent that has a policy today keeps it: its latest version overrides
-- the endpoint(s) the agent is assigned now and every endpoint its rules name.
UPDATE agent_mcp_tool_policy_versions v
SET override_endpoints = covered.endpoints
FROM (
    SELECT latest.id, array_agg(DISTINCT e.endpoint ORDER BY e.endpoint) AS endpoints
    FROM (
        SELECT DISTINCT ON (device_id) id, org_id, device_id, rules
        FROM agent_mcp_tool_policy_versions
        ORDER BY device_id, version DESC
    ) latest
    CROSS JOIN LATERAL (
        SELECT btrim(p.endpoint) AS endpoint
        FROM agent_group_members m
        JOIN agent_mcp_profile_assignments a
          ON a.org_id = m.org_id AND a.agent_group_id = m.agent_group_id AND a.state = 'active'
        JOIN agent_mcp_profiles p ON p.id = a.profile_id AND p.org_id = a.org_id
        WHERE m.org_id = latest.org_id AND m.device_id = latest.device_id
        UNION
        SELECT btrim(rule ->> 'endpoint')
        FROM jsonb_array_elements(
            CASE WHEN jsonb_typeof(latest.rules) = 'array' THEN latest.rules ELSE '[]'::jsonb END
        ) AS rule
        WHERE coalesce(btrim(rule ->> 'endpoint'), '') <> ''
    ) e
    GROUP BY latest.id
) covered
WHERE v.id = covered.id;

-- Which policy a step-up request and an activity row were decided under.
-- 'agent' is the per-agent policy (every row written before this migration);
-- 'group' is a group policy, named by policy_group_id while that group exists.
ALTER TABLE agent_mcp_tool_approval_requests
    ADD COLUMN policy_source text NOT NULL DEFAULT 'agent'
        CONSTRAINT agent_mcp_tool_approval_requests_policy_source_ck CHECK (policy_source IN ('agent', 'group')),
    ADD COLUMN policy_group_id uuid REFERENCES agent_groups (id) ON DELETE SET NULL,
    ADD CONSTRAINT agent_mcp_tool_approval_requests_policy_group_ck
        CHECK (policy_source = 'group' OR policy_group_id IS NULL);

ALTER TABLE agent_mcp_tool_activity
    ADD COLUMN policy_source text
        CONSTRAINT agent_mcp_tool_activity_policy_source_ck CHECK (policy_source IS NULL OR policy_source IN ('agent', 'group')),
    ADD COLUMN policy_group_id uuid REFERENCES agent_groups (id) ON DELETE SET NULL,
    ADD CONSTRAINT agent_mcp_tool_activity_policy_group_ck
        CHECK (policy_group_id IS NULL OR coalesce(policy_source, '') = 'group');

-- Activity written before this migration was decided under the per-agent
-- policy whenever it names a policy version.
UPDATE agent_mcp_tool_activity SET policy_source = 'agent' WHERE policy_version IS NOT NULL;

-- A live step-up request is unique per call identity. Version numbers repeat
-- across the per-agent policy and each group policy, so the source and the
-- group are part of that identity.
DROP INDEX agent_mcp_tool_approval_requests_live_digest_idx;
CREATE UNIQUE INDEX agent_mcp_tool_approval_requests_live_digest_idx
    ON agent_mcp_tool_approval_requests (
        org_id, device_id, policy_source,
        COALESCE(policy_group_id, '00000000-0000-0000-0000-000000000000'::uuid),
        policy_version, endpoint, server_name, tool_name, input_schema_hash, request_digest
    )
    WHERE state IN ('pending', 'approved');

-- "Connect MCP server": the administrator enters an address and the gateway
-- reads the tool list on its next discovery pass. A preview is a short-lived
-- request for that read. It holds tool definitions only (name, description,
-- input schema and the hashes the control plane computed) and no credential.
-- Rows are removed after expires_at.
CREATE TABLE agent_mcp_connection_previews (
    id                   uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id               uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    endpoint             text NOT NULL CHECK (char_length(endpoint) BETWEEN 1 AND 2048),
    via_device_id        uuid,
    via_group_id         uuid,
    -- The gateway asked to read the tool list. NULL when none could be chosen.
    node_id              uuid REFERENCES nodes (id) ON DELETE CASCADE,
    state                text NOT NULL DEFAULT 'waiting' CHECK (state IN ('waiting', 'ready', 'failed')),
    failure_reason       text NOT NULL DEFAULT '' CHECK (char_length(failure_reason) <= 64),
    server_name          text NOT NULL DEFAULT '' CHECK (char_length(server_name) <= 512),
    tools                jsonb NOT NULL DEFAULT '[]'
                         CHECK (jsonb_typeof(tools) = 'array' AND octet_length(tools::text) <= 1048576),
    requested_by_user_id uuid REFERENCES users (id) ON DELETE SET NULL,
    observed_at          timestamptz,
    expires_at           timestamptz NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_mcp_connection_previews_via_ck
        CHECK ((via_device_id IS NOT NULL) <> (via_group_id IS NOT NULL)),
    FOREIGN KEY (via_device_id, org_id)
        REFERENCES devices (id, org_id) ON DELETE CASCADE,
    FOREIGN KEY (via_group_id, org_id)
        REFERENCES agent_groups (id, org_id) ON DELETE CASCADE
);
CREATE INDEX agent_mcp_connection_previews_node_waiting_idx
    ON agent_mcp_connection_previews (org_id, node_id, expires_at)
    WHERE state = 'waiting';
CREATE INDEX agent_mcp_connection_previews_expiry_idx
    ON agent_mcp_connection_previews (expires_at);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON agent_mcp_connection_previews
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
