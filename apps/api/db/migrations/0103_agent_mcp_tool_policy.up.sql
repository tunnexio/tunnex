-- F14: immutable, inventory-bound allow policies for a managed agent's explicit MCP proxy.
CREATE TABLE agent_mcp_tool_policy_versions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    version bigint NOT NULL CHECK (version > 0),
    rules jsonb NOT NULL,
    inventory_observed_at timestamptz NOT NULL,
    created_by_user_id uuid NOT NULL REFERENCES users (id),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (device_id, version)
);

CREATE INDEX agent_mcp_tool_policy_versions_current_idx
    ON agent_mcp_tool_policy_versions (org_id, device_id, version DESC);

COMMENT ON TABLE agent_mcp_tool_policy_versions IS
    'F14 immutable MCP tool allow policies. Rules contain only stable inventory identities; never arguments, results, OAuth tokens, or client secrets.';
