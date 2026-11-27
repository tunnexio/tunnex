-- AI-SEC-2: MCP tool policy is enforced at the gateway, not on the agent host.
-- Additive: nullable columns or columns with a default; no existing row changes
-- meaning except organizations that already use MCP, which get a grace date.

-- Who observed the tool list. 'agent' rows were reported by the agent host and
-- stay as they are. Once a gateway reports a device's inventory the row becomes
-- 'gateway' and agent-reported inventory for that device is ignored.
ALTER TABLE agent_mcp_inventory
    ADD COLUMN source text NOT NULL DEFAULT 'agent'
        CONSTRAINT agent_mcp_inventory_source_ck CHECK (source IN ('agent', 'gateway'));

-- When the managed runtime last declared that it forwards MCP to the gateway
-- listener. NULL = a runtime that predates the gateway path (it cannot update
-- itself; the operator re-runs the install command).
ALTER TABLE agent_runtime_state
    ADD COLUMN mcp_gateway_capable_at timestamptz;

-- Until grace_until an older runtime may keep the direct path to its MCP
-- endpoint. No row = no grace: the direct path is closed as soon as the gateway
-- can enforce. Organizations that already have an active MCP assignment get 30
-- days from the upgrade; everyone else starts closed.
--
-- A table of its own rather than a column on organizations: the organization
-- row is read by `SELECT *` everywhere, including by tests that pin an older
-- schema version, and this date concerns only MCP.
CREATE TABLE organization_mcp_direct_path_grace (
    org_id      uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    grace_until timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO organization_mcp_direct_path_grace (org_id, grace_until)
SELECT o.id, now() + interval '30 days'
FROM organizations o
WHERE EXISTS (
    SELECT 1 FROM agent_mcp_profile_assignments a
    WHERE a.org_id = o.id AND a.state = 'active'
);

-- An approver sees what is being approved. The arguments of the pending call
-- are kept with the request (capped; the service stores at most 4 KiB of
-- canonical JSON and sets arguments_truncated when the call was larger) and go
-- away with the row. tool_definition_hash binds the approval to the exact tool
-- definition (name, description, input schema) the approver was shown.
ALTER TABLE agent_mcp_tool_approval_requests
    ADD COLUMN arguments jsonb,
    ADD COLUMN arguments_truncated boolean NOT NULL DEFAULT false,
    ADD COLUMN tool_definition_hash text,
    ADD CONSTRAINT agent_mcp_tool_approval_requests_arguments_ck
        CHECK (arguments IS NULL OR (jsonb_typeof(arguments) = 'object' AND octet_length(arguments::text) <= 8192)),
    ADD CONSTRAINT agent_mcp_tool_approval_requests_definition_hash_ck
        CHECK (tool_definition_hash IS NULL OR length(tool_definition_hash) = 64);

COMMENT ON TABLE agent_mcp_tool_approval_requests IS
    'Step-up permits bound to exact policy identity and request digest. The pending call''s arguments are kept (capped) so an approver can see them; results, OAuth tokens, and secrets are never retained.';
