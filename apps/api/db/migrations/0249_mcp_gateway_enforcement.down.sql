-- Rolling back returns enforcement to the agent host. Stored call arguments are
-- dropped with their columns. Gateway-observed inventory rows are removed first:
-- without the source column an older control plane would treat them as
-- agent-reported and could not refresh them, leaving a stale allow-list source.
DELETE FROM agent_mcp_inventory WHERE source = 'gateway';

COMMENT ON TABLE agent_mcp_tool_approval_requests IS
    'F16 step-up permits. Exact policy identity plus request digest only; raw MCP arguments, results, OAuth tokens, and secrets are never retained.';

ALTER TABLE agent_mcp_tool_approval_requests
    DROP CONSTRAINT IF EXISTS agent_mcp_tool_approval_requests_definition_hash_ck,
    DROP CONSTRAINT IF EXISTS agent_mcp_tool_approval_requests_arguments_ck,
    DROP COLUMN IF EXISTS tool_definition_hash,
    DROP COLUMN IF EXISTS arguments_truncated,
    DROP COLUMN IF EXISTS arguments;

DROP TABLE IF EXISTS organization_mcp_direct_path_grace;

ALTER TABLE agent_runtime_state
    DROP COLUMN IF EXISTS mcp_gateway_capable_at;

ALTER TABLE agent_mcp_inventory
    DROP CONSTRAINT IF EXISTS agent_mcp_inventory_source_ck,
    DROP COLUMN IF EXISTS source;
