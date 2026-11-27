-- Rolling back returns tool policy to one policy per agent. Group policies,
-- tool markers and pending previews are dropped with their tables; agents that
-- relied on a group policy are denied (no policy = deny) until an administrator
-- writes a per-agent policy.
DROP TABLE IF EXISTS agent_mcp_connection_previews;

-- The previous version identifies a live step-up request without a policy
-- source. Requests decided under a group policy cannot be told apart from
-- per-agent ones there, so they end here rather than survive as something else.
UPDATE agent_mcp_tool_approval_requests
SET state = 'expired'
WHERE policy_source = 'group' AND state IN ('pending', 'approved');

DROP INDEX IF EXISTS agent_mcp_tool_approval_requests_live_digest_idx;
CREATE UNIQUE INDEX agent_mcp_tool_approval_requests_live_digest_idx
    ON agent_mcp_tool_approval_requests (org_id, device_id, policy_version, endpoint, server_name, tool_name, input_schema_hash, request_digest)
    WHERE state IN ('pending', 'approved');

ALTER TABLE agent_mcp_tool_activity
    DROP CONSTRAINT IF EXISTS agent_mcp_tool_activity_policy_group_ck,
    DROP CONSTRAINT IF EXISTS agent_mcp_tool_activity_policy_source_ck,
    DROP COLUMN IF EXISTS policy_group_id,
    DROP COLUMN IF EXISTS policy_source;

ALTER TABLE agent_mcp_tool_approval_requests
    DROP CONSTRAINT IF EXISTS agent_mcp_tool_approval_requests_policy_group_ck,
    DROP CONSTRAINT IF EXISTS agent_mcp_tool_approval_requests_policy_source_ck,
    DROP COLUMN IF EXISTS policy_group_id,
    DROP COLUMN IF EXISTS policy_source;

ALTER TABLE agent_mcp_tool_policy_versions
    DROP COLUMN IF EXISTS override_endpoints;

DROP TABLE IF EXISTS agent_mcp_tool_markers;
DROP TABLE IF EXISTS agent_group_mcp_tool_policy_versions;
