ALTER TABLE agent_mcp_tool_approval_requests
    DROP CONSTRAINT IF EXISTS agent_mcp_tool_approval_requests_timestamps_check;

ALTER TABLE agent_mcp_tool_approval_requests
    ADD CONSTRAINT agent_mcp_tool_approval_requests_timestamps_check CHECK (
        (state = 'pending' AND approved_at IS NULL AND denied_at IS NULL AND consumed_at IS NULL) OR
        (state = 'approved' AND approved_at IS NOT NULL AND denied_at IS NULL AND consumed_at IS NULL) OR
        (state = 'denied' AND approved_at IS NULL AND denied_at IS NOT NULL AND consumed_at IS NULL) OR
        (state = 'consumed' AND approved_at IS NOT NULL AND denied_at IS NULL AND consumed_at IS NOT NULL) OR
        (state = 'expired' AND denied_at IS NULL AND consumed_at IS NULL)
    );
