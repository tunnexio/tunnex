ALTER TABLE agent_runtime_state
    DROP COLUMN IF EXISTS tunnel_dns_applied,
    DROP COLUMN IF EXISTS mcp_hold_capable_at;
