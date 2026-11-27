-- Rolling back returns MCP to the "Agent groups & policy templates" switch. An
-- organization that turned MCP on by itself loses MCP until that switch is on.
DROP TABLE IF EXISTS organization_mcp_settings;
