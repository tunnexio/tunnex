-- F12: secret-free MCP inventory observed by one managed agent runtime.
CREATE TABLE agent_mcp_inventory (
    device_id uuid PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    snapshot jsonb NOT NULL,
    observed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER set_updated_at BEFORE UPDATE ON agent_mcp_inventory
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE agent_mcp_inventory IS
    'F12 MCP shadow-mode metadata only; no credentials, session ids, contents, prompts, or tool results.';
