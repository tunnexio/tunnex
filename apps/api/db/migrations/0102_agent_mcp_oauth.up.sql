-- F13: OAuth trust records are separate from F12's secret-free inventory.
CREATE TABLE agent_mcp_oauth_connections (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    endpoint text NOT NULL,
    protected_resource text NOT NULL,
    issuer text NOT NULL,
    scopes jsonb NOT NULL DEFAULT '[]'::jsonb,
    client_id text NOT NULL,
    client_secret_sealed text,
    client_secret_fingerprint text,
    access_token_sealed text,
    refresh_token_sealed text,
    token_expires_at timestamptz,
    state text NOT NULL DEFAULT 'discovered' CHECK (state IN ('discovered','pending_consent','connected','expired','failed','disconnected')),
    failure_code text,
    connected_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    connected_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (device_id, endpoint)
);

CREATE INDEX agent_mcp_oauth_connections_org_device_idx ON agent_mcp_oauth_connections(org_id, device_id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON agent_mcp_oauth_connections
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE agent_mcp_oauth_connections IS
    'F13 agent MCP OAuth trust; tokens and client secrets are sealed and never returned by readable APIs.';
