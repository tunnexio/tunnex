-- AI-UX-1: MCP has its own organization switch and no longer depends on
-- "Agent groups & policy templates".
--
-- A table of its own rather than a column on organizations: the organization
-- row is read by `SELECT *` everywhere, including by tests that pin an older
-- schema version. No row = off.
CREATE TABLE organization_mcp_settings (
    org_id             uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    enabled            boolean NOT NULL,
    updated_by_user_id uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON organization_mcp_settings
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Until now MCP was reachable exactly when agent groups and policy templates
-- were on, so every organization that had that switch on keeps MCP.
INSERT INTO organization_mcp_settings (org_id, enabled)
SELECT o.id, true
FROM organizations o
WHERE o.agent_policy_templates_enabled;
