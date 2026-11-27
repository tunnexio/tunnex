-- AI-SEC-2: what an agent did through MCP. One row per decision the control
-- plane made for a gateway-forwarded MCP request. Allowed calls live here (with
-- retention) rather than in the audit log, because their volume is unbounded;
-- denials and step-up events are also written to the audit log by the service.
--
-- Never stored: call arguments (only their digest), results, OAuth tokens.
CREATE TABLE agent_mcp_tool_activity (
    id                   uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id               uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    device_id            uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    node_id              uuid REFERENCES nodes (id) ON DELETE SET NULL,
    endpoint             text NOT NULL CHECK (char_length(endpoint) <= 2048),
    server_name          text NOT NULL DEFAULT '' CHECK (char_length(server_name) <= 512),
    method               text NOT NULL CHECK (char_length(method) BETWEEN 1 AND 128),
    tool_name            text NOT NULL DEFAULT '' CHECK (char_length(tool_name) <= 512),
    arguments_digest     text CHECK (arguments_digest IS NULL OR length(arguments_digest) = 64),
    decision             text NOT NULL CHECK (decision IN ('allow', 'deny')),
    -- Empty for an allow. For a deny: why (for example policy, arguments,
    -- rate_limit, step_up_required, definition_changed, no_profile).
    reason               text NOT NULL DEFAULT '' CHECK (char_length(reason) <= 64),
    policy_version       bigint CHECK (policy_version IS NULL OR policy_version > 0),
    approval_request_id  uuid REFERENCES agent_mcp_tool_approval_requests (id) ON DELETE SET NULL,
    -- What happened after an allow: pending until the gateway reports back.
    result_status        text NOT NULL DEFAULT 'pending'
                         CHECK (result_status IN ('pending', 'ok', 'error', 'upstream_unavailable', 'not_forwarded')),
    upstream_http_status integer CHECK (upstream_http_status IS NULL OR upstream_http_status BETWEEN 100 AND 599),
    occurred_at          timestamptz NOT NULL DEFAULT now(),
    completed_at         timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_mcp_tool_activity_deny_not_forwarded_ck
        CHECK (decision = 'allow' OR result_status = 'not_forwarded')
);

-- The agent Activity tab: newest first for one agent.
CREATE INDEX agent_mcp_tool_activity_device_idx
    ON agent_mcp_tool_activity (org_id, device_id, occurred_at DESC, id DESC);

-- Retention sweep by ingest age.
CREATE INDEX agent_mcp_tool_activity_created_idx
    ON agent_mcp_tool_activity (org_id, created_at);

COMMENT ON TABLE agent_mcp_tool_activity IS
    'AI-SEC-2 MCP tool activity. Decision and outcome metadata plus an argument digest only; never arguments, results, OAuth tokens, or secrets.';

-- Tenant-scoped retention. A missing row means the application default (30 days).
CREATE TABLE agent_mcp_tool_activity_retention_settings (
    org_id              uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    retention_days      integer NOT NULL DEFAULT 30 CHECK (retention_days BETWEEN 1 AND 3650),
    updated_by_user_id  uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON agent_mcp_tool_activity_retention_settings
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
