-- F16: one-use, policy-bound step-up approvals for an explicit MCP proxy.
-- Raw MCP arguments and OAuth material are deliberately never persisted here.
CREATE TABLE agent_mcp_tool_approval_requests (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    policy_version bigint NOT NULL CHECK (policy_version > 0),
    endpoint text NOT NULL,
    server_name text NOT NULL,
    tool_name text NOT NULL,
    input_schema_hash text NOT NULL,
    request_digest text NOT NULL CHECK (length(request_digest) = 64),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'denied', 'expired', 'consumed')),
    requested_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    approved_by_user_id uuid REFERENCES users (id),
    approved_at timestamptz,
    denied_by_user_id uuid REFERENCES users (id),
    denied_at timestamptz,
    consumed_at timestamptz,
    CHECK ((state = 'approved') = (approved_at IS NOT NULL)),
    CHECK ((state = 'denied') = (denied_at IS NOT NULL)),
    CHECK ((state = 'consumed') = (consumed_at IS NOT NULL))
);

CREATE INDEX agent_mcp_tool_approval_requests_pending_idx
    ON agent_mcp_tool_approval_requests (org_id, device_id, requested_at DESC)
    WHERE state = 'pending';

CREATE UNIQUE INDEX agent_mcp_tool_approval_requests_live_digest_idx
    ON agent_mcp_tool_approval_requests (org_id, device_id, policy_version, endpoint, server_name, tool_name, input_schema_hash, request_digest)
    WHERE state IN ('pending', 'approved');

COMMENT ON TABLE agent_mcp_tool_approval_requests IS
    'F16 step-up permits. Exact policy identity plus request digest only; raw MCP arguments, results, OAuth tokens, and secrets are never retained.';
