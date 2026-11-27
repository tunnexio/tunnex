-- AI-UX-1: the MCP switch, several MCP servers per agent, group tool policy,
-- connection previews, the approvals inbox and filtered activity.

-- name: GetOrganizationMCPSetting :one
-- No row means MCP is off.
SELECT org_id, enabled, updated_by_user_id, created_at, updated_at
FROM organization_mcp_settings
WHERE org_id = sqlc.arg(org_id);

-- name: UpsertOrganizationMCPSetting :one
INSERT INTO organization_mcp_settings (org_id, enabled, updated_by_user_id)
VALUES (sqlc.arg(org_id), sqlc.arg(enabled), sqlc.narg(updated_by_user_id))
ON CONFLICT (org_id) DO UPDATE
SET enabled = EXCLUDED.enabled, updated_by_user_id = EXCLUDED.updated_by_user_id
RETURNING org_id, enabled, updated_by_user_id, created_at, updated_at;

-- name: CountActiveAgentMCPAssignments :one
-- Turning MCP off is refused while this is not zero.
SELECT count(*)
FROM agent_mcp_profile_assignments a
WHERE a.org_id = sqlc.arg(org_id) AND a.state = 'active';

-- name: ListAgentMCPServersForDevice :many
-- Every MCP server an agent inherits from its groups, first one first: "first"
-- is the earliest active assignment (assigned_at, then id). The same profile
-- reached through two groups appears once per group; the caller keeps the
-- earliest.
SELECT a.id AS assignment_id, a.assigned_at, a.agent_group_id, g.name AS group_name,
       p.id AS profile_id, p.name AS profile_name, p.server_name, p.endpoint
FROM agent_group_members m
JOIN agent_mcp_profile_assignments a
  ON a.org_id = m.org_id AND a.agent_group_id = m.agent_group_id AND a.state = 'active'
JOIN agent_mcp_profiles p ON p.id = a.profile_id AND p.org_id = a.org_id
JOIN agent_groups g ON g.id = a.agent_group_id AND g.org_id = a.org_id
WHERE m.org_id = sqlc.arg(org_id) AND m.device_id = sqlc.arg(device_id)
ORDER BY a.assigned_at, a.id;

-- name: ListAgentMCPServersForGroup :many
-- The MCP servers assigned to one group, first one first.
SELECT a.id AS assignment_id, a.assigned_at,
       p.id AS profile_id, p.name AS profile_name, p.server_name, p.endpoint
FROM agent_mcp_profile_assignments a
JOIN agent_mcp_profiles p ON p.id = a.profile_id AND p.org_id = a.org_id
WHERE a.org_id = sqlc.arg(org_id) AND a.agent_group_id = sqlc.arg(agent_group_id) AND a.state = 'active'
ORDER BY a.assigned_at, a.id;

-- name: GetActiveAgentMCPProfileByServerName :one
SELECT * FROM agent_mcp_profiles
WHERE org_id = sqlc.arg(org_id) AND server_name = sqlc.arg(server_name) AND archived_at IS NULL;

-- name: CreateAgentMCPProfileNamed :one
-- An empty server_name lets the database derive one from the display name.
INSERT INTO agent_mcp_profiles (org_id, name, endpoint, server_name)
VALUES (sqlc.arg(org_id), sqlc.arg(name), sqlc.arg(endpoint), sqlc.arg(server_name))
RETURNING *;

-- name: GetAgentMCPToolPolicyOverrideEndpoints :one
-- The endpoints the agent's own policy decides for: those named by its latest
-- version. No row means the agent has no policy of its own.
SELECT v.version, v.override_endpoints
FROM agent_mcp_tool_policy_versions v
WHERE v.org_id = sqlc.arg(org_id) AND v.device_id = sqlc.arg(device_id)
ORDER BY v.version DESC
LIMIT 1;

-- name: GetLatestAgentGroupMCPToolPolicy :one
SELECT v.id, v.org_id, v.agent_group_id, v.profile_id, v.version, v.rules, v.inventory_observed_at,
       v.created_by_user_id, v.created_at
FROM agent_group_mcp_tool_policy_versions v
WHERE v.org_id = sqlc.arg(org_id)
  AND v.agent_group_id = sqlc.arg(agent_group_id)
  AND v.profile_id = sqlc.arg(profile_id)
ORDER BY v.version DESC
LIMIT 1;

-- name: InsertAgentGroupMCPToolPolicyVersion :one
-- The caller holds the group row lock and passes the next version.
INSERT INTO agent_group_mcp_tool_policy_versions (
    org_id, agent_group_id, profile_id, version, rules, inventory_observed_at, created_by_user_id
) VALUES (
    sqlc.arg(org_id), sqlc.arg(agent_group_id), sqlc.arg(profile_id), sqlc.arg(version),
    sqlc.arg(rules)::jsonb, sqlc.arg(inventory_observed_at), sqlc.arg(created_by_user_id)
)
RETURNING id, org_id, agent_group_id, profile_id, version, rules, inventory_observed_at,
          created_by_user_id, created_at;

-- name: ListLatestAgentGroupMCPToolPoliciesForDevice :many
-- The group policy that applies to each of an agent's MCP servers, in server
-- order (earliest assignment first). A server with no group policy yet has a
-- NULL version: no policy means deny.
SELECT a.id AS assignment_id, a.assigned_at, a.agent_group_id, p.id AS profile_id, p.server_name, p.endpoint,
       v.version, v.rules, v.inventory_observed_at, v.created_at AS policy_created_at
FROM agent_group_members m
JOIN agent_mcp_profile_assignments a
  ON a.org_id = m.org_id AND a.agent_group_id = m.agent_group_id AND a.state = 'active'
JOIN agent_mcp_profiles p ON p.id = a.profile_id AND p.org_id = a.org_id
LEFT JOIN LATERAL (
    SELECT gv.version, gv.rules, gv.inventory_observed_at, gv.created_at
    FROM agent_group_mcp_tool_policy_versions gv
    WHERE gv.org_id = a.org_id AND gv.agent_group_id = a.agent_group_id AND gv.profile_id = a.profile_id
    ORDER BY gv.version DESC
    LIMIT 1
) v ON true
WHERE m.org_id = sqlc.arg(org_id) AND m.device_id = sqlc.arg(device_id)
ORDER BY a.assigned_at, a.id;

-- name: ListAgentMCPToolMarkers :many
SELECT org_id, profile_id, tool_name, effect, set_by_user_id, created_at, updated_at
FROM agent_mcp_tool_markers
WHERE org_id = sqlc.arg(org_id) AND profile_id = sqlc.arg(profile_id)
ORDER BY tool_name;

-- name: UpsertAgentMCPToolMarker :one
INSERT INTO agent_mcp_tool_markers (org_id, profile_id, tool_name, effect, set_by_user_id)
VALUES (sqlc.arg(org_id), sqlc.arg(profile_id), sqlc.arg(tool_name), sqlc.arg(effect), sqlc.narg(set_by_user_id))
ON CONFLICT (profile_id, tool_name) DO UPDATE
SET effect = EXCLUDED.effect, set_by_user_id = EXCLUDED.set_by_user_id
WHERE agent_mcp_tool_markers.org_id = EXCLUDED.org_id
RETURNING org_id, profile_id, tool_name, effect, set_by_user_id, created_at, updated_at;

-- name: DeleteAgentMCPToolMarker :execrows
DELETE FROM agent_mcp_tool_markers
WHERE org_id = sqlc.arg(org_id) AND profile_id = sqlc.arg(profile_id) AND tool_name = sqlc.arg(tool_name);

-- name: CreateAgentMCPConnectionPreview :one
INSERT INTO agent_mcp_connection_previews (
    org_id, endpoint, via_device_id, via_group_id, node_id, requested_by_user_id, expires_at
) VALUES (
    sqlc.arg(org_id), sqlc.arg(endpoint), sqlc.narg(via_device_id), sqlc.narg(via_group_id),
    sqlc.narg(node_id), sqlc.narg(requested_by_user_id), sqlc.arg(expires_at)
)
RETURNING *;

-- name: GetAgentMCPConnectionPreview :one
-- An expired preview is not found.
SELECT * FROM agent_mcp_connection_previews
WHERE id = sqlc.arg(id) AND org_id = sqlc.arg(org_id) AND expires_at > now();

-- name: ListWaitingAgentMCPConnectionPreviewsForNode :many
-- The addresses a gateway is asked to read the tool list of on its next
-- discovery pass.
SELECT id, endpoint
FROM agent_mcp_connection_previews
WHERE org_id = sqlc.arg(org_id) AND node_id = sqlc.arg(node_id)
  AND state = 'waiting' AND expires_at > now()
ORDER BY created_at, id;

-- name: CompleteAgentMCPConnectionPreview :execrows
-- Records what the gateway read, once, and only for the gateway that was asked.
UPDATE agent_mcp_connection_previews
SET state = sqlc.arg(state),
    failure_reason = sqlc.arg(failure_reason),
    server_name = sqlc.arg(server_name),
    tools = sqlc.arg(tools)::jsonb,
    observed_at = now()
WHERE id = sqlc.arg(id) AND org_id = sqlc.arg(org_id) AND node_id = sqlc.arg(node_id)
  AND state = 'waiting' AND expires_at > now();

-- name: DeleteExpiredAgentMCPConnectionPreviews :execrows
-- lint:cross-org — housekeeping sweep over every organization; it selects by age only and returns nothing.
DELETE FROM agent_mcp_connection_previews
WHERE expires_at < sqlc.arg(cutoff);

-- name: ListOrganizationMCPToolApprovalRequests :many
-- The Approvals inbox: every agent's requests, newest first. Keyset: pass the
-- last row's requested_at and id. only_pending lists live pending requests.
-- lint:allow-deleted — the owner stays named after their account is removed; the agent must be current.
SELECT r.id, r.org_id, r.device_id, r.policy_version, r.policy_source, r.policy_group_id, r.endpoint,
       r.server_name, r.tool_name, r.input_schema_hash, r.request_digest, r.state, r.requested_at,
       r.expires_at, r.approved_by_user_id, r.approved_at, r.denied_by_user_id, r.denied_at, r.consumed_at,
       r.arguments, r.arguments_truncated, r.tool_definition_hash,
       d.name AS agent_name, u.email AS owner_email
FROM agent_mcp_tool_approval_requests r
JOIN devices d ON d.id = r.device_id AND d.org_id = r.org_id
LEFT JOIN users u ON u.id = d.user_id
WHERE r.org_id = sqlc.arg(org_id)
  AND d.kind = 'agent'
  AND d.deleted_at IS NULL
  AND (NOT sqlc.arg(only_pending)::boolean OR (r.state = 'pending' AND r.expires_at > now()))
  AND (sqlc.narg(before_requested_at)::timestamptz IS NULL
       OR (r.requested_at, r.id) < (sqlc.narg(before_requested_at)::timestamptz, sqlc.narg(before_id)::uuid))
ORDER BY r.requested_at DESC, r.id DESC
LIMIT sqlc.arg(page_limit);

-- name: CountPendingOrganizationMCPToolApprovalRequests :one
-- The sidebar count: live pending requests of current agents.
SELECT count(*)
FROM agent_mcp_tool_approval_requests r
JOIN devices d ON d.id = r.device_id AND d.org_id = r.org_id
WHERE r.org_id = sqlc.arg(org_id)
  AND d.kind = 'agent'
  AND d.deleted_at IS NULL
  AND r.state = 'pending'
  AND r.expires_at > now();

-- name: GetAgentMCPToolApprovalRequestState :one
-- What a held call waits on. Scoped to the agent the gateway identified.
SELECT r.id, r.state, r.expires_at
FROM agent_mcp_tool_approval_requests r
WHERE r.id = sqlc.arg(id) AND r.org_id = sqlc.arg(org_id) AND r.device_id = sqlc.arg(device_id);

-- name: ListAgentMCPToolActivityFiltered :many
-- The agent Activity tab with filters, newest first. Keyset: pass the last
-- row's occurred_at and id. Every filter is optional. approved_only keeps calls
-- that ran on an approval. The approver and time come from the approval row.
-- lint:allow-deleted — the approver stays named after their account is removed; the agent must be current.
SELECT a.id, a.org_id, a.device_id, a.node_id, a.endpoint, a.server_name, a.method, a.tool_name,
       a.arguments_digest, a.decision, a.reason, a.policy_version, a.policy_source, a.policy_group_id,
       a.approval_request_id, a.result_status, a.upstream_http_status, a.occurred_at, a.completed_at,
       a.created_at,
       r.state AS approval_state, r.approved_by_user_id, r.approved_at, approver.email AS approved_by_email
FROM agent_mcp_tool_activity a
JOIN devices d ON d.id = a.device_id
LEFT JOIN agent_mcp_tool_approval_requests r ON r.id = a.approval_request_id AND r.org_id = a.org_id
LEFT JOIN users approver ON approver.id = r.approved_by_user_id
WHERE a.org_id = sqlc.arg(org_id)
  AND a.device_id = sqlc.arg(device_id)
  AND d.org_id = sqlc.arg(org_id)
  AND d.kind = 'agent'
  AND d.deleted_at IS NULL
  AND (sqlc.narg(decision)::text IS NULL OR a.decision = sqlc.narg(decision)::text)
  AND (NOT sqlc.arg(approved_only)::boolean OR (a.decision = 'allow' AND a.approval_request_id IS NOT NULL))
  AND (sqlc.narg(endpoint)::text IS NULL OR a.endpoint = sqlc.narg(endpoint)::text)
  AND (sqlc.narg(occurred_from)::timestamptz IS NULL OR a.occurred_at >= sqlc.narg(occurred_from)::timestamptz)
  AND (sqlc.narg(occurred_to)::timestamptz IS NULL OR a.occurred_at < sqlc.narg(occurred_to)::timestamptz)
  AND (sqlc.narg(before_occurred_at)::timestamptz IS NULL
       OR (a.occurred_at, a.id) < (sqlc.narg(before_occurred_at)::timestamptz, sqlc.narg(before_id)::uuid))
ORDER BY a.occurred_at DESC, a.id DESC
LIMIT sqlc.arg(page_limit);

-- name: GetAgentBootstrapTokenStatus :one
-- The install step's live status for one token the organization issued:
-- whether it was used, by which agent, and that agent's tunnel facts from the
-- same sources as the agents list (the gateway's status push, with the
-- reporter's own clock). The token hash is deliberately not selected.
SELECT t.id, t.agent_name, t.gateway_node_id, t.created_at, t.expires_at, t.consumed_at, t.revoked_at,
       t.consumed_device_id,
       d.id AS device_id, d.status AS device_status,
       ds.last_handshake_at, ds.updated_at AS status_reported_at, n.last_seen_at AS gateway_last_seen_at
FROM agent_bootstrap_tokens t
LEFT JOIN devices d
  ON d.id = t.consumed_device_id AND d.org_id = t.org_id AND d.kind = 'agent' AND d.deleted_at IS NULL
LEFT JOIN device_status ds ON ds.device_id = d.id
LEFT JOIN nodes n ON n.id = d.node_id AND n.org_id = t.org_id
WHERE t.id = sqlc.arg(id) AND t.org_id = sqlc.arg(org_id);

-- name: MarkAgentRuntimeMCPHoldCapable :execrows
-- The runtime declared (poll query mcp_hold=true) that it keeps an MCP call
-- open while an "Ask first" request waits. Recorded on every declaring poll so
-- the value is also a freshness signal. Never cleared by a poll that omits it.
UPDATE agent_runtime_state ars
SET mcp_hold_capable_at = now()
FROM devices d
WHERE d.id = ars.device_id
  AND ars.device_id = sqlc.arg(device_id)
  AND d.org_id = sqlc.arg(org_id)
  AND d.kind = 'agent'
  AND d.deleted_at IS NULL;

-- name: SetAgentRuntimeTunnelDNSApplied :execrows
-- The runtime reported whether it wrote the pushed DNS servers into its tunnel
-- configuration (false: the host has no resolvconf).
UPDATE agent_runtime_state ars
SET tunnel_dns_applied = sqlc.arg(tunnel_dns_applied)
FROM devices d
WHERE d.id = ars.device_id
  AND ars.device_id = sqlc.arg(device_id)
  AND d.org_id = sqlc.arg(org_id)
  AND d.kind = 'agent'
  AND d.deleted_at IS NULL
  AND ars.tunnel_dns_applied IS DISTINCT FROM sqlc.arg(tunnel_dns_applied);

-- name: GetAgentRuntimeDeclarations :one
-- What the runtime has declared about itself beyond its revisions.
SELECT ars.device_id, ars.mcp_gateway_capable_at, ars.mcp_hold_capable_at, ars.tunnel_dns_applied
FROM agent_runtime_state ars
JOIN devices d ON d.id = ars.device_id
WHERE ars.device_id = sqlc.arg(device_id)
  AND d.org_id = sqlc.arg(org_id)
  AND d.kind = 'agent'
  AND d.deleted_at IS NULL;
