-- name: ListScopedSandboxTerminalRoutes :many
-- Only explicitly pinned, current active sandbox/terminal pairs provide routes.
-- Transport carries no grant and does not include the historical reservation.
SELECT r.sandbox_id,r.terminal_gateway_id,r.runtime_gateway_id,
 r.terminal_gateway_endpoint,r.runtime_gateway_endpoint,
 COALESCE(h.assigned_ip,'')::text AS terminal_address,COALESCE(d.assigned_ip,'')::text AS sandbox_address,
 terminal.wg_public_key AS terminal_public_key,runtime.wg_public_key AS runtime_public_key
FROM sandbox_remote_terminal_routes r
JOIN sandboxes s ON s.id=r.sandbox_id AND s.org_id=r.org_id AND s.terminal_device_id=r.terminal_device_id AND s.local_terminal_gateway_id IS NULL
JOIN sandbox_templates t ON t.id=s.template_id AND t.org_id=s.org_id AND t.enabled AND t.maximum_scope='[]'::jsonb
JOIN organizations o ON o.id=s.org_id AND o.deleted_at IS NULL AND o.sandboxes_enabled AND o.zero_trust_mode='enforcing'
JOIN memberships m ON m.org_id=s.org_id AND m.user_id=s.creator_id AND m.access_revoked_at IS NULL AND COALESCE(m.roles,ARRAY[m.role]) && ARRAY['member','admin','owner']::text[]
JOIN users u ON u.id=s.creator_id AND u.status='active' AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL AND NOT u.must_change_password
JOIN devices h ON h.id=r.terminal_device_id AND h.org_id=s.org_id AND h.user_id=s.creator_id AND h.node_id=r.terminal_gateway_id AND h.kind='human' AND h.status='active' AND h.deleted_at IS NULL AND NOT h.health_blocked
JOIN devices d ON d.id=s.peer_id AND d.org_id=s.org_id AND d.user_id=s.creator_id AND d.node_id=r.runtime_gateway_id AND d.kind='sandbox' AND d.status='active' AND d.deleted_at IS NULL AND NOT d.health_blocked
JOIN nodes terminal ON terminal.id=r.terminal_gateway_id AND terminal.org_id=s.org_id AND terminal.status='active'
JOIN nodes runtime ON runtime.id=r.runtime_gateway_id AND runtime.org_id=s.org_id AND runtime.status='active'
WHERE r.org_id=$1 AND s.desired_state='started' AND s.observed_state IN ('creating','starting','ready')
 AND s.requested_scope='[]'::jsonb AND s.expires_at>now() AND sandbox_delegation_valid(s.id)
 AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(s.selected_skills) selection
 LEFT JOIN sandbox_skill_revisions sr ON sr.id=(selection->>'revision_id')::uuid AND sr.org_id=s.org_id AND sr.enabled
 LEFT JOIN sandbox_template_skills a ON a.org_id=s.org_id AND a.template_id=s.template_id AND a.revision_id=sr.id
 LEFT JOIN sandbox_custom_skills c ON c.id=sr.custom_skill_id AND c.org_id=s.org_id AND c.owner_id=s.creator_id AND c.deleted_at IS NULL
 WHERE sr.id IS NULL OR (sr.owner_id IS NULL AND a.revision_id IS NULL) OR (sr.owner_id IS NOT NULL AND (sr.owner_id<>s.creator_id OR c.id IS NULL)))
 AND h.assigned_ip IS NOT NULL AND d.assigned_ip IS NOT NULL
 AND EXISTS(SELECT 1 FROM sandbox_runtime_credentials c WHERE c.sandbox_id=s.id AND c.org_id=s.org_id AND c.peer_id=d.id AND c.revoked_at IS NULL)
ORDER BY r.sandbox_id LIMIT 33;

-- name: ListReservedSandboxRuntimeGateways :many
-- Immutable remote identity reserves a dedicated runtime even when its
-- corridor is withdrawn. It must never fall back to broad client carriage.
SELECT DISTINCT r.runtime_gateway_id,n.site_id
FROM sandbox_remote_terminal_routes r
JOIN nodes n ON n.id=r.runtime_gateway_id AND n.org_id=r.org_id AND n.status='active'
WHERE r.org_id=$1
ORDER BY r.runtime_gateway_id LIMIT 33;
