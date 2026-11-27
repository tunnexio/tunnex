-- AI-UX-1: the agent Access tab (what an agent can reach now) and "create rules from the owner's access".
-- Read-only. Rules are created through the policy service's rule insert, never from here.

-- name: GetAgentAccessOwner :one
-- The agent and the person its access can be copied from. The owner columns are NULL when the owner's
-- account is gone or is no longer a member of this organization: there is then nobody to copy from.
SELECT d.id AS device_id, d.name AS agent_name,
       m.user_id AS owner_user_id, u.email AS owner_email
FROM devices d
LEFT JOIN users u ON u.id = d.user_id AND u.deleted_at IS NULL
LEFT JOIN memberships m
  ON m.org_id = d.org_id AND m.user_id = u.id AND m.access_revoked_at IS NULL
WHERE d.org_id = sqlc.arg(org_id) AND d.id = sqlc.arg(device_id)
  AND d.kind = 'agent' AND d.deleted_at IS NULL;

-- name: ListAccessRulesForSubjects :many
-- Unexpired rules whose source is the given agent (the agent itself or an agent group it is in), or the
-- given person (the person or a user group they are in), with the destination named. Pass only the subject
-- wanted; a NULL subject matches nothing. An archived agent group contributes no rule, like the compiler.
SELECT p.id AS rule_id, p.src_kind, p.created_at, p.expires_at, p.disabled,
       p.src_group_id, sg.name AS src_group_name,
       p.src_agent_group_id, ag.name AS src_agent_group_name,
       p.dst_kind,
       p.dst_resource_id, r.name AS resource_name, r.cidr AS resource_cidr,
       r.protocol AS resource_protocol, r.port_low AS resource_port_low, r.port_high AS resource_port_high,
       p.dst_group_id, dg.name AS dst_group_name,
       p.dst_site_id, s.name AS site_name,
       p.dst_k8s_service_id, ks.name AS k8s_service_name, ks.namespace AS k8s_service_namespace,
       ks.protocol AS k8s_service_protocol, ks.port_low AS k8s_service_port_low, ks.port_high AS k8s_service_port_high,
       p.dst_k8s_cluster_id, kc.name AS k8s_cluster_name,
       p.dst_fqdn_resource_id, fr.name AS fqdn_name, fr.fqdn AS fqdn_host,
       fr.protocol AS fqdn_protocol, fr.port_low AS fqdn_port_low, fr.port_high AS fqdn_port_high,
       ae.cluster_id AS k8s_api_cluster_id, akc.name AS k8s_api_cluster_name
FROM policy_rules p
LEFT JOIN user_groups sg ON sg.id = p.src_group_id AND sg.org_id = p.org_id
LEFT JOIN agent_groups ag ON ag.id = p.src_agent_group_id AND ag.org_id = p.org_id
LEFT JOIN resources r ON r.id = p.dst_resource_id AND r.org_id = p.org_id
LEFT JOIN user_groups dg ON dg.id = p.dst_group_id AND dg.org_id = p.org_id
LEFT JOIN sites s ON s.id = p.dst_site_id AND s.org_id = p.org_id
LEFT JOIN k8s_services ks ON ks.id = p.dst_k8s_service_id AND ks.org_id = p.org_id AND ks.deleted_at IS NULL
LEFT JOIN k8s_clusters kc ON kc.id = p.dst_k8s_cluster_id AND kc.org_id = p.org_id
LEFT JOIN fqdn_resources fr ON fr.id = p.dst_fqdn_resource_id AND fr.org_id = p.org_id
LEFT JOIN k8s_api_endpoints ae ON ae.id = p.dst_k8s_api_endpoint_id AND ae.org_id = p.org_id
LEFT JOIN k8s_clusters akc ON akc.id = ae.cluster_id AND akc.org_id = ae.org_id
WHERE p.org_id = sqlc.arg(org_id)
  AND (p.expires_at IS NULL OR p.expires_at > now())
  AND (
    (sqlc.narg(device_id)::uuid IS NOT NULL AND (
        p.src_device_id = sqlc.narg(device_id)::uuid
        OR p.src_agent_group_id IN (
            SELECT m.agent_group_id
            FROM agent_group_members m
            JOIN agent_groups g ON g.id = m.agent_group_id AND g.org_id = m.org_id
            WHERE m.org_id = sqlc.arg(org_id) AND m.device_id = sqlc.narg(device_id)::uuid
              AND g.archived_at IS NULL)))
    OR
    (sqlc.narg(user_id)::uuid IS NOT NULL AND (
        p.src_user_id = sqlc.narg(user_id)::uuid
        OR p.src_group_id IN (
            SELECT gm.group_id FROM group_members gm
            WHERE gm.org_id = sqlc.arg(org_id) AND gm.user_id = sqlc.narg(user_id)::uuid)))
  )
ORDER BY p.created_at, p.id
LIMIT 2000;
