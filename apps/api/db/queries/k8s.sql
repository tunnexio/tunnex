-- S10.3: Kubernetes cluster + exposed-Service queries. Org-scoped (tenant isolation).

-- name: GetK8sClusterForConnectorPoolConfigForUpdate :one
-- Configuration serializes on the exact cluster before it looks up or creates
-- its one cluster-owned pool. Site scope is intentional: a configuration
-- caller must prove the full org/site/cluster relationship at the mutation
-- boundary, rather than treating a globally unique cluster ID as authority.
SELECT *
FROM k8s_clusters
WHERE org_id = sqlc.arg(org_id)
  AND site_id = sqlc.arg(site_id)
  AND id = sqlc.arg(cluster_id)
FOR UPDATE;

-- name: GetK8sConnectorPoolForClusterForConfigForUpdate :one
SELECT *
FROM k8s_connector_pools
WHERE org_id = sqlc.arg(org_id)
  AND site_id = sqlc.arg(site_id)
  AND cluster_id = sqlc.arg(cluster_id)
FOR UPDATE;

-- name: GetK8sConnectorPoolForClusterForConfig :one
SELECT p.*
FROM k8s_connector_pools p
JOIN k8s_clusters c
  ON c.id = p.cluster_id
 AND c.org_id = p.org_id
 AND c.site_id = p.site_id
 AND c.connector_pool_id = p.id
WHERE p.org_id = sqlc.arg(org_id)
  AND p.site_id = sqlc.arg(site_id)
  AND p.cluster_id = sqlc.arg(cluster_id);

-- name: ListK8sConnectorPoolMembersForConfigForUpdate :many
SELECT m.pool_id, m.org_id, m.site_id, m.node_id, m.admin_priority, m.created_at, m.updated_at
FROM k8s_connector_pool_members m
JOIN k8s_connector_pools p
  ON p.id = m.pool_id
 AND p.org_id = m.org_id
 AND p.site_id = m.site_id
WHERE m.org_id = sqlc.arg(org_id)
  AND m.site_id = sqlc.arg(site_id)
  AND m.pool_id = sqlc.arg(pool_id)
ORDER BY m.node_id
FOR UPDATE OF m;

-- name: ListK8sConnectorPoolMembersForConfig :many
SELECT m.pool_id, m.org_id, m.site_id, m.node_id, m.admin_priority, m.created_at, m.updated_at
FROM k8s_connector_pool_members m
JOIN k8s_connector_pools p
  ON p.id = m.pool_id
 AND p.org_id = m.org_id
 AND p.site_id = m.site_id
WHERE m.org_id = sqlc.arg(org_id)
  AND m.site_id = sqlc.arg(site_id)
  AND m.pool_id = sqlc.arg(pool_id)
ORDER BY m.admin_priority DESC, m.node_id;

-- name: CreateK8sConnectorPoolForConfig :one
-- A configuration may create only from the legacy single-selected-connector
-- mode. The initial pool keeps that exact connector as both preferred and
-- active; it neither performs a promotion nor changes generation.
WITH pool AS (
    INSERT INTO k8s_connector_pools (org_id, site_id, cluster_id, preferred_node_id, active_node_id)
    SELECT c.org_id, c.site_id, c.id, n.id, n.id
    FROM k8s_clusters c
    JOIN nodes n
      ON n.id = sqlc.arg(initial_connector_node_id)
     AND n.org_id = c.org_id
     AND n.site_id = c.site_id
    WHERE c.org_id = sqlc.arg(org_id)
      AND c.site_id = sqlc.arg(site_id)
      AND c.id = sqlc.arg(cluster_id)
      AND c.connector_pool_id IS NULL
      AND c.connector_node_id = n.id
    RETURNING *
), members AS (
    INSERT INTO k8s_connector_pool_members (pool_id, org_id, site_id, node_id)
    SELECT p.id, p.org_id, p.site_id, p.active_node_id
    FROM pool p
    RETURNING pool_id
)
SELECT p.* FROM pool p;

-- name: BindK8sClusterConnectorPoolFromLegacyForConfig :execrows
-- The bind is the one-way compatibility handoff inside the same transaction:
-- legacy connector_node_id becomes NULL only after a matching exact pool was
-- created with that connector as its unchanged active and preferred member.
UPDATE k8s_clusters c
SET connector_node_id = NULL,
    connector_pool_id = sqlc.arg(connector_pool_id)
WHERE c.org_id = sqlc.arg(org_id)
  AND c.site_id = sqlc.arg(site_id)
  AND c.id = sqlc.arg(cluster_id)
  AND c.connector_pool_id IS NULL
  AND c.connector_node_id = sqlc.arg(expected_connector_node_id)
  AND EXISTS (
      SELECT 1
      FROM k8s_connector_pools p
      WHERE p.id = sqlc.arg(connector_pool_id)
        AND p.org_id = c.org_id
        AND p.site_id = c.site_id
        AND p.cluster_id = c.id
        AND p.preferred_node_id = c.connector_node_id
        AND p.active_node_id = c.connector_node_id
  );

-- name: AddK8sConnectorPoolMemberForConfig :one
INSERT INTO k8s_connector_pool_members (pool_id, org_id, site_id, node_id, admin_priority)
SELECT p.id, p.org_id, p.site_id, n.id, sqlc.arg(admin_priority)
FROM k8s_connector_pools p
JOIN nodes n
  ON n.id = sqlc.arg(node_id)
 AND n.org_id = p.org_id
 AND n.site_id = p.site_id
WHERE p.id = sqlc.arg(pool_id)
  AND p.org_id = sqlc.arg(org_id)
  AND p.site_id = sqlc.arg(site_id)
RETURNING *;

-- name: SetK8sConnectorPoolMemberPriorityForConfig :one
UPDATE k8s_connector_pool_members m
SET admin_priority = sqlc.arg(admin_priority)
FROM k8s_connector_pools p
WHERE m.pool_id = p.id
  AND m.org_id = p.org_id
  AND m.site_id = p.site_id
  AND m.pool_id = sqlc.arg(pool_id)
  AND m.org_id = sqlc.arg(org_id)
  AND m.site_id = sqlc.arg(site_id)
  AND m.node_id = sqlc.arg(node_id)
  AND m.admin_priority IS DISTINCT FROM sqlc.arg(admin_priority)
RETURNING m.*;

-- name: DeleteK8sConnectorPoolMemberForConfig :execrows
DELETE FROM k8s_connector_pool_members m
USING k8s_connector_pools p
WHERE m.pool_id = p.id
  AND m.org_id = p.org_id
  AND m.site_id = p.site_id
  AND m.pool_id = sqlc.arg(pool_id)
  AND m.org_id = sqlc.arg(org_id)
  AND m.site_id = sqlc.arg(site_id)
  AND m.node_id = sqlc.arg(node_id);

-- name: ListK8sConnectorPoolMembersForOrg :many
SELECT m.pool_id, m.org_id, m.site_id, m.node_id, m.admin_priority, m.created_at, m.updated_at
FROM k8s_connector_pool_members m
JOIN k8s_connector_pools p ON p.id = m.pool_id AND p.org_id = m.org_id
WHERE m.org_id = $1 AND m.pool_id = $2
ORDER BY m.admin_priority DESC, m.node_id;

-- name: CreateK8sConnectorPoolHealthState :one
INSERT INTO k8s_connector_pool_health_states (
    org_id, site_id, cluster_id, pool_id, observed_active_node_id, observed_generation
)
SELECT p.org_id, p.site_id, p.cluster_id, p.id, p.active_node_id, p.generation
FROM k8s_connector_pools p
WHERE p.org_id = sqlc.arg(org_id)
  AND p.site_id = sqlc.arg(site_id)
  AND p.cluster_id = sqlc.arg(cluster_id)
  AND p.id = sqlc.arg(pool_id)
ON CONFLICT (pool_id) DO NOTHING
RETURNING *;

-- name: GetK8sConnectorPoolHealthState :one
SELECT *
FROM k8s_connector_pool_health_states
WHERE org_id = sqlc.arg(org_id)
  AND site_id = sqlc.arg(site_id)
  AND cluster_id = sqlc.arg(cluster_id)
  AND pool_id = sqlc.arg(pool_id);

-- name: GetK8sConnectorPoolHealthStateForUpdate :one
SELECT *
FROM k8s_connector_pool_health_states
WHERE org_id = sqlc.arg(org_id)
  AND site_id = sqlc.arg(site_id)
  AND cluster_id = sqlc.arg(cluster_id)
  AND pool_id = sqlc.arg(pool_id)
FOR UPDATE;


-- name: CreateK8sCluster :one
INSERT INTO k8s_clusters (org_id, site_id, connector_node_id, name, vip_range, service_cidr, dns_zone, dns_vip, managed_by_machine)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetK8sCluster :one
SELECT * FROM k8s_clusters WHERE org_id = $1 AND id = $2;

-- name: GetK8sClusterForConnectorSetForUpdate :one
-- The legacy setter and pool configuration take the same cluster lock. Once a
-- cluster enters pool mode, the direct connector setter must return a typed
-- conflict rather than falling through to the database mode constraint.
SELECT *
FROM k8s_clusters
WHERE org_id = sqlc.arg(org_id)
  AND id = sqlc.arg(cluster_id)
FOR UPDATE;

-- name: ListK8sClustersForOrg :many
SELECT * FROM k8s_clusters WHERE org_id = $1 ORDER BY name;

-- name: DeleteK8sCluster :exec
DELETE FROM k8s_clusters WHERE org_id = $1 AND id = $2;

-- name: SetK8sClusterConnector :execrows
UPDATE k8s_clusters
SET connector_node_id = $3
WHERE org_id = $1 AND id = $2 AND connector_pool_id IS NULL;

-- CountClusterCascade returns what a DeregisterCluster will destroy, for the audit trail (H2): the number of
-- LIVE exposed Services in the cluster, and the number of policy grants (rules) that reference ANY Service in
-- it. Both are FK ON DELETE CASCADE'd when the cluster row is deleted, so the audit must capture them BEFORE
-- the delete — a governance cascade must never vanish untraceably.
-- name: CountClusterCascade :one
SELECT
  (SELECT count(*) FROM k8s_services s WHERE s.cluster_id = $2 AND s.org_id = $1 AND s.deleted_at IS NULL) AS service_count,
  (SELECT count(*) FROM policy_rules r WHERE r.org_id = $1 AND r.dst_k8s_service_id IN (SELECT s2.id FROM k8s_services s2 WHERE s2.cluster_id = $2)) AS grant_count;

-- ListVIPRangesForOrg feeds the subnetguard collector: EVERY disjointness check (cluster-VIP creation,
-- pool resize, site-subnet approval) must include the org's VIP ranges so disjointness stays bidirectional
-- (the validator-input-filtering law). Returns the raw cidr text.
-- name: ListVIPRangesForOrg :many
SELECT vip_range::text AS vip_range FROM k8s_clusters WHERE org_id = $1;

-- ListK8sClusterZonesForOrg feeds (a) cross-mechanism one-zone-one-resolver enforcement (S10.3 (A)): a site
-- dns_forwarding domain must not collide with a K8s cluster's DNS zone (<cluster>.<dns_zone>), and vice versa;
-- and (b) the client-side resolver push (fork-1): the {<cluster>.<dns_zone> -> reserved DNS VIP} mapping the
-- routed-forwards channel hands split-tunnel/OVPN clients so they resolve exposed Service names.
-- name: ListK8sClusterZonesForOrg :many
SELECT name, dns_zone, COALESCE(host(dns_vip), '')::text AS dns_vip FROM k8s_clusters WHERE org_id = $1;

-- ListK8sServedZonesForOrg is the zones a connector ACTUALLY answers: a cluster with >=1 LIVE exposed Service
-- AND a resolved connector. A pool-bound cluster resolves only through its
-- exact org/site/cluster-owned pool and a positive generation; it never falls
-- back to the legacy connector column.
-- This is the SAME live-service set the agent's K8sDNSZones is built from (loadSiteTopology →
-- ListActiveK8sServicesForOrg), so the client resolver push (routedranges) and the gateway's own answer set
-- agree BY CONSTRUCTION (L2): a zone the gateway would REFUSE for (no Service yet) is never handed to a client
-- as a resolver. DISTINCT collapses a multi-Service cluster to one zone row.
-- name: ListK8sServedZonesForOrg :many
SELECT DISTINCT c.name, c.dns_zone, COALESCE(host(c.dns_vip), '')::text AS dns_vip
FROM k8s_clusters c
JOIN k8s_services s ON s.cluster_id = c.id AND s.deleted_at IS NULL
LEFT JOIN k8s_connector_pools p
  ON p.id = c.connector_pool_id
 AND p.org_id = c.org_id
 AND p.site_id = c.site_id
 AND p.cluster_id = c.id
LEFT JOIN nodes connector
  ON connector.id = p.active_node_id
 AND connector.org_id = p.org_id
 AND connector.site_id = p.site_id
 AND connector.status = 'active'
 AND connector.revoked_at IS NULL
 AND connector.wg_public_key ~ '^[A-Za-z0-9+/]{43}=$'
 AND btrim(connector.endpoint) <> ''
WHERE c.org_id = $1
  AND (
    (c.connector_pool_id IS NULL AND c.connector_node_id IS NOT NULL)
    OR (c.connector_pool_id IS NOT NULL AND connector.id IS NOT NULL AND p.generation > 0)
  );

-- name: CreateK8sService :one
INSERT INTO k8s_services (org_id, cluster_id, name, namespace, protocol, port_low, port_high, vip, managed_by_machine)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetK8sService :one
SELECT * FROM k8s_services WHERE org_id = $1 AND id = $2 AND deleted_at IS NULL;

-- Immutable F09 template versions retain their destination identity. A soft
-- unexpose must refuse before it would turn a reusable template into a silent
-- no-op; the released confirmation reads the same server-owned count.
-- name: CountAgentPolicyTemplateK8sServiceReferences :one
SELECT count(DISTINCT template_version_id)
FROM agent_policy_template_version_items
WHERE org_id = $1 AND dst_k8s_service_id = $2;

-- ListUsedVIPsInCluster returns the LIVE VIPs in a cluster (the used-set ipalloc allocates around).
-- org_id-scoped for tenant isolation (defence-in-depth; the caller already authorized the cluster).
-- name: ListUsedVIPsInCluster :many
SELECT host(vip) AS vip FROM k8s_services WHERE org_id = $1 AND cluster_id = $2 AND deleted_at IS NULL;

-- ListActiveK8sServicesForOrg is the compiler's resolution source: id -> current VIP (+ proto/ports), LIVE
-- only. A soft-deleted Service is absent, so a grant referencing it compiles to nothing (honest, not silent).
-- Pool mode keeps legacy and active-pool columns separate. Callers must reject
-- a pool-bound row without its exact active member and positive generation.
-- name: ListActiveK8sServicesForOrg :many
SELECT s.id, s.cluster_id, s.name, s.namespace, s.protocol, s.port_low, s.port_high, s.managed_by_machine,
       host(s.vip) AS vip, c.site_id, c.connector_pool_id,
       c.connector_node_id AS legacy_connector_node_id,
       p.active_node_id AS pool_active_node_id,
       COALESCE(p.generation > 0 AND connector.id IS NOT NULL, false)::boolean AS pool_connector_eligible,
       p.generation AS connector_generation,
       host(c.vip_range) AS vip_range, c.service_cidr::text AS service_cidr,
       c.name AS cluster_name, c.dns_zone, COALESCE(host(c.dns_vip), '')::text AS dns_vip
FROM k8s_services s
JOIN k8s_clusters c ON c.id = s.cluster_id
LEFT JOIN k8s_connector_pools p
  ON p.id = c.connector_pool_id
 AND p.org_id = c.org_id
 AND p.site_id = c.site_id
 AND p.cluster_id = c.id
LEFT JOIN nodes connector
  ON connector.id = p.active_node_id
 AND connector.org_id = p.org_id
 AND connector.site_id = p.site_id
 AND connector.status = 'active'
 AND connector.revoked_at IS NULL
 AND connector.wg_public_key ~ '^[A-Za-z0-9+/]{43}=$'
 AND btrim(connector.endpoint) <> ''
WHERE s.org_id = $1 AND s.deleted_at IS NULL
ORDER BY s.id;

-- name: SoftDeleteK8sService :exec
UPDATE k8s_services SET deleted_at = now() WHERE org_id = $1 AND id = $2 AND deleted_at IS NULL;
