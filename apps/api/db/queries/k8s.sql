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
INSERT INTO k8s_clusters (org_id, site_id, connector_node_id, name, vip_range, service_cidr, dns_zone, dns_vip, managed_by_machine, provider, platform)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, sqlc.arg(provider), sqlc.arg(platform))
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

-- name: SetK8sClusterProviderMetadata :one
UPDATE k8s_clusters
SET provider = sqlc.arg(provider), platform = sqlc.arg(platform)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(cluster_id)
RETURNING *;

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
    OR (
      c.connector_pool_id IS NOT NULL AND connector.id IS NOT NULL AND p.generation > 0
      AND (
        p.generation = 1
        OR EXISTS (
          SELECT 1
          FROM k8s_connector_handoff_operations hop
          WHERE hop.org_id = p.org_id
            AND hop.site_id = p.site_id
            AND hop.cluster_id = p.cluster_id
            AND hop.pool_id = p.id
            AND hop.new_node_id = p.active_node_id
            AND hop.target_generation = p.generation
            AND hop.phase = 'complete'
        )
      )
    )
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
       COALESCE(
         p.generation > 0
         AND connector.id IS NOT NULL
         AND (
           p.generation = 1
           OR EXISTS (
             SELECT 1
             FROM k8s_connector_handoff_operations hop
             WHERE hop.org_id = p.org_id
               AND hop.site_id = p.site_id
               AND hop.cluster_id = p.cluster_id
               AND hop.pool_id = p.id
               AND hop.new_node_id = p.active_node_id
               AND hop.target_generation = p.generation
               AND hop.phase = 'complete'
           )
         ), false
       )::boolean AS pool_connector_eligible,
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


-- name: CreateK8sConnectorPool :one
WITH pool AS (
    INSERT INTO k8s_connector_pools (org_id, site_id, cluster_id, preferred_node_id, active_node_id)
    SELECT c.org_id, c.site_id, c.id, preferred.id, active.id
    FROM k8s_clusters c
    JOIN nodes preferred ON preferred.id = sqlc.arg(preferred_node_id) AND preferred.org_id = c.org_id AND preferred.site_id = c.site_id
    JOIN nodes active ON active.id = sqlc.arg(active_node_id) AND active.org_id = c.org_id AND active.site_id = c.site_id
    WHERE c.id = sqlc.arg(cluster_id) AND c.org_id = sqlc.arg(org_id)
    RETURNING *
), members AS (
    INSERT INTO k8s_connector_pool_members (pool_id, org_id, site_id, node_id)
    SELECT p.id, p.org_id, p.site_id, n.id
    FROM pool p
    JOIN nodes n ON n.id IN (p.preferred_node_id, p.active_node_id)
    RETURNING pool_id
)
SELECT p.* FROM pool p;

-- name: GetK8sConnectorPoolForOrg :one
SELECT * FROM k8s_connector_pools WHERE org_id = $1 AND id = $2;

-- name: GetK8sConnectorPoolForPromotion :one
-- A promotion holds the exact pool row while it rechecks its observed active
-- member and generation. Site scope is explicit even though pool ID is unique:
-- a caller must never mutate an org peer's same-ID state by omission.
SELECT *
FROM k8s_connector_pools
WHERE org_id = sqlc.arg(org_id)
  AND site_id = sqlc.arg(site_id)
  AND id = sqlc.arg(pool_id)
FOR UPDATE;

-- name: ListK8sConnectorPoolMembersForPromotion :many
-- Lock the current member set too. This makes the source and selected target
-- membership evidence stable through the active-state CAS and audit append.
SELECT m.pool_id, m.org_id, m.site_id, m.node_id, m.admin_priority, m.created_at, m.updated_at
FROM k8s_connector_pool_members m
JOIN k8s_connector_pools p
  ON p.id = m.pool_id AND p.org_id = m.org_id AND p.site_id = m.site_id
WHERE m.org_id = sqlc.arg(org_id)
  AND m.site_id = sqlc.arg(site_id)
  AND m.pool_id = sqlc.arg(pool_id)
FOR UPDATE OF m;

-- name: AddK8sConnectorPoolMember :one
INSERT INTO k8s_connector_pool_members (pool_id, org_id, site_id, node_id, admin_priority)
SELECT p.id, p.org_id, p.site_id, n.id, sqlc.arg(admin_priority)
FROM k8s_connector_pools p
JOIN nodes n ON n.id = sqlc.arg(node_id) AND n.org_id = p.org_id AND n.site_id = p.site_id
WHERE p.id = sqlc.arg(pool_id) AND p.org_id = sqlc.arg(org_id)
RETURNING *;

-- name: SetK8sConnectorPoolState :one
-- Expected-active-and-generation compare-and-swap is the persistence fence.
-- A stale reconciler affects zero rows; it must not overwrite a newer promotion.
UPDATE k8s_connector_pools p
SET active_node_id = sqlc.arg(active_node_id),
    generation = p.generation + 1,
    updated_at = now()
WHERE p.org_id = sqlc.arg(org_id)
  AND p.site_id = sqlc.arg(site_id)
  AND p.id = sqlc.arg(pool_id)
  AND p.generation = sqlc.arg(expected_generation)
  AND p.active_node_id = sqlc.arg(expected_active_node_id)
  AND EXISTS (SELECT 1 FROM k8s_connector_pool_members m WHERE m.pool_id = p.id AND m.org_id = p.org_id AND m.site_id = p.site_id AND m.node_id = sqlc.arg(active_node_id))
RETURNING *;

-- name: BindK8sClusterConnectorPool :execrows
-- Do not let a pool bind silently replace the legacy selected connector.
UPDATE k8s_clusters c
SET connector_pool_id = sqlc.arg(connector_pool_id)
WHERE c.org_id = sqlc.arg(org_id)
  AND c.id = sqlc.arg(cluster_id)
  AND c.connector_node_id IS NULL
  AND EXISTS (
      SELECT 1 FROM k8s_connector_pools p
      WHERE p.id = sqlc.arg(connector_pool_id) AND p.org_id = c.org_id AND p.site_id = c.site_id AND p.cluster_id = c.id
  );

-- S10.3c durable handoff-operation contract. The PostgreSQL tick source uses
-- these generated read bindings; it remains unregistered and read-only.

-- S10.3c durable health-history contract. A source may persist one CP-issued
-- observation after it locks and rechecks this exact pool/member snapshot.
-- These queries have no pool ownership mutation and no scheduler registration.

-- name: ListK8sConnectorPoolHealthObservationMembersForUpdate :many
-- The observer locks the exact current members and their CP-recorded node
-- evidence with the pool row before it derives an idempotency fingerprint.
SELECT
    m.pool_id,
    m.org_id,
    m.site_id,
    m.node_id,
    m.admin_priority,
    n.status AS node_status,
    n.revoked_at AS node_revoked_at,
    n.wg_public_key AS node_wg_public_key,
    n.endpoint AS node_endpoint,
    n.last_seen_at AS node_last_seen_at,
    n.policy_reported_at AS node_policy_reported_at,
    n.capabilities AS node_capabilities
FROM k8s_connector_pool_members m
JOIN nodes n
  ON n.id = m.node_id
 AND n.org_id = m.org_id
 AND n.site_id = m.site_id
WHERE m.pool_id = sqlc.arg(pool_id)
  AND m.org_id = sqlc.arg(org_id)
  AND m.site_id = sqlc.arg(site_id)
FOR UPDATE OF m, n;

-- name: ListK8sConnectorPoolHealthCandidateTicksForUpdate :many
SELECT *
FROM k8s_connector_pool_health_candidate_ticks
WHERE state_id = sqlc.arg(state_id)
  AND org_id = sqlc.arg(org_id)
  AND site_id = sqlc.arg(site_id)
  AND cluster_id = sqlc.arg(cluster_id)
  AND pool_id = sqlc.arg(pool_id)
FOR UPDATE;

-- name: ListK8sConnectorPoolHealthCandidateTicks :many
SELECT *
FROM k8s_connector_pool_health_candidate_ticks
WHERE state_id = sqlc.arg(state_id)
  AND org_id = sqlc.arg(org_id)
  AND site_id = sqlc.arg(site_id)
  AND cluster_id = sqlc.arg(cluster_id)
  AND pool_id = sqlc.arg(pool_id)
ORDER BY node_id;

-- name: ResetK8sConnectorPoolHealthCandidateTicks :execrows
DELETE FROM k8s_connector_pool_health_candidate_ticks
WHERE state_id = sqlc.arg(state_id)
  AND org_id = sqlc.arg(org_id)
  AND site_id = sqlc.arg(site_id)
  AND cluster_id = sqlc.arg(cluster_id)
  AND pool_id = sqlc.arg(pool_id);

-- name: UpsertK8sConnectorPoolHealthCandidateTicks :one
INSERT INTO k8s_connector_pool_health_candidate_ticks (
    state_id, org_id, site_id, cluster_id, pool_id, node_id, healthy_ticks
)
VALUES (
    sqlc.arg(state_id), sqlc.arg(org_id), sqlc.arg(site_id), sqlc.arg(cluster_id),
    sqlc.arg(pool_id), sqlc.arg(node_id), sqlc.arg(healthy_ticks)
)
ON CONFLICT (state_id, node_id)
DO UPDATE SET healthy_ticks = EXCLUDED.healthy_ticks, updated_at = now()
RETURNING *;

-- name: UpdateK8sConnectorPoolHealthState :one
UPDATE k8s_connector_pool_health_states
SET observed_active_node_id = sqlc.arg(observed_active_node_id),
    observed_generation = sqlc.arg(observed_generation),
    stale_ticks = sqlc.arg(stale_ticks),
    preferred_fresh_ticks = sqlc.arg(preferred_fresh_ticks),
    last_transition = sqlc.arg(last_transition),
    last_transition_from_node_id = sqlc.narg(last_transition_from_node_id),
    last_transition_to_node_id = sqlc.narg(last_transition_to_node_id),
    last_observation_key = sqlc.arg(last_observation_key),
    last_observation_at = sqlc.arg(last_observation_at),
    updated_at = now()
WHERE id = sqlc.arg(id)
  AND org_id = sqlc.arg(org_id)
  AND site_id = sqlc.arg(site_id)
  AND cluster_id = sqlc.arg(cluster_id)
  AND pool_id = sqlc.arg(pool_id)
RETURNING *;

-- name: ListK8sConnectorHandoffTickMembers :many
-- The scheduler source sees only clusters explicitly bound to their exact
-- org/site/cluster-owned pool. Every member is joined to its current node row
-- in the same org/site; a partial or cross-scope relationship emits no row.
SELECT
    p.id AS pool_id,
    p.org_id,
    p.site_id,
    p.cluster_id,
    p.preferred_node_id,
    p.active_node_id,
    p.generation,
    m.node_id,
    m.admin_priority,
    n.status AS node_status,
    n.revoked_at AS node_revoked_at,
    n.wg_public_key AS node_wg_public_key,
    n.endpoint AS node_endpoint,
    n.last_seen_at AS node_last_seen_at,
    n.policy_reported_at AS node_policy_reported_at,
    n.capabilities AS node_capabilities
FROM k8s_clusters c
JOIN k8s_connector_pools p
  ON p.id = c.connector_pool_id
 AND p.org_id = c.org_id
 AND p.site_id = c.site_id
 AND p.cluster_id = c.id
JOIN k8s_connector_pool_members m
  ON m.pool_id = p.id
 AND m.org_id = p.org_id
 AND m.site_id = p.site_id
JOIN nodes n
  ON n.id = m.node_id
 AND n.org_id = p.org_id
 AND n.site_id = p.site_id
LEFT JOIN k8s_ha_settings hs ON hs.org_id = p.org_id
LEFT JOIN k8s_connector_pool_ha_transitions ht
  ON ht.pool_id = p.id
 AND ht.org_id = p.org_id
 AND ht.site_id = p.site_id
 AND ht.cluster_id = p.cluster_id
LEFT JOIN k8s_connector_pool_health_states hh
  ON hh.pool_id = p.id
 AND hh.org_id = p.org_id
WHERE (
    hs.enabled = true
    AND ht.requested_mode = 'fenced_ha'
    AND ht.actual_mode = 'fenced_ha'
    AND hh.id IS NOT NULL
    AND ht.active_node_id = p.active_node_id
    AND ht.promotion_generation = p.generation
    AND ht.membership_epoch = hh.membership_epoch
) OR EXISTS (
    -- Organization opt-out/drain blocks new decisions immediately, but an
    -- already committed handoff must remain visible until its safe terminal
    -- phase. The source's operation branch cannot create fresh intent here.
    SELECT 1 FROM k8s_connector_handoff_operations pending
    WHERE pending.pool_id = p.id AND pending.org_id = p.org_id
      AND pending.phase NOT IN ('complete','failed')
)
ORDER BY p.org_id, p.site_id, p.id, m.admin_priority DESC, m.node_id;

-- name: ListNonterminalK8sConnectorHandoffOperationsForTick :many
-- A resume read is restricted to the same explicit cluster-pool binding as
-- discovery. Terminal records remain historical only and cannot be reopened.
SELECT o.*
FROM k8s_connector_handoff_operations o
JOIN k8s_connector_pools p
  ON p.id = o.pool_id
 AND p.org_id = o.org_id
 AND p.site_id = o.site_id
 AND p.cluster_id = o.cluster_id
JOIN k8s_clusters c
  ON c.id = p.cluster_id
 AND c.org_id = p.org_id
 AND c.site_id = p.site_id
 AND c.connector_pool_id = p.id
WHERE o.phase NOT IN ('complete', 'failed')
ORDER BY o.org_id, o.site_id, o.pool_id, o.id;

-- name: CreateOrResumeK8sConnectorHandoffOperation :one
-- Idempotent create/resume has one operation UUID and one immutable intent.
-- A new record requires the exact pool pre-CAS state and both members. A retry
-- may resume the same immutable record after CAS changed the pool state. A
-- competing operation ID returns zero rows rather than replacing it; a caller
-- that raced an initial insert retries its same operation ID normally.
WITH leadership AS (
    SELECT sqlc.arg(leader_backend_pid)::integer AS backend_pid
), observed_health_epoch AS (
    -- Lock the durable incarnation while this statement checks it. A member
    -- mutation's AFTER trigger updates this row FOR UPDATE, so it either
    -- commits before this claim (epoch mismatch) or waits until the claim has
    -- finished; it cannot slip between an unlocked epoch read and INSERT.
    SELECT h.id
    FROM k8s_connector_pool_health_states h
    WHERE h.org_id = sqlc.arg(org_id)
      AND h.site_id = sqlc.arg(site_id)
      AND h.cluster_id = sqlc.arg(cluster_id)
      AND h.pool_id = sqlc.arg(pool_id)
      AND h.membership_epoch = sqlc.narg(expected_membership_epoch)::bigint
    FOR SHARE
), existing AS (
    SELECT o.*
    FROM k8s_connector_handoff_operations o
    WHERE o.id = sqlc.arg(operation_id)
       OR (o.org_id = sqlc.arg(org_id)
           AND o.site_id = sqlc.arg(site_id)
           AND o.pool_id = sqlc.arg(pool_id)
           AND o.phase NOT IN ('complete', 'failed'))
), created AS (
INSERT INTO k8s_connector_handoff_operations (
    id, org_id, site_id, pool_id, cluster_id, old_node_id, new_node_id,
    expected_generation, target_generation,
    old_serving_manifest_identity, candidate_prepared_manifest_identity,
    old_withdrawal_manifest_identity, new_serving_manifest_identity,
    old_serving_manifest_revision, candidate_prepared_manifest_revision,
    old_withdrawal_manifest_revision, new_serving_manifest_revision,
    old_serving_expected_route_digest, old_serving_expected_vip_map_digest,
    candidate_prepared_expected_route_digest, candidate_prepared_expected_vip_map_digest,
    old_withdrawal_expected_route_digest, old_withdrawal_expected_vip_map_digest,
    new_serving_expected_route_digest, new_serving_expected_vip_map_digest,
    old_lease_identity, target_lease_identity, old_lease_epoch,
    target_lease_epoch, old_lease_expires_at, target_lease_expires_at,
    observed_membership_epoch, decision_transition
)
SELECT
    sqlc.arg(operation_id), sqlc.arg(org_id), sqlc.arg(site_id),
    sqlc.arg(pool_id), sqlc.arg(cluster_id), sqlc.arg(old_node_id),
    sqlc.arg(new_node_id), sqlc.arg(expected_generation),
    sqlc.arg(target_generation), sqlc.arg(old_serving_manifest_identity),
    sqlc.arg(candidate_prepared_manifest_identity),
    sqlc.arg(old_withdrawal_manifest_identity),
    sqlc.arg(new_serving_manifest_identity),
    sqlc.arg(old_serving_manifest_revision),
    sqlc.arg(candidate_prepared_manifest_revision),
    sqlc.arg(old_withdrawal_manifest_revision),
    sqlc.arg(new_serving_manifest_revision),
    sqlc.arg(old_serving_expected_route_digest),
    sqlc.arg(old_serving_expected_vip_map_digest),
    sqlc.arg(candidate_prepared_expected_route_digest),
    sqlc.arg(candidate_prepared_expected_vip_map_digest),
    sqlc.arg(old_withdrawal_expected_route_digest),
    sqlc.arg(old_withdrawal_expected_vip_map_digest),
    sqlc.arg(new_serving_expected_route_digest),
    sqlc.arg(new_serving_expected_vip_map_digest),
    sqlc.arg(old_lease_identity),
    sqlc.arg(target_lease_identity), sqlc.arg(old_lease_epoch),
    sqlc.arg(target_lease_epoch), sqlc.arg(old_lease_expires_at),
    sqlc.arg(target_lease_expires_at), sqlc.narg(expected_membership_epoch),
    sqlc.arg(decision_transition)
WHERE NOT EXISTS (SELECT 1 FROM existing)
  AND (
    (SELECT backend_pid FROM leadership) = 0
    OR pg_backend_pid() = (SELECT backend_pid FROM leadership)
  )
  AND EXISTS (
    SELECT 1
    FROM k8s_connector_pools p
    JOIN k8s_connector_pool_members old_member
      ON old_member.pool_id = p.id AND old_member.org_id = p.org_id
     AND old_member.site_id = p.site_id AND old_member.node_id = sqlc.arg(old_node_id)
    JOIN k8s_connector_pool_members new_member
      ON new_member.pool_id = p.id AND new_member.org_id = p.org_id
     AND new_member.site_id = p.site_id AND new_member.node_id = sqlc.arg(new_node_id)
    WHERE p.id = sqlc.arg(pool_id)
      AND p.org_id = sqlc.arg(org_id)
      AND p.site_id = sqlc.arg(site_id)
      AND p.cluster_id = sqlc.arg(cluster_id)
      AND p.active_node_id = sqlc.arg(old_node_id)
      AND p.generation = sqlc.arg(expected_generation)
      -- A health-observer origin carries its durable membership incarnation.
      -- It is rechecked here, in the operation-claim statement, rather than
      -- trusting the earlier observation snapshot after a member churn race.
      AND (
        sqlc.narg(expected_membership_epoch)::bigint IS NULL
        OR EXISTS (SELECT 1 FROM observed_health_epoch)
      )
)
ON CONFLICT DO NOTHING
RETURNING *
)
SELECT * FROM created
UNION ALL
SELECT prior.*
FROM existing prior
WHERE prior.id = sqlc.arg(operation_id)
  AND (
    (SELECT backend_pid FROM leadership) = 0
    OR pg_backend_pid() = (SELECT backend_pid FROM leadership)
  )
  AND prior.org_id = sqlc.arg(org_id)
  AND prior.site_id = sqlc.arg(site_id)
  AND prior.pool_id = sqlc.arg(pool_id)
  AND prior.cluster_id = sqlc.arg(cluster_id)
  AND prior.old_node_id = sqlc.arg(old_node_id)
  AND prior.new_node_id = sqlc.arg(new_node_id)
  AND prior.expected_generation = sqlc.arg(expected_generation)
  AND prior.target_generation = sqlc.arg(target_generation)
  AND prior.old_serving_manifest_identity = sqlc.arg(old_serving_manifest_identity)
  AND prior.candidate_prepared_manifest_identity = sqlc.arg(candidate_prepared_manifest_identity)
  AND prior.old_withdrawal_manifest_identity = sqlc.arg(old_withdrawal_manifest_identity)
  AND prior.new_serving_manifest_identity = sqlc.arg(new_serving_manifest_identity)
  AND prior.old_serving_manifest_revision = sqlc.arg(old_serving_manifest_revision)
  AND prior.candidate_prepared_manifest_revision = sqlc.arg(candidate_prepared_manifest_revision)
  AND prior.old_withdrawal_manifest_revision = sqlc.arg(old_withdrawal_manifest_revision)
  AND prior.new_serving_manifest_revision = sqlc.arg(new_serving_manifest_revision)
  AND prior.old_serving_expected_route_digest = sqlc.arg(old_serving_expected_route_digest)
  AND prior.old_serving_expected_vip_map_digest = sqlc.arg(old_serving_expected_vip_map_digest)
  AND prior.candidate_prepared_expected_route_digest = sqlc.arg(candidate_prepared_expected_route_digest)
  AND prior.candidate_prepared_expected_vip_map_digest = sqlc.arg(candidate_prepared_expected_vip_map_digest)
  AND prior.old_withdrawal_expected_route_digest = sqlc.arg(old_withdrawal_expected_route_digest)
  AND prior.old_withdrawal_expected_vip_map_digest = sqlc.arg(old_withdrawal_expected_vip_map_digest)
  AND prior.new_serving_expected_route_digest = sqlc.arg(new_serving_expected_route_digest)
  AND prior.new_serving_expected_vip_map_digest = sqlc.arg(new_serving_expected_vip_map_digest)
  AND prior.old_lease_identity = sqlc.arg(old_lease_identity)
  AND prior.target_lease_identity = sqlc.arg(target_lease_identity)
  AND prior.old_lease_epoch = sqlc.arg(old_lease_epoch)
  AND prior.target_lease_epoch = sqlc.arg(target_lease_epoch)
  AND prior.old_lease_expires_at = sqlc.arg(old_lease_expires_at)
  AND prior.target_lease_expires_at = sqlc.arg(target_lease_expires_at)
  AND prior.observed_membership_epoch IS NOT DISTINCT FROM sqlc.narg(expected_membership_epoch)
  AND prior.decision_transition = sqlc.arg(decision_transition);

-- name: GetK8sConnectorHandoffOperation :one
-- Exact operation lookup precedes a new health decision. A terminal record is
-- deliberately still visible so a retry cannot reopen or replace it.
SELECT *
FROM k8s_connector_handoff_operations
WHERE id = sqlc.arg(operation_id)
  AND org_id = sqlc.arg(org_id)
  AND site_id = sqlc.arg(site_id)
  AND pool_id = sqlc.arg(pool_id);

-- name: GetNonterminalK8sConnectorHandoffOperationForPool :one
-- A fresh resolver must not mint a second intent while an operation for this
-- exact tenant/site/pool is already durable. The partial unique index makes
-- more than one row impossible; a missing row is the only fresh domain.
SELECT *
FROM k8s_connector_handoff_operations
WHERE org_id = sqlc.arg(org_id)
  AND site_id = sqlc.arg(site_id)
  AND pool_id = sqlc.arg(pool_id)
  AND phase NOT IN ('complete', 'failed');

-- name: ListK8sConnectorHandoffResolutionMembers :many
-- One exact pool-bound cluster snapshot for the durable plan resolver.  The
-- cluster.connector_pool_id join deliberately forbids legacy fallback and a
-- matching health row supplies the authoritative 0083 membership incarnation.
SELECT
    p.id AS pool_id,
    p.org_id,
    p.site_id,
    p.cluster_id,
    p.preferred_node_id,
    p.active_node_id,
    p.generation,
    h.membership_epoch,
    m.node_id,
    m.admin_priority
FROM k8s_connector_pools p
JOIN k8s_clusters c
  ON c.id = p.cluster_id
 AND c.org_id = p.org_id
 AND c.site_id = p.site_id
 AND c.connector_pool_id = p.id
JOIN k8s_connector_pool_health_states h
  ON h.pool_id = p.id
 AND h.org_id = p.org_id
 AND h.site_id = p.site_id
 AND h.cluster_id = p.cluster_id
JOIN k8s_connector_pool_members m
  ON m.pool_id = p.id
 AND m.org_id = p.org_id
 AND m.site_id = p.site_id
WHERE p.id = sqlc.arg(pool_id)
  AND p.org_id = sqlc.arg(org_id)
  AND p.site_id = sqlc.arg(site_id)
  AND p.cluster_id = sqlc.arg(cluster_id)
-- Higher administrative priority wins; UUID breaks ties exactly as the pure
-- pool model does for a stable candidate order.
ORDER BY m.admin_priority DESC, m.node_id ASC;

-- name: GetK8sConnectorHandoffOperationForUpdate :one
-- Delivery is held behind this row lock until its expected-phase CAS commits.
-- A concurrent tick then rereads the advanced phase instead of sending a
-- second transport request for the same operation key.
SELECT *
FROM k8s_connector_handoff_operations
WHERE id = sqlc.arg(operation_id)
  AND org_id = sqlc.arg(org_id)
  AND site_id = sqlc.arg(site_id)
  AND pool_id = sqlc.arg(pool_id)
FOR UPDATE;

-- name: AdvanceK8sConnectorHandoffOperationPhase :one
-- Every non-CAS phase advance has an operation-ID + exact-scope + expected
-- phase CAS. The table trigger admits only the next ordered phase (or failed),
-- while the receipt checks prevent a phase from claiming evidence it lacks.
UPDATE k8s_connector_handoff_operations o
SET phase = sqlc.arg(next_phase),
    prepared_ack_received_at = COALESCE(sqlc.narg(prepared_ack_received_at), o.prepared_ack_received_at),
    withdrawal_ack_received_at = COALESCE(sqlc.narg(withdrawal_ack_received_at), o.withdrawal_ack_received_at),
    withdrawal_expiry_received_at = COALESCE(sqlc.narg(withdrawal_expiry_received_at), o.withdrawal_expiry_received_at),
    serving_ack_received_at = COALESCE(sqlc.narg(serving_ack_received_at), o.serving_ack_received_at),
    failure_reason = sqlc.narg(failure_reason)
WHERE o.id = sqlc.arg(operation_id)
  AND o.org_id = sqlc.arg(org_id)
  AND o.site_id = sqlc.arg(site_id)
  AND o.pool_id = sqlc.arg(pool_id)
  AND o.phase = sqlc.arg(expected_phase)
  AND (
    sqlc.arg(leader_backend_pid)::integer = 0
    OR pg_backend_pid() = sqlc.arg(leader_backend_pid)::integer
  )
RETURNING o.*;

-- name: CommitK8sConnectorHandoffCAS :one
-- This is the future scheduler's crash-safe boundary. One transaction locks
-- and rechecks exact pool state, applies active+generation once, appends one
-- append-only system audit, records its provenance, and advances the durable
-- operation to enable_serving. If any predicate is stale, it returns no row;
-- it cannot leave a pool CAS without its receipt/audit/phase record.
WITH validated_audit AS (
    SELECT sqlc.arg(actor_system)::text AS actor_system,
           sqlc.arg(audit_reason)::text AS audit_reason
    WHERE octet_length(sqlc.arg(actor_system)::text) BETWEEN 1 AND 128
      AND sqlc.arg(actor_system)::text ~ '[^[:space:]]'
      AND octet_length(sqlc.arg(audit_reason)::text) BETWEEN 1 AND 512
      AND sqlc.arg(audit_reason)::text ~ '[^[:space:]]'
), leadership AS (
    SELECT sqlc.arg(leader_backend_pid)::integer AS backend_pid
), locked_operation AS (
    SELECT o.*
    FROM k8s_connector_handoff_operations o
    JOIN k8s_connector_pools p
      ON p.id = o.pool_id AND p.org_id = o.org_id AND p.site_id = o.site_id AND p.cluster_id = o.cluster_id
    CROSS JOIN validated_audit validation
    CROSS JOIN leadership
    WHERE o.id = sqlc.arg(operation_id)
      AND o.org_id = sqlc.arg(org_id)
      AND o.site_id = sqlc.arg(site_id)
      AND o.pool_id = sqlc.arg(pool_id)
      AND o.phase = 'cas_active'
      AND p.active_node_id = o.old_node_id
      AND p.generation = o.expected_generation
      AND (
        leadership.backend_pid = 0
        OR pg_backend_pid() = leadership.backend_pid
      )
    FOR UPDATE OF o, p
), promoted AS (
    UPDATE k8s_connector_pools p
    SET active_node_id = o.new_node_id,
        generation = o.target_generation,
        updated_at = now()
    FROM locked_operation o
    WHERE p.id = o.pool_id
      AND p.org_id = o.org_id
      AND p.site_id = o.site_id
      AND p.cluster_id = o.cluster_id
      AND p.active_node_id = o.old_node_id
      AND p.generation = o.expected_generation
    RETURNING p.id
), appended_audit AS (
    INSERT INTO audit_logs (org_id, actor_system, action, target_type, target_id, metadata)
    SELECT o.org_id,
           validation.actor_system,
           'k8s.connector_pool.handoff_applied',
           'k8s_connector_pool',
           o.pool_id::text,
           jsonb_build_object(
               'operation_id', o.id,
               'old_node_id', o.old_node_id,
               'new_node_id', o.new_node_id,
               'expected_generation', o.expected_generation,
               'target_generation', o.target_generation,
               'reason', validation.audit_reason
           )
    FROM locked_operation o
    JOIN promoted p ON p.id = o.pool_id
    CROSS JOIN validated_audit validation
    RETURNING id, org_id
)
UPDATE k8s_connector_handoff_operations o
SET phase = 'enable_serving',
    cas_receipt_at = now(),
    cas_audit_id = a.id,
    cas_audit_applied = true
FROM locked_operation locked
JOIN promoted p ON p.id = locked.pool_id
JOIN appended_audit a ON a.org_id = locked.org_id
WHERE o.id = locked.id
  AND o.phase = 'cas_active'
RETURNING o.*;

-- name: GetK8sClusterConnectorView :one
-- Basic cluster API projection. A pool-bound cluster resolves its active
-- connector only through the exact org/site/cluster-owned pool join. The
-- service rejects a non-null cluster pool ID lacking this exact row rather
-- than selecting another pool or treating the connector as unassigned.
SELECT
    c.*,
    p.id AS resolved_connector_pool_id,
    p.active_node_id AS active_connector_node_id
FROM k8s_clusters c
LEFT JOIN k8s_connector_pools p
  ON p.id = c.connector_pool_id
 AND p.org_id = c.org_id
 AND p.site_id = c.site_id
 AND p.cluster_id = c.id
WHERE c.org_id = sqlc.arg(org_id)
  AND c.id = sqlc.arg(cluster_id);

-- name: ListK8sClusterConnectorViewsForOrg :many
-- One org-scoped query for the cluster list; handlers never do a per-cluster
-- pool lookup. Malformed pool-bound rows are returned only as an unresolved
-- join and are rejected fail-closed by the service before any partial list is
-- emitted.
SELECT
    c.*,
    p.id AS resolved_connector_pool_id,
    p.active_node_id AS active_connector_node_id
FROM k8s_clusters c
LEFT JOIN k8s_connector_pools p
  ON p.id = c.connector_pool_id
 AND p.org_id = c.org_id
 AND p.site_id = c.site_id
 AND p.cluster_id = c.id
WHERE c.org_id = sqlc.arg(org_id)
ORDER BY c.name;

-- name: ListK8sConnectorPoolStatusMembersForOrg :many
SELECT
    p.id AS pool_id,
    p.org_id,
    p.site_id,
    p.cluster_id,
    p.preferred_node_id,
    p.active_node_id,
    p.generation,
    m.node_id,
    m.admin_priority,
    n.status AS node_status,
    n.revoked_at AS node_revoked_at,
    n.wg_public_key AS node_wg_public_key,
    n.endpoint AS node_endpoint,
    n.last_seen_at AS node_last_seen_at,
    n.policy_reported_at AS node_policy_reported_at,
    n.capabilities AS node_capabilities,
    COALESCE(o.id, '00000000-0000-0000-0000-000000000000'::uuid) AS operation_id,
    COALESCE(o.phase, '') AS operation_phase
FROM k8s_connector_pools p
JOIN k8s_clusters c
  ON c.id = p.cluster_id
 AND c.org_id = p.org_id
 AND c.site_id = p.site_id
 AND c.connector_pool_id = p.id
JOIN k8s_connector_pool_members m
  ON m.pool_id = p.id
 AND m.org_id = p.org_id
 AND m.site_id = p.site_id
JOIN nodes n
  ON n.id = m.node_id
 AND n.org_id = m.org_id
 AND n.site_id = m.site_id
LEFT JOIN k8s_connector_handoff_operations o
  ON o.pool_id = p.id
 AND o.org_id = p.org_id
 AND o.site_id = p.site_id
 AND o.cluster_id = p.cluster_id
 AND o.phase NOT IN ('complete', 'failed')
WHERE p.org_id = $1
ORDER BY p.site_id, p.id, m.admin_priority DESC, m.node_id;

-- name: ListK8sConnectorPoolHealthStatesForOperatorStatus :many
-- Operator status may expose only the durable health-state incarnation and
-- CP receipt time for explicitly pool-bound clusters. observed_active_node_id
-- is read only to reject an ownership-drifted snapshot; the projection never
-- exposes it. The query omits member, artifact, lease, observation-key, and
-- P2 identity fields.
SELECT
    h.org_id,
    h.site_id,
    h.cluster_id,
    h.pool_id,
    h.membership_epoch,
    h.observed_active_node_id,
    h.observed_generation,
    h.last_observation_at
FROM k8s_connector_pool_health_states h
JOIN k8s_connector_pools p
  ON p.id = h.pool_id
 AND p.org_id = h.org_id
 AND p.site_id = h.site_id
 AND p.cluster_id = h.cluster_id
JOIN k8s_clusters c
  ON c.id = p.cluster_id
 AND c.org_id = p.org_id
 AND c.site_id = p.site_id
 AND c.connector_pool_id = p.id
WHERE h.org_id = $1
ORDER BY h.site_id, h.pool_id;

-- name: GetPoolVIPOwnershipFreshHandoffEnvelopeBodies :one
-- Private P2 composition read. The four raw envelope bodies do not cross this
-- query boundary into a public handler; the provenance facade selects one
-- only after exact non-secret artifact identity validation.
SELECT old_serving_envelope, new_prepared_envelope, old_withdrawal_envelope, new_serving_envelope
FROM pool_vip_ownership_handoff_provenance
WHERE operation_id = sqlc.arg(operation_id)
  AND org_id = sqlc.arg(org_id)
  AND site_id = sqlc.arg(site_id)
  AND cluster_id = sqlc.arg(cluster_id)
  AND pool_id = sqlc.arg(pool_id);
