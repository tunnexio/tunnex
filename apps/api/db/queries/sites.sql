-- name: CreateSite :one
INSERT INTO sites (org_id, name) VALUES ($1, $2)
RETURNING *;

-- name: GetSite :one
SELECT * FROM sites WHERE id = $1 AND org_id = $2;

-- name: ListSitesByOrg :many
SELECT * FROM sites WHERE org_id = $1 ORDER BY created_at;

-- name: DeleteSite :execrows
-- S8.3 D4: WIRED — the deleteSite endpoint (name-typed confirm + cascade preview in the UI). The cascade
-- it triggers (dst_kind='site'/src_kind='site' rules + subnets, ON DELETE CASCADE) is exercised by
-- TestPolicyRuleSiteDstCascade; the bound gateway is unbound (nodes.site_id -> NULL via the FK).
DELETE FROM sites WHERE id = $1 AND org_id = $2;

-- name: CountPolicyRulesReferencingSite :one
-- lint:cross-org — org-scoped by org_id; counts policy rules that name this site as src OR dst. S8.3 D1/D4:
-- the reverse-link "rules referencing this site" and the delete-cascade preview share this ONE count.
SELECT COUNT(*) FROM policy_rules
WHERE org_id = $1 AND (dst_site_id = $2 OR src_site_id = $2);

-- name: AddSiteSubnet :one
-- lint:cross-org — site_id is org-checked by the caller (GetSite) before this insert; site_subnets
-- has no org_id column of its own (it inherits the site's org via the FK).
INSERT INTO site_subnets (site_id, cidr) VALUES ($1, $2)
RETURNING *;

-- name: ListSiteSubnets :many
-- lint:cross-org — scoped by site_id, which the caller org-checks via GetSite.
SELECT * FROM site_subnets WHERE site_id = $1 ORDER BY created_at;

-- name: BindNodeToSite :execrows
-- Bind a gateway node to a site IN THE SAME ORG. The EXISTS guard refuses a cross-org bind (a
-- node must not bind to another org's site). The single-node-per-site partial unique index makes a
-- second bind to an already-occupied site a unique violation, which the service maps to a typed 409.
-- S8.5 #2: `site_id IS NULL` makes the bind an ATOMIC CLAIM — under two concurrent binds of an unbound
-- gateway, only ONE UPDATE matches (the other sees the just-committed non-null site_id → 0 rows), so the
-- write itself enforces the re-home refusal the read alone could only race on. The caller re-reads on 0
-- rows to emit the right typed error (same-site no-op / already-bound-elsewhere / node-or-site-not-found).
UPDATE nodes SET site_id = $3
WHERE nodes.id = $1 AND nodes.org_id = $2 AND nodes.site_id IS NULL
  AND EXISTS (SELECT 1 FROM sites s WHERE s.id = $3 AND s.org_id = $2);

-- name: UnbindNode :execrows
UPDATE nodes SET site_id = NULL WHERE id = $1 AND org_id = $2;

-- name: ListNodeIDsForSite :many
-- lint:cross-org — org-scoped. The node ids currently bound to a site — the bodyless-unbind sole-gateway
-- resolution (S8.6 #6 compat): a legacy DELETE with no body unbinds the site's ONE gateway; more than one
-- requires an explicit node_id.
SELECT id FROM nodes WHERE site_id = @site_id AND org_id = @org_id;

-- name: UnbindNodeFromSite :execrows
-- lint:cross-org — org-scoped. S8.6 #3: unbind a SPECIFIC gateway from a SPECIFIC site (post the single-node
-- lift a site may hold several gateways — the caller names which; no arbitrary GetSiteNode :one pick). 0 rows
-- = the node is not bound to that site in this org (a deterministic 404, never a wrong-gateway unbind).
UPDATE nodes SET site_id = NULL WHERE id = @node_id AND org_id = @org_id AND site_id = @site_id;

-- name: GetNodeSiteBinding :one
-- lint:cross-org — org-scoped (org_id in the predicate). Returns the node's current site_id (nullable) so
-- BindNode can refuse a silent re-home and RouteLAN can RESUME its own half-built site (S8.5 #2). No rows
-- when the node is not in this org.
SELECT site_id FROM nodes WHERE id = $1 AND org_id = $2;

-- name: ListSiteGatewaysForOrg :many
-- S8.2: every site-bound gateway that has reported a WG key, with its site + public endpoint — the
-- input to the hub-and-spoke site-link peer graph + per-node route set. A gateway with no wg_public_key
-- yet can't be a peer, so it is excluded. endpoint is '' for a NAT'd spoke (it dials out).
-- S8.6: last_seen_at + hub_priority are the election ORDERING inputs (health + the admin pin) — additive,
-- the S8.2 site-link-graph consumers read only id/site_id/wg_public_key/endpoint.
-- S8.6 #4 (revoke-path): status='active' — a REVOKED gateway must not be a site-link peer NOR a hub
-- candidate (revocation is a full sweep; "revoked but still electable as the org's transit hub" contradicts
-- the product's loudest promise at the topology tier). Revoking a gateway drops it here → the derive-then-
-- filter drops it from the active order (no blackhole) and RevokeNode's ReconcileHubSet trigger makes the
-- configured drop durable + audited.
-- ⛔ FORMAT, NOT PRESENCE (S15.3) — THE SAME GUARD THE DEVICE PEER PATH GOT, IN THE PATH THAT WAS MISSED.
-- A site-link peer's key goes to `wg syncconf` exactly as a device peer's does, and syncconf is
-- ALL-OR-NOTHING: one malformed key rejects the ENTIRE interface config, so a single bad site peer takes
-- down every peer on that gateway, including every human device.
--
-- ⚠ `<> ''` ANSWERS "IS THERE A KEY"; THE PARSER ASKS "IS THIS A KEY". The S15.2 census scoped itself to
-- queries returning a DEVICE public_key and stopped there — but the hazard is any key reaching syncconf,
-- and node keys reach it through here.
SELECT id, site_id, wg_public_key, endpoint, last_seen_at, hub_priority FROM nodes
WHERE org_id = $1 AND site_id IS NOT NULL AND status = 'active'
  AND wg_public_key ~ '^[A-Za-z0-9+/]{43}=$';

-- name: ListSiteNodesForOrg :many
-- S8.2 compiler input: the (site_id, node_id, endpoint) binding for every site-bound gateway in the org.
-- The compiler places a src_kind='site' grant on the src + dst gateways AND the transit HUB (B1) — the
-- hub is the site gateway with a public endpoint, so endpoint is needed to designate it. site_id is
-- org-scoped via the node row (nodes.org_id).
--
-- ACTIVE ONLY (S13.1 WF-S11-14, the SHARED-SEAM fix). This is the input its sibling at :77 already filters,
-- with a comment saying revocation must drop a gateway here "no blackhole" — and this one did not. The
-- consequence is not merely a wasted artifact: the compiler reduces these rows into `siteNode[site_id] =
-- node_id`, a SINGLE-VALUE map, so for a site holding both a revoked and an active gateway the placement slot
-- went to whichever row arrived last. With no ORDER BY that was NON-DETERMINISTIC and could flip between
-- compiles — a site grant landing on a dead gateway while the live one never received it, traffic denied while
-- the policy read correct.
--
-- Filtering at the INPUT is deliberate: every consumer of this query is fixed at once, rather than each
-- consumer remembering. ORDER BY makes the reduction deterministic even if a future change admits more than one
-- active gateway per site.
SELECT id, site_id, endpoint FROM nodes
WHERE org_id = $1 AND site_id IS NOT NULL AND status = 'active'
ORDER BY id;

-- name: ListSiteSubnetsForOrg :many
-- lint:cross-org — site_subnets has no org_id of its own; scoped via the join to sites.org_id. The
-- S8.1 compiler input: every APPROVED (site_id, cidr) in the org (D5 — a pending advertisement does NOT
-- propagate), so the compiler expands a dst_kind='site' rule to one AllowEntry per the target site's
-- APPROVED subnets. This same set is the resize disjointness input.
SELECT ss.site_id, ss.cidr
FROM site_subnets ss
JOIN sites s ON s.id = ss.site_id
WHERE s.org_id = $1 AND ss.status = 'approved'
ORDER BY ss.site_id, ss.cidr;

-- name: GetSiteSubnetForOrg :one
-- lint:cross-org — org-scoped via the join to sites.org_id.
SELECT ss.id, ss.site_id, ss.cidr, ss.status
FROM site_subnets ss
JOIN sites s ON s.id = ss.site_id
WHERE ss.id = $1 AND s.org_id = $2;

-- name: ApproveSiteSubnet :one
-- lint:cross-org — the subnet is org-checked via GetSiteSubnetForOrg before approval. Idempotent-ish:
-- approving an already-approved subnet is a no-op UPDATE.
UPDATE site_subnets SET status = 'approved' WHERE id = $1
RETURNING *;

-- name: DeleteSiteSubnet :exec
-- lint:cross-org — the subnet is org-checked via GetSiteSubnetForOrg before deletion (WF-5 un-advertise).
DELETE FROM site_subnets WHERE id = $1;

-- name: ListSiteDNSForwardsForOrg :many
-- lint:cross-org — org-scoped directly. S8.4: each site's dns_forwarding JSONB ([{domain,resolver_ip}]),
-- unioned CP-side into the org forwarding table compiled onto every gateway.
SELECT dns_forwarding FROM sites WHERE org_id = $1;

-- name: SetSiteDNSForwarding :exec
-- lint:cross-org — the site is org-checked via GetSite before this write (S8.4 D7 CRUD).
UPDATE sites SET dns_forwarding = $2, updated_at = now() WHERE id = $1;

-- name: ListPendingSiteSubnetsForOrg :many
-- lint:cross-org — org-scoped via the join. The admin review queue (advertised, awaiting approval).
SELECT ss.id, ss.site_id, ss.cidr, ss.status
FROM site_subnets ss
JOIN sites s ON s.id = ss.site_id
WHERE s.org_id = $1 AND ss.status = 'pending'
ORDER BY ss.created_at;
