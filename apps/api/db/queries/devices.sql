-- name: CreateDevice :one
-- status is 'active' normally, or 'pending' when the org requires device approval
-- (S7.3). A pending device holds its assigned_ip from creation (excluded from every
-- status='active' reader EXCEPT the allocator, which counts its IP as in-flight).
-- ⚠ `kind` (S15.2 slice 3) distinguishes an AGENT's row from a human's. It carries the cap exemption and
-- the one-per-node uniqueness; it is NOT a permission and grants nothing.
--
-- ⛔ COALESCE(NULLIF(...)), BECAUSE A FORGOTTEN PARAMETER MUST NOT BE A RUNTIME CRASH. Go's zero value for a
-- string is "", which the CHECK rejects — so adding this column made every existing caller that did not
-- name it fail at INSERT time rather than at compile time. One did (`ovpn/service_test.go`), and the next
-- one would too.
-- ⚠ AND THE DEFAULT DIRECTION IS THE CONSERVATIVE ONE: an unspecified row is a HUMAN, so it COUNTS toward
-- the cap. A row that silently defaulted to 'agent' would be cap-exempt by accident — the failure would be
-- a quota that stopped working, discovered by nobody.
INSERT INTO devices (org_id, user_id, node_id, name, platform, public_key, assigned_ip, full_tunnel, status, transport, kind)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, COALESCE(NULLIF(sqlc.arg(kind)::text, ''), 'human'))
RETURNING *;

-- name: EnsureAgentProfile :exec
-- lint:cross-org — the device was just inserted in this same org-scoped transaction;
-- the device ID is not an authorization input and this existence check does not
-- expose or mutate a device outside the caller's already-authorized create.
-- lint:allow-deleted — this guard only admits the row created immediately above;
-- a soft-deleted device cannot be the newly inserted row being profiled.
INSERT INTO agent_profiles (device_id)
SELECT $1
WHERE EXISTS (SELECT 1 FROM devices WHERE id = $1 AND kind = 'agent')
ON CONFLICT (device_id) DO NOTHING;

-- name: GetAgentProfileForOrg :one
SELECT ap.device_id, d.name, ap.environment, ap.runtime, ap.labels,
       d.user_id, u.email AS owner_email, d.status,
       ds.last_handshake_at, ds.rx_bytes, ds.tx_bytes
FROM agent_profiles ap
JOIN devices d ON d.id = ap.device_id
JOIN users u ON u.id = d.user_id
LEFT JOIN device_status ds ON ds.device_id = d.id
WHERE ap.device_id = $1 AND d.org_id = $2 AND d.kind = 'agent' AND d.deleted_at IS NULL;

-- name: UpdateAgentProfile :one
UPDATE agent_profiles ap
SET environment = $2, runtime = $3, labels = $4, updated_at = now()
FROM devices d
WHERE ap.device_id = $1 AND d.id = ap.device_id AND d.org_id = $5 AND d.kind = 'agent' AND d.deleted_at IS NULL
RETURNING ap.*;

-- name: UpdateAgentLifecycle :one
UPDATE devices
SET status = $3, updated_at = now()
WHERE id = $1 AND org_id = $2 AND kind = 'agent' AND deleted_at IS NULL AND status = $4
RETURNING *;


-- name: ApproveDevice :one
-- S7.3: pending -> active, recording the approver (approved_by). Only a PENDING device
-- can be approved (pgx.ErrNoRows => not pending: already active / rejected / wrong org).
-- Returns the owner so the caller can distinguish self-approval for the audit.
UPDATE devices
SET status = 'active', approved_by = $3, updated_at = now()
WHERE id = $1 AND org_id = $2 AND status = 'pending' AND deleted_at IS NULL
RETURNING user_id;

-- name: UpdateDeviceMode :one
-- Mode changes preserve the device principal, gateway, credential and pool allocation. The caller
-- authorizes ownership; the service serializes this update with a row lock before invoking it.
UPDATE devices
SET full_tunnel = $3, updated_at = now()
WHERE id = $1 AND org_id = $2
  AND status IN ('active', 'pending')
  AND deleted_at IS NULL
RETURNING *;

-- name: RejectDevice :one
-- S7.3: pending -> revoked, FREEING the held pool IP (assigned_ip=NULL) so it returns to
-- the pool for reuse (D1b — the same release RevokeDevice does). Only a PENDING device
-- can be rejected. Returns node_id for the (own-node) push.
UPDATE devices
SET status = 'revoked', revoked_at = now(), assigned_ip = NULL
WHERE id = $1 AND org_id = $2 AND status = 'pending' AND deleted_at IS NULL
RETURNING node_id;

-- ⛔ AGENTS ARE EXCLUDED FROM THE HUMAN DEVICE SURFACES. An AI agent is a `devices` row because it IS a
-- WireGuard peer — the peer set, the pool allocation, the revocation sweep and the liveness upsert all read
-- this table and MUST keep seeing it. What it is not is a user endpoint: it has no owner carrying it, no
-- client, no posture, and no place in a laptop roster.
--
-- ⚠ THE PREDICATE IS `kind`, NEVER `platform`. Agent rows exist with a NULL platform (measured on the review
-- rig), so a platform-based filter silently misses them — and a row that escapes this filter reappears in the
-- middle of an operator's device list with no owner and no posture.
-- name: ListPendingDevicesByOrg :many
-- The approval queue (S7.3): devices awaiting admin approval, oldest first.
-- device_health joined (S7.5.3): a pending device may already be reporting posture
-- (both facts surface independently — the D7 orthogonality).
SELECT sqlc.embed(d), ds.last_handshake_at, ds.rx_bytes, ds.tx_bytes,
       dh.evaluated_state, dh.failed_checks, dh.os_version, dh.disk_encrypted, dh.reported_at
FROM devices d
LEFT JOIN device_status ds ON ds.device_id = d.id
LEFT JOIN device_health dh ON dh.device_id = d.id
WHERE d.org_id = $1 AND d.status = 'pending' AND d.deleted_at IS NULL AND d.kind <> 'agent'
ORDER BY d.created_at;

-- ⛔ AGENTS ARE EXCLUDED FROM THE HUMAN DEVICE SURFACES. An AI agent is a `devices` row because it IS a
-- WireGuard peer — the peer set, the pool allocation, the revocation sweep and the liveness upsert all read
-- this table and MUST keep seeing it. What it is not is a user endpoint: it has no owner carrying it, no
-- client, no posture, and no place in a laptop roster.
--
-- ⚠ THE PREDICATE IS `kind`, NEVER `platform`. Agent rows exist with a NULL platform (measured on the review
-- rig), so a platform-based filter silently misses them — and a row that escapes this filter reappears in the
-- middle of an operator's device list with no owner and no posture.
-- name: CountActiveDevicesForOrg :one
-- Grandfathered count when flipping device_approval off->on (best-effort blast radius,
-- S7.3 D4 — existing active devices stay active, not retro-pended).
SELECT count(*) FROM devices
WHERE org_id = $1 AND status = 'active' AND deleted_at IS NULL AND kind <> 'agent';

-- name: SetOrgDeviceApproval :one
-- S7.3: flip the org device-approval gate. Enterprise-gated at the HTTP layer; the open
-- build can never set it 'on', so enrollment there stays immediately-active.
UPDATE organizations SET device_approval = $2, updated_at = now()
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: ListActiveFullTunnelDevices :many
-- S7.2 decision 2a: the devices whose internet egress is governed by policy once the
-- org enters enforcing mode -- enumerated (count + names) in the mode-enable response
-- so the warn-and-confirm shows real blast radius. Owner must be a CURRENT org member
-- (the F1 convention: policy-input queries re-verify membership, not just status).
SELECT d.id, d.user_id, d.name, d.assigned_ip
FROM devices d
JOIN users u ON u.id = d.user_id
JOIN memberships mem ON mem.org_id = d.org_id AND mem.user_id = d.user_id
WHERE d.org_id = $1
  AND d.status = 'active' AND d.deleted_at IS NULL
  AND u.status = 'active' AND u.deleted_at IS NULL
  AND d.full_tunnel
ORDER BY d.name;

-- name: GetDevice :one
SELECT * FROM devices
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL;

-- name: GetDeviceForUpdate :one
-- Row-locking read (S7.3 finding #6): Revoke reads the PRIOR status in-tx to label the
-- audit (device.cancelled for pending vs device.revoked for active). FOR UPDATE serializes
-- against a concurrently-committing Approve (pending->active) so the label can't be stale —
-- audit_logs is APPEND-ONLY, so a mislabel is a permanent error in the forensic record.
SELECT * FROM devices
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
FOR UPDATE;

-- ⛔ AGENTS ARE EXCLUDED FROM THE HUMAN DEVICE SURFACES. An AI agent is a `devices` row because it IS a
-- WireGuard peer — the peer set, the pool allocation, the revocation sweep and the liveness upsert all read
-- this table and MUST keep seeing it. What it is not is a user endpoint: it has no owner carrying it, no
-- client, no posture, and no place in a laptop roster.
--
-- ⚠ THE PREDICATE IS `kind`, NEVER `platform`. Agent rows exist with a NULL platform (measured on the review
-- rig), so a platform-based filter silently misses them — and a row that escapes this filter reappears in the
-- middle of an operator's device list with no owner and no posture.
-- name: ListDevicesByUser :many
SELECT sqlc.embed(d), ds.last_handshake_at, ds.rx_bytes, ds.tx_bytes,
       dh.evaluated_state, dh.failed_checks, dh.os_version, dh.disk_encrypted, dh.reported_at
FROM devices d
LEFT JOIN device_status ds ON ds.device_id = d.id
LEFT JOIN device_health dh ON dh.device_id = d.id
WHERE d.org_id = $1 AND d.user_id = $2 AND d.deleted_at IS NULL AND d.kind <> 'agent'
ORDER BY d.created_at;

-- ⛔ AGENTS ARE EXCLUDED FROM THE HUMAN DEVICE SURFACES. An AI agent is a `devices` row because it IS a
-- WireGuard peer — the peer set, the pool allocation, the revocation sweep and the liveness upsert all read
-- this table and MUST keep seeing it. What it is not is a user endpoint: it has no owner carrying it, no
-- client, no posture, and no place in a laptop roster.
--
-- ⚠ THE PREDICATE IS `kind`, NEVER `platform`. Agent rows exist with a NULL platform (measured on the review
-- rig), so a platform-based filter silently misses them — and a row that escapes this filter reappears in the
-- middle of an operator's device list with no owner and no posture.
-- name: ListDevicesByOrg :many
SELECT sqlc.embed(d), ds.last_handshake_at, ds.rx_bytes, ds.tx_bytes,
       dh.evaluated_state, dh.failed_checks, dh.os_version, dh.disk_encrypted, dh.reported_at
FROM devices d
LEFT JOIN device_status ds ON ds.device_id = d.id
LEFT JOIN device_health dh ON dh.device_id = d.id
WHERE d.org_id = $1 AND d.deleted_at IS NULL AND d.kind <> 'agent'
ORDER BY d.created_at;

-- name: CountDevicesForUserCap :one
-- The per-user device cap counts ACTIVE + PENDING (S7.3 finding #1): a pending device
-- reserves a real pool /32 and is a real enrollment, so excluding it let a user create
-- unbounded pending devices (cap bypass on approve + an org-pool DoS). CONVENTION: pending
-- is EXCLUDED from enforcement but INCLUDED in resource accounting (caps, pools, sweeps).
-- ⛔ HUMANS ONLY (S15.2 slice 3). An agent is a `devices` row, and without this predicate every gateway an
-- admin enrolled would spend that admin's PERSONAL laptop allowance — a fleet charged to one human. The cap
-- convention is right for humans and wrong for agents, and the exemption is EXPLICIT here rather than
-- implied by a caller.
-- ⚠ The partial index `devices_org_user_active_human_idx` is keyed the same way, so the exempted shape is
-- the one the database is built for and a future count that forgets this predicate is slow and visible
-- rather than silently wrong.
SELECT count(*) FROM devices
WHERE org_id = $1 AND user_id = $2 AND status IN ('active', 'pending') AND deleted_at IS NULL
  AND kind = 'human';

-- name: RevokeDevice :one
-- Terminal revocation of an active OR pending device (S7.3 finding #3: an owner may CANCEL
-- their own pending enrollment via this path). Returns the gateway node_id for the push. The caller reads the PRIOR
-- status (via GetDevice, in-tx) to audit distinctly (pending -> device.cancelled, active ->
-- device.revoked). pgx.ErrNoRows means the device was neither active nor pending.
--
-- cause='deliberate' (S13.1 D5): a human decided about THIS device. A gateway coming back must NEVER revive it —
-- the whole point of recording the cause is that "its gateway went away" and "the user lost the laptop" stop
-- rendering identically.
--
-- KEEPS assigned_ip. It used to be cleared "to free the pool address", but the address was already free the moment
-- status left ('active','pending') — both the unique index and ListActiveDeviceAllocations filter on exactly that.
-- Clearing it destroyed the only record of what the revocation took, for no gain.
UPDATE devices
SET status = 'revoked', revoked_at = now(), revoked_cause = 'deliberate' 
WHERE id = $1 AND org_id = $2 AND status IN ('active', 'pending', 'suspended') AND deleted_at IS NULL
RETURNING node_id;

-- name: RevokeDevicesForNode :execrows
-- lint:cross-org — keyed by node_id; when a node is revoked its peers can no longer reach a
-- gateway, so they are revoked too (no dangling devices). Sweeps ACTIVE + PENDING (S7.3
-- finding #2: a pending device on a revoked node would otherwise leak its /32 forever and
-- linger in the approval queue pointing at a dead gateway).
--
-- cause='cascade' (S13.1 D5): nobody decided about THESE devices — their gateway went away. That is what makes
-- them restorable when the gateway comes back, and what distinguishes them from a deliberately revoked laptop.
--
-- KEEPS assigned_ip, and the old comment claiming it "frees the address" was describing a side effect it did not
-- need: the address is free the instant status leaves ('active','pending'), because both readers that define
-- taken-ness filter on exactly that (devices_org_ip_key and ListActiveDeviceAllocations). Clearing it destroyed
-- the only record of what each user held, which is what made Wall 6 unrecoverable rather than merely painful.
-- revoked_prev_status records WHAT THE CASCADE FOUND (review pass 1 #8). Without it the restore has to guess,
-- and it guessed 'active' — promoting a device that was PENDING, never approved by anyone, straight past the
-- org's approval gate. The schema recorded WHY a device was revoked and not WHAT IT WAS.
UPDATE devices
SET status = 'revoked', revoked_at = now(), revoked_cause = 'cascade',
    revoked_prev_status = status
WHERE node_id = $1 AND status IN ('active', 'pending', 'suspended') AND deleted_at IS NULL;

-- name: DeleteDeviceStatus :exec
-- lint:cross-org — keyed by device_id (the caller already authorized the device
-- via its org). Clears a device's live status (on revoke) so a revoked device
-- never reports stale online/handshake via the API.
DELETE FROM device_status WHERE device_id = $1;

-- name: LockDeviceKey :exec
-- lint:cross-org — a transaction-scoped advisory lock on an arbitrary key (a
-- user id or org id, passed as text). Create takes BOTH (in sorted order, so no
-- deadlock) to make the per-user cap check AND the org-wide IP allocation atomic
-- against concurrent creates.
--
-- TWO CLIENTS, both load-bearing: (1) device allocation (per-org mutual
-- exclusion); (2) CIDR resize (S4.5b) — ResizePool takes the org key so its
-- orphan check can't race a concurrent allocation during the resize window. A
-- future S3.5 refactor that rescopes/weakens this lock (per-device keys, etc.)
-- MUST keep resize and allocation contending on the SAME per-org key, or it
-- silently reopens that race — see TestResizeAllocationRace (the red-without-lock
-- guard). Resize takes only the org key; allocation takes {owner,org} sorted;
-- resize never waits on the owner key, so no inversion/deadlock.
SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0));

-- name: ListActiveDeviceAllocations :many
-- The org's live tunnel allocations (flat pool, across all nodes) WITH the owning
-- device (id, name). The SINGLE definition of "live allocation" — used by BOTH
-- device-create's lowest-free choice AND resize's orphan check/409 objects, so
-- there are no two filtered reads to drift apart. Read under the org advisory
-- lock so allocation and resize serialize on the same snapshot.
--
-- INCLUDES 'pending' (S7.3): a pending device HOLDS its assigned_ip from creation, so it
-- is IN-FLIGHT — create must not hand its IP to another device (silent duplicate; the
-- org_ip unique index is likewise widened to active+pending), and resize's orphan check
-- must see it (else a shrink silently strands a pending device's allocation). Revoked/
-- rejected devices have assigned_ip=NULL and never appear.
SELECT id, name, assigned_ip FROM devices
WHERE org_id = $1 AND assigned_ip IS NOT NULL AND status IN ('active', 'pending') AND deleted_at IS NULL
ORDER BY assigned_ip;

-- name: CountAgentIdentitiesForQuota :one
-- F02 H2: pending, active, and suspended reserve org-wide agent identity
-- capacity; revoked and deleted identities do not count.
SELECT count(*)::bigint FROM devices
WHERE org_id = $1
  AND kind = 'agent'
  AND status IN ('pending', 'active', 'suspended')
  AND deleted_at IS NULL;

-- name: ListActiveWireGuardPeersForNode :many
-- fetches the peers for its own node). TWO invariants own this query (both load-bearing):
--   IDENTITY-BINDING (main hotfix): a peer is present only while its owning user has an
--   ACTIVE, CURRENT-MEMBER identity — the users + memberships joins + NOT health_blocked
--   mirror the policy compiler (ListActiveDevicesForOrg, the reference impl). u.status='active'
--   drops a deactivated user's peers; the memberships join drops a REMOVED member's (offboarding
--   severs open-edition WG access, not only the compiled policy — without it RemoveMember's
--   org-wide push rebuilt a query that still served the removed member); NOT health_blocked is
--   the orthogonal posture gate.
--   ⛔ MALFORMED-KEY EXCLUSION (S15.2 walk Leg 4) — THIS GUARD EXISTED AND WAS ONE PREDICATE TOO NARROW.
--   The S9.1 note below names this exact hazard and defends against EMPTINESS. Emptiness is a SPECIAL CASE
--   of malformedness, and the guard tested the special case: an agent device row carrying the placeholder
--   `pending-agent-<uuid>` is non-empty, sailed through `<> ''`, and made `wg syncconf` reject the ENTIRE
--   interface — zero peers configured on that gateway, including every human device.
--
--   > A GUARD WRITTEN FOR A HAZARD IS NOT A GUARD AGAINST THE HAZARD. It is a guard against the instance
--   > that was in front of whoever wrote it. `<> ''` answers "is there a key"; the parser asks "is this a
--   > key", and only the second question is the one `wg` will ask.
--
--   Now a FORMAT check: base64 of 32 bytes — 43 chars plus '='. ⛔ FAIL-CLOSED FOR THE PEER, NEVER FOR THE
--   INTERFACE: a malformed row is dropped from the peer set so the remaining peers still configure. The
--   alternative — letting it through and having `wg` refuse the batch — is fail-closed for the whole
--   data plane, which is the outage this fixes.
--   ⚠ AND EXCLUSION IS SURFACED, NOT SILENT: see ListMalformedKeyPeersForNode, logged at reconcile with the
--   device named. A peer that vanishes without a word is the reassuring-empty class on a data plane.
--
--   KEYLESS EXCLUSION (S9.1 D-S9.4-MODEL / WF-OVPN-10): public_key <> '' — a KEYLESS device (an
--   OpenVPN client carries a cert, not a WG key) is NEVER a WireGuard peer. The query NAME + this
--   WHERE are the SINGLE SOURCE, so every consumer (the per-node peer list AND the hub-set
--   widenedDevicePeers) gets keyed, current-member devices only. A keyless row would render
--   `PublicKey = ` and make `wg syncconf` reject the ENTIRE config (one OpenVPN client bricking
--   the WG fleet on a hub member). The OVPN device's /32 reaches the data plane via the compiled
--   artifact + the OVPN roster (which now shares the identity gate), never this list.
SELECT d.public_key, d.assigned_ip
FROM devices d
JOIN users u ON u.id = d.user_id
JOIN memberships mem ON mem.org_id = d.org_id AND mem.user_id = d.user_id
WHERE d.node_id = $1
  AND d.status = 'active' AND NOT d.health_blocked AND d.deleted_at IS NULL
  AND d.public_key ~ '^[A-Za-z0-9+/]{43}=$'
  AND u.status = 'active' AND u.deleted_at IS NULL
ORDER BY d.created_at;

-- name: GetDeviceUserForOrg :one
-- lint:cross-org — org-scoped by the $2 arg; resolves a flow event's SRC device to its
-- owning user (S7.5.4 v3 flow attribution: src_device_id -> src_user_id, a clean FK join,
-- NEVER an src_ip->device guess).
-- lint:allow-deleted — DELIBERATELY no deleted_at filter (the REVIEWED escape, not an
-- incidental substring [8]): a since-revoked/deleted device's HISTORICAL flow must still
-- attribute its user (access_events is an immutable record; src_device_id/src_user_id are
-- plain uuids, not FKs, precisely so they survive the device/user deletion).
SELECT user_id FROM devices WHERE id = $1 AND org_id = $2;

-- name: ListNodeIDsForUserActiveDevices :many
-- lint:cross-org — keyed by user_id; used to find which nodes to push after a
-- user's peers change (create/revoke/deactivate). Not org-scoped: a user's
-- devices may span orgs and all affected nodes must be nudged to reconcile.
SELECT DISTINCT node_id FROM devices
WHERE user_id = $1 AND status = 'active' AND deleted_at IS NULL;

-- name: GetOrgNode :one
-- Verifies a node belongs to the org (id+org scoped) before a device attaches to it.
SELECT * FROM nodes
WHERE id = $1 AND org_id = $2 AND status = 'active';

-- name: UpsertDeviceStatus :batchexec
-- lint:cross-org — keyed by node_id (agent is cert-authorized) + pubkey. Batched
-- (pgx.Batch) so a whole report is a single round-trip; no per-peer write
-- amplification and the write lands on the lean status table, not the devices
-- row. Maps pubkey->active device on this node; an unknown pubkey is a no-op.
-- rx/tx are raw gauges.
INSERT INTO device_status (device_id, last_handshake_at, rx_bytes, tx_bytes, updated_at)
SELECT d.id, @last_handshake_at, @rx_bytes, @tx_bytes, now()
FROM devices d
WHERE d.node_id = @node_id AND d.public_key = @public_key
  AND d.status = 'active' AND d.deleted_at IS NULL
ON CONFLICT (device_id) DO UPDATE
SET last_handshake_at = EXCLUDED.last_handshake_at,
    rx_bytes = EXCLUDED.rx_bytes,
    tx_bytes = EXCLUDED.tx_bytes,
    updated_at = now();

-- name: ListActiveOVPNDevicesForNode :many
-- lint:cross-org — keyed by node_id after the agent's mTLS auth (its own node's roster), like ListActiveWireGuardPeersForNode.
-- The OVPN roster for a gateway (S9.1 Slice 4c): active OpenVPN devices with an assigned pool /32,
-- homed to this node. id doubles as the cert CommonName + the CCD filename; assigned_ip is the
-- CP-assigned /32 pushed via CCD (the allocator stays authoritative). Feeds ovpnserver.SetDesired.
-- Identity-binding parity (review #1): the roster gates on the OWNING USER's identity exactly like the
-- WG peer query + the policy compiler (ListActiveDevicesForOrg) — a device credential is only valid for
-- its owning user's ACTIVE, CURRENT-MEMBER identity. Without this, a deactivated / offboarded / removed-
-- member / health-blocked user kept a live OpenVPN tunnel (open-edition mesh = full access) while their
-- WireGuard device was severed. The users + memberships joins + NOT health_blocked mirror the compiler.
-- Severance takes effect within one renegotiation interval (reneg-sec 60), the documented OVPN bound.
SELECT d.id, d.assigned_ip, d.full_tunnel FROM devices d
JOIN users u ON u.id = d.user_id
JOIN memberships mem ON mem.org_id = d.org_id AND mem.user_id = d.user_id
WHERE d.node_id = $1 AND d.transport = 'openvpn' AND d.status = 'active'
  AND NOT d.health_blocked
  AND d.assigned_ip IS NOT NULL AND d.deleted_at IS NULL
  AND u.status = 'active' AND u.deleted_at IS NULL
ORDER BY d.id;

-- name: SetDeviceProvisioning :exec
-- Records what the ISSUED CONFIG baked, at issuance. Called after CreateDevice on every path.
--
-- provisioned_ranges is STATIC-ONLY (managed devices poll routes, so there is nothing baked to go stale).
-- provisioned_ip is recorded for EVERY MODE (S13.1 Slice 6): every issued config embeds an interface address,
-- managed included, so a managed device whose address later changes is just as stale — and was silently excluded
-- from the staleness signal, leaving its user to discover the problem by failing to connect.
-- lint:cross-org — keyed by id inside the org-authorized create transaction (same as CreateDevice's row).
UPDATE devices SET provisioning_mode = $2, provisioned_ranges = $3, provisioned_ip = $4,
                   provisioned_node_id = $5, updated_at = now()
WHERE id = $1 AND deleted_at IS NULL;

-- name: ListStaticDevicesForOrg :many
-- S9.1 Part-2 stale-profile surface: every static-provisioned device + its baked ranges snapshot. The
-- caller diffs each snapshot against the org's CURRENT routed ranges to flag "re-export needed".
SELECT id, name, user_id, provisioned_ranges FROM devices
WHERE org_id = $1 AND provisioning_mode = 'static' AND status = 'active' AND deleted_at IS NULL
ORDER BY id;

-- name: ListCascadeRevokedDevicesForNode :many
-- lint:cross-org — keyed by node_id, which the caller resolved from an org-scoped node row.
-- The restore candidate set (S13.1 D5): devices revoked BECAUSE this gateway was, and only those.
--
-- 'deliberate' rows are excluded by the predicate rather than by the caller remembering — a human decided about
-- those devices, and a gateway coming back must never overturn that. NULL cause is also excluded: revoked before
-- 0059, honestly unknown, and reviving a device whose reason nobody recorded is exactly the risk the column exists
-- to avoid.
--
-- Returns the address each device HELD, so the caller can ask the allocation oracle whether it is still free.
SELECT id, name, user_id, assigned_ip, public_key, transport, revoked_prev_status
FROM devices
WHERE node_id = $1 AND status = 'revoked' AND revoked_cause = 'cascade' AND deleted_at IS NULL
ORDER BY id;

-- name: RestoreCascadeRevokedDevice :one
-- lint:cross-org — keyed by device id; the caller authorized via the org-scoped node and read the candidate set
-- from ListCascadeRevokedDevicesForNode.
-- Restores ONE cascade-revoked device (S13.1 D5), to the address the caller resolved.
--
-- The `revoked_cause = 'cascade'` predicate is repeated here deliberately: the candidate query already filtered,
-- and this makes a caller that skipped it unable to revive a deliberately-revoked device anyway. Construction over
-- convention, the same shape as RekeyNode refusing to touch status.
--
-- Clears revoked_cause on success: the row is active again, so a stale cause would make the next reader think it
-- was revoked. needs_reexport is NOT a column — staleness is derived at read time — so nothing to set here.
--
-- node_id is SET, not left alone (S13.1 Slice 7). The re-key path passes the device's existing gateway and nothing
-- moves. The OPERATOR path passes the REPLACEMENT gateway, because a gateway that was revoked is never active again
-- — recovery from a revoke is a join-token enrolment, which creates a NEW node — so restoring these devices onto
-- the node they were homed to would hand back rows that are `active` and point at a dead gateway. The caller
-- authorizes both nodes and proves the target is live; this statement only records the binding it is given.
-- status comes from the CALLER, resolved from revoked_prev_status (review pass 1 #8). Asserting 'active' here
-- promoted a device that was PENDING — never approved by anyone — straight past the org's approval gate, because
-- the statement declared a terminal value for a set whose members were not all in the same state.
UPDATE devices
SET status = $4, revoked_at = NULL, revoked_cause = NULL, revoked_prev_status = NULL,
    assigned_ip = $2, node_id = $3
WHERE id = $1 AND status = 'revoked' AND revoked_cause = 'cascade' AND deleted_at IS NULL
RETURNING *;


-- name: ListMalformedKeyPeersForNode :many
-- ⛔ THE VISIBLE HALF OF THE EXCLUSION (S15.2 walk Leg 4). ListActiveWireGuardPeersForNode drops any device
-- whose public_key is not a well-formed WireGuard key; this names them so the drop can be REPORTED.
--
-- > A PEER EXCLUDED FOR A MALFORMED KEY MUST BE VISIBLE, NOT SILENTLY ABSENT. A device that quietly stops
-- > being a peer is indistinguishable from a device that was never configured — the reassuring-empty class,
-- > on a data plane, where the symptom is "my tunnel does not work" and the screen says everything is fine.
--
-- ⚠ THE PREDICATE IS THE EXACT COMPLEMENT of the peer query's format check. Written as an independent
-- condition it would drift, and the two would disagree about which rows are excluded — the one-truth
-- violation, in the pair whose whole purpose is to agree.
SELECT d.id, d.name, d.public_key
FROM devices d
JOIN users u ON u.id = d.user_id
JOIN memberships mem ON mem.org_id = d.org_id AND mem.user_id = d.user_id
WHERE d.node_id = $1
  AND d.status = 'active' AND NOT d.health_blocked AND d.deleted_at IS NULL
  AND d.public_key <> ''
  AND d.public_key !~ '^[A-Za-z0-9+/]{43}=$'
  AND u.status = 'active' AND u.deleted_at IS NULL
ORDER BY d.created_at;

-- name: SoftDeleteRevokedDevice :execrows
-- ⛔ SOFT, AND THE `ovpn_client_certs` CASCADE IS WHY — NOT A PREFERENCE.
--
-- Every FK into `devices` is ON DELETE CASCADE, including `ovpn_client_certs`. The OpenVPN CRL is
-- literally `SELECT serial ... FROM ovpn_client_certs WHERE revoked_at IS NOT NULL`, so a HARD delete of a
-- revoked device would delete its cert row, drop the serial out of the CRL, and thereby UN-REVOKE the
-- credential on the wire. The operator's tidy-up would silently restore access.
--
-- > **A DELETE THAT CASCADES INTO A REVOCATION LIST IS AN UN-REVOKE WEARING A HOUSEKEEPING VERB.**
--
-- It would also destroy the device's posture and telemetry history and any policy rule naming it as an
-- agent source. Soft delete keeps every one of those rows and simply stops the device being a subject:
-- 27 queries in this file already scope `deleted_at IS NULL`, so the convention exists and this joins it.
--
-- ⚠ REVOKED ONLY. Removing an ACTIVE device from the roster would leave a live credential with no surface
-- to revoke it from — invisible and still working, which is the worst state this product can produce.
-- Returns rows-affected so the caller can tell "not found" from "not revoked" instead of reporting success.
UPDATE devices
SET deleted_at = now(), updated_at = now()
WHERE id = @id AND org_id = @org_id AND status = 'revoked' AND deleted_at IS NULL;

-- name: CountLiveDevicesForNode :one
-- lint:cross-org — keyed by node_id, which the caller resolved from an org-scoped node row.
-- ⛔ THE PREDICATE THAT MAKES A REVOKE REFUSABLE (S12.12 D1). Exactly the set RevokeDevicesForNode would
-- sweep, asked BEFORE the sweep instead of after it. The two must stay identical: a count that is narrower
-- than the cascade lets a revoke through that still disconnects someone, which is the whole defect.
SELECT count(*) FROM devices
WHERE node_id = $1 AND status IN ('active', 'pending', 'suspended') AND deleted_at IS NULL;

-- name: ListLiveDevicesForNode :many
-- lint:cross-org — keyed by node_id, which the caller resolved from an org-scoped node row.
-- The TRANSFER candidate set (S12.12 D1/D4): the devices a revoke would cascade, named so they can be MOVED
-- instead. Same predicate as CountLiveDevicesForNode and RevokeDevicesForNode — one definition of "homed
-- here and live", read three ways.
--
-- PENDING IS INCLUDED (D4). An outstanding approval is about the PERSON, not the gateway; leaving pending
-- rows behind would strand an approval queue pointing at a gateway that is about to be revoked — the exact
-- reason RevokeDevicesForNode sweeps pending rather than only active.
--
-- Returns provisioning_mode because the CONSEQUENCE of the move differs by mode: a static export is a file
-- that never polls and must be re-issued, while a managed device re-homes itself — but only through a
-- hub-set member. The caller needs the mode to report which devices are broken until re-imported.
SELECT id, name, user_id, assigned_ip, transport, status, provisioning_mode
FROM devices
WHERE node_id = $1 AND status IN ('active', 'pending', 'suspended') AND deleted_at IS NULL
ORDER BY id;

-- name: TransferDeviceToNode :one
-- lint:cross-org — keyed by device id; the caller authorized both nodes via the org and read the candidate
-- set from ListLiveDevicesForNode.
-- Re-homes ONE live device onto another gateway (S12.12 D1).
--
-- ⛔ STATUS IS NOT TOUCHED, and that is the difference from RestoreCascadeRevokedDevice. Restore RESURRECTS,
-- so it must resolve what the row used to be; transfer moves a device that is already in a state a human
-- chose. A pending device stays pending — the move is about the gateway, never about the approval.
--
-- ⛔ AND assigned_ip IS NOT TOUCHED EITHER, because the pool is ORG-SCOPED (organizations.pool_cidr, one
-- per org; uniqueness is devices_org_ip_key on (org_id, ip)). A same-org transfer therefore cannot collide:
-- the device already holds that address and keeps holding it. Reallocating would cost every moved user a
-- re-import for a contention that does not exist.
--
-- The `status IN ('active','pending')` predicate is repeated here deliberately, the same construction-over-
-- convention shape as RestoreCascadeRevokedDevice: a caller who skipped the candidate filter still cannot
-- re-home a revoked device and thereby hand it back onto a live gateway.
UPDATE devices
SET node_id = $3, updated_at = now()
WHERE id = $1 AND org_id = $2 AND status IN ('active', 'pending', 'suspended') AND deleted_at IS NULL
RETURNING *;
