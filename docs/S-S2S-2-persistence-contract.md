# S2S-2 — Persistence and lifecycle contract

Status: proposed, 2026-09-24. The [foundation](S-S2S-2-decision-gates.md) is approved; the decisions below make its remaining lifecycle gate reviewable. No migration, IPsec endpoint or runtime is introduced by this paper.

## Observable outcome and implementation boundary

A verified owner/admin can store and inspect a redacted, disabled two-tunnel connection against an existing local site/gateway. Concurrent edits cannot overwrite each other. Deletion never silently discards outstanding gateway cleanup. Existing WireGuard sites and policies survive connection deletion. All licence tiers behave identically.

Implement storage and disabled configuration first. Activation, gateway delivery, rotation and acknowledgements remain unavailable until their actual runtime paths exist and pass the corresponding tests. Do not expose a working-looking Connect action backed only by storage. No provider-support claim follows from these records.

## P1 — Ownership and records

- An organization setting stores `enabled=false` by default and a positive revision. It is separate from licence entitlements. Setting changes require `ipsec:manage` and verified email.
- A connection stores immutable UUID identity, org, site, assigned gateway, name, desired revision, desired intent, creation/update times and deletion time. UUID identity is never reused. Gateway/site assignment cannot be edited in this increment.
- Exactly two tunnel records belong to the connection, with immutable UUIDs and slots 1 and 2. Configuration and secret revisions are separate: changing a display name does not require rebinding ciphertext to a new secret revision.
- Secret rows are internal storage only: org/connection/tunnel/secret revision plus the existing sealed envelope. Manager responses may expose presence and revision; ordinary topology reads expose neither. No plaintext or ciphertext response field, export endpoint or unkeyed PSK fingerprint.
- Database ownership constraints enforce same-org site and gateway references and tunnel-to-connection ownership. Service checks also require an active enrolled gateway currently bound to the selected site. Eligibility checks and inserts share locks/transaction boundaries with destructive ownership changes; a read-then-insert check alone is insufficient.
- Keep shared site, subnet and policy ownership unchanged. Do not widen `sites.link_transport` or add remote CIDRs to shared policies as a side effect.

This first storage increment reserves identities and stores disabled configuration. Provider-specific endpoint/inside-address/algorithm validation must be specified before accepting those fields through a public write API; storage must not accept opaque engine commands or arbitrary configuration text.

## P2 — Revisions, retries and atomicity

- A new connection starts at desired revision 1, disabled. Every accepted configuration/intent change compares the caller's exact positive expected revision and increments it once. Revision overflow refuses. A stale revision returns 409 without records, audit changes or notification.
- The create operation uses a caller-generated UUID and create-only semantics (`If-None-Match: *`). A repeated identity cannot create another connection: return 409 and let the client recover using a redacted GET. Do not silently reinterpret a retry as an update, compare only non-secret fields, or claim transparent successful replay. This deliberately avoids retaining request bodies or secret-derived retry hashes.
- Updates and deletes use `If-Match` with the current revision. After a lost response, GET the latest state before retrying. Even an identical stale update refuses. These preconditions belong in OpenAPI and generated clients, not a frontend-only check.
- Validate authority and scope before existence-sensitive responses. Bind encryption to IDs/revision derived from authoritative rows. Seal, store both tunnels, update revision and append a redacted audit atomically. Any failure rolls back all records. Notifications follow commit; notification failure is recovered by the next desired-state fetch.
- Lock in a documented consistent order: organization IPsec setting, site, gateway, connection, then tunnel slot. Existing site/node mutation paths must participate where necessary. Cover opposing operations with real concurrent PostgreSQL tests before shipping.

## P3 — Desired intent is separate from gateway evidence

| Action | Persisted effect | Completion evidence |
| --- | --- | --- |
| Create | Disabled, revision 1, never delivered | Configuration stored only |
| Edit disabled | Exact revision successor | Configuration stored only |
| Enable, later runtime slice | Enabled successor after opt-in/capability/enforcement gates | Pending until assigned gateway acknowledges that exact revision; still no traffic claim |
| Disable | Disabled successor; reject further active material delivery | Never-delivered configuration needs no cleanup; previously deliverable configuration remains pending until exact cleanup acknowledgement |
| Delete | Terminal deleted intent, successor revision and tombstone | Never-delivered record can finalize transactionally; otherwise pending cleanup until exact acknowledgement |
| Re-enable | Allowed only after prior cleanup completes, and only for a non-deleted record | New revision, new application evidence |
| Reassign / rotate | Refused in this increment | Separate ordered handover/rotation contract and implementation required |

Record that a revision **may have been delivered before sending material**. A lost response/crash must leave cleanup owed, not a false never-delivered conclusion. Gateway acknowledgement stores assigned identity, exact desired revision, result and server receipt time. SA/route observations stay separate, timestamped and cannot advance desired intent or cleanup. Application acknowledgement never means verified traffic.

Wrong-org, wrong-gateway, revoked-principal, stale-revision and conflicting duplicate acknowledgements refuse. An exact duplicate has no additional effect. Disabling/deleting remains available when opt-in is off or the gateway has lost capability. Turning organization opt-in off refuses while any connection is enabled or has cleanup pending; it does not silently strand active state.

Tombstones have no automatic expiry in this first implementation. Finalization removes sealed secret rows and mutable tunnel configuration, retains connection/org identity, last revision and cleanup evidence, and releases live site/gateway references. Preserve original IDs as historical values, not live foreign keys. Tombstones remain until organization erasure is explicitly handled; there is no TTL sweeper or operator force-complete endpoint.

Offline or revoked gateways can leave cleanup pending indefinitely. Preserve this limitation in the UI. Do not treat a timeout, certificate revocation or manager acknowledgement as proof of host cleanup. Recovery/abandonment requires its own explicit contract; this slice cannot promise automatic gateway replacement.

## P4 — Existing destructive paths participate

| Existing seam | Required behavior with an unfinished connection |
| --- | --- |
| `sites.Service.DeleteSite` / `db/queries/sites.sql:DeleteSite` | Return a scoped 409; do not cascade away connection/cleanup evidence |
| `sites.Service.UnbindNode`, `UnbindSiteNode` | Refuse detaching the assigned gateway until its connection is deleted and finalized; bodyless and explicit-node paths agree |
| `nodes.Service.DeleteRevokedNode` | Refuse removal while connection cleanup is owed; preserve the principal identity for diagnosis |
| Gateway revocation | Preserve the existing security revocation path; stop secret delivery immediately, retain pending cleanup evidence, never synthesize an acknowledgement |
| Organization soft deletion | Refuse while any live connection or cleanup obligation remains; existing behavior resumes after all connections finalize |
| Direct SQL / migration | Ownership constraints prevent orphaning; tests bypass service helpers to prove the database boundary |

Only organizations/resources with IPsec records acquire these guards. Existing WireGuard-only behavior and tests remain unchanged. Recheck the full node/site mutation census when wiring; generated HTTP interfaces are not the underlying service implementation.

## Mutation and API census

Proposed org-scoped surfaces: GET/PUT IPsec setting; list/get connections; create-only PUT connection identity; revision-checked configuration PUT; disable/delete. Enabling is refused until runtime qualification. No generic PATCH, secret read/export, gateway reassignment, active secret rotation, cloud provisioning or force-cleanup operation.

Read authorization uses `org:view`; all writes use `ipsec:manage` through the existing shared authorization seam. Manager-only secret metadata uses server-side permission checks. List/detail queries and DTOs must select redacted fields explicitly; do not marshal persistence rows or envelopes. Error/audit/trace fixtures use synthetic secret markers and assert their absence. Existing auth-walk census must include every new operation when OpenAPI routes are added.

Gateway desired-state delivery and acknowledgement are later authenticated-agent-channel operations, not human-management API endpoints. They derive identity from the authenticated certificate and stored assignment. User-supplied node/org IDs never grant delivery authority.

## Migration and acceptance sequence

1. Reserve the next unused migration number only at implementation time. Additive schema; no conversion or backfill of existing WireGuard sites. Generate SQLC with the repository's toolchain; inspect deterministic output.
2. Write PostgreSQL regression tests before migration/store implementation. An unset test DSN is a skipped gate, never passing migration evidence.
3. Prove two tunnels, same-org ownership, CAS concurrency, rollback on second-tunnel/encryption/audit failure, stale retries, no secret serialization, and shared-resource preservation. Test create versus site-delete/unbind, connection-delete versus ack, and revocation versus delivery at their respective implementation boundaries.
4. Down migration refuses if any IPsec connection, secret, tombstone or explicitly configured setting exists. Empty-schema down/up is supported. Do not drop populated records as rollback; data restoration requires a separately approved plan.
5. Remove each critical ownership/revision/cleanup guard independently and require the targeted regression to fail. Restore originals, rerun affected tests/race/build and review final diff before feature-branch push.

No runtime acknowledgement test is counted as implemented merely because a pure reducer passes. Storage, HTTP, agent delivery and actual Linux cleanup each require their own evidence.

## Isolated database test plan

Concrete review artifact: `/private/tmp/s2s-foundation-db/compose.yaml`.

- Docker context `colima-f10-dev`; new non-default project `tunnexs2sfoundation0924` only.
- One cached `postgres:16-alpine` container, loopback `127.0.0.1:54924`, internal project network, 512 MiB memory limit, 256 MiB tmpfs database storage and 64 MiB shared memory. No host data mount or persistent volume.
- Synthetic local test credential only. No application, node agent, Redis, cloud resource, shared database or production migration.
- Before creating, refuse any pre-existing object with that project/name and verify the port is free. Before each DB-capable test command, print and verify project, container project/service labels, network project label, loopback port and tmpfs mount; construct the test DSN only from this verified fixture. Never inherit an arbitrary DSN.
- Tests may create/drop only scratch databases inside this new container. Container removal after tests needs an explicit teardown decision; no volume pruning or default-project command is part of the plan. Tmpfs data is disposable and is lost if the container stops.

The Compose file is prepared and statically checked only. Database creation and lifecycle implementation await disposition of this paper and the bounded test resource plan.
