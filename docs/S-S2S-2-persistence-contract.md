# S2S-2 — Persistence and lifecycle contract

Status: implementation proceeding after Founder's 2026-09-24 instruction to continue development, following the reviewed proposal and local CP bring-up. The [foundation](S-S2S-2-decision-gates.md) and all-tier decision remain in force. The first bounded increment below implements only relational storage invariants; public API and runtime acceptance remain separate work.

## Observable outcome and implementation boundary

A verified owner/admin can store and inspect a redacted, disabled two-tunnel connection against an existing local site/gateway. Concurrent edits cannot overwrite each other. Deletion never silently discards outstanding gateway cleanup. Existing WireGuard sites and policies survive connection deletion. All licence tiers behave identically.

Implement storage and disabled configuration first. Activation, gateway delivery, rotation and acknowledgements remain unavailable until their actual runtime paths exist and pass the corresponding tests. Do not expose a working-looking Connect action backed only by storage. No provider-support claim follows from these records.

The reviewed capability requirement for disabled creation, stable organization lock and node-deletion guard are part of this implementation direction. They do not imply that a runtime or public mutation endpoint already exists.

## P1 — Ownership and records

- An organization setting stores `enabled=false` by default and a positive revision. It is separate from licence entitlements. Setting changes require `ipsec:manage` and verified email.
- A connection stores immutable UUID identity, org, site, assigned gateway, name, desired revision, desired intent, creation/update times and deletion time. UUID identity is never reused. Gateway/site assignment cannot be edited in this increment.
- Exactly two tunnel records belong to the connection, with immutable UUIDs and slots 1 and 2. Configuration and secret revisions are separate: changing a display name does not require rebinding ciphertext to a new secret revision.
- Secret rows are internal storage only: org/connection/tunnel/secret revision plus the existing sealed envelope. Manager responses may expose presence and revision; ordinary topology reads expose neither. No plaintext or ciphertext response field, export endpoint or unkeyed PSK fingerprint.
- Database ownership constraints enforce same-org site and gateway references and tunnel-to-connection ownership. Service checks also require an active enrolled gateway currently bound to the selected site. Disabled creation retains the foundation requirements: organization opt-in must be enabled and the assigned gateway must advertise the explicit IPsec capability. Saving disabled configuration does not create an exception for gateways without that capability. Eligibility checks and inserts share locks/transaction boundaries with destructive ownership changes; a read-then-insert check alone is insufficient.
- Keep shared site, subnet and policy ownership unchanged. Do not widen `sites.link_transport` or add remote CIDRs to shared policies as a side effect.

This first storage increment reserves identities and stores disabled configuration. Provider-specific endpoint/inside-address/algorithm validation must be specified before accepting those fields through a public write API; storage must not accept opaque engine commands or arbitrary configuration text.

## P2 — Revisions, retries and atomicity

- A new connection starts at desired revision 1, disabled. Every accepted configuration/intent change compares the caller's exact positive expected revision and increments it once. Revision overflow refuses. A stale revision returns 409 without records, audit changes or notification.
- The create operation uses a caller-generated UUID and create-only semantics (`If-None-Match: *`). A repeated identity cannot create another connection: return 409 and let the client recover using a redacted GET. Do not silently reinterpret a retry as an update, compare only non-secret fields, or claim transparent successful replay. This deliberately avoids retaining request bodies or secret-derived retry hashes.
- Updates and deletes use `If-Match` with the current revision. After a lost response, GET the latest state before retrying. Even an identical stale update refuses. These preconditions belong in OpenAPI and generated clients, not a frontend-only check.
- Validate authority and scope before existence-sensitive responses. Bind encryption to IDs/revision derived from authoritative rows. Seal, store both tunnels, update revision and append a redacted audit atomically. Any failure rolls back all records. Notifications follow commit; notification failure is recovered by the next desired-state fetch.
- Lock in a documented consistent order: stable organization row, organization IPsec setting if present, site, gateway, connection, then tunnel slot. Creation, setting changes and organization soft deletion share the organization-row lock, including when no IPsec setting row exists. Recheck organization deletion state and applicable connection blockers inside that transaction; an earlier resource-count read is not sufficient. Existing site/node mutation paths must participate where necessary. Cover opposing operations with real concurrent PostgreSQL tests before shipping.

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

Tombstones have no automatic expiry in this first implementation. Never-delivered finalization removes sealed secret rows and mutable tunnel configuration, retains connection/org identity, last revision and cleanup evidence, and releases live site/gateway references. For delivered records, the user-approved retained-guard disposition in [cleanup disposition](S-S2S-2-cleanup-disposition.md) supersedes unconditional reference release: exact cleanup removes tunnel credentials/configuration but retains nonsecret safety-guard ownership, range reservations and resource obligations. Show tunnel removed and guard retained separately; no unrelated successor may remove the guard. Tombstones remain until organization erasure is explicitly handled; there is no TTL sweeper or operator force-complete endpoint.

Offline or revoked gateways can leave cleanup pending indefinitely. Preserve this limitation in the UI. Do not treat a timeout, certificate revocation or manager acknowledgement as proof of host cleanup. Recovery/abandonment requires its own explicit contract; this slice cannot promise automatic gateway replacement.

## P4 — Existing destructive paths participate

| Existing seam | Required behavior with an unfinished connection |
| --- | --- |
| `sites.Service.DeleteSite` / `db/queries/sites.sql:DeleteSite` | Return a scoped 409; do not cascade away connection/cleanup evidence |
| `sites.Service.UnbindNode`, `UnbindSiteNode` | Refuse detaching the assigned gateway until its connection is deleted and finalized; bodyless and explicit-node paths agree |
| `nodes.Service.DeleteRevokedNode` | Refuse removal while any referencing connection is unfinalized, including never-delivered disabled records; preserve the principal identity for diagnosis |
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
- One cached `postgres:16-alpine` container, loopback `127.0.0.1:54924`, dedicated project bridge network, 512 MiB memory limit, 256 MiB tmpfs database storage and 64 MiB shared memory. No host data mount or persistent volume. Local CP startup demonstrated that this Docker context suppresses host port publication on an internal network; the test fixture therefore uses a bridge with loopback-only published ports.
- Synthetic local test credential only. No application, node agent, Redis, cloud resource, shared database or production migration.
- Before creating, refuse any pre-existing object with that project/name and verify the port is free. Before each DB-capable test command, print and verify project, container project/service labels, network project label, loopback port and tmpfs mount; construct the test DSN only from this verified fixture. Never inherit an arbitrary DSN.
- Tests may create/drop only scratch databases inside this new container. Container removal after tests needs an explicit teardown decision; no volume pruning or default-project command is part of the plan. Tmpfs data is disposable and is lost if the container stops.

The dedicated fixture was started for the continued development instruction, separately from the running local review CP. Project/container/network labels, loopback port and tmpfs storage are checked before each DB-capable test command. No migration test runs against the review CP or existing default databases.

## Current bounded increment — relational storage invariants

Migration 0158 introduces organization settings, connection identities, two tunnel slots and sealed secret storage. Only `disabled` and terminal `deleted` connection states are representable in this increment. There is no delivered state, enabled state, secret-delivery query, observation or acknowledgement implementation. A disabled record therefore means never delivered; deletion requires retaining its identity/revision/history, releasing its live site/gateway references and removing children/secrets atomically.

Composite ownership references protect live sites and gateway bindings. Deferred constraints require exactly two tunnel/secret pairs for disabled records and none for deleted records. Immutable identity/assignment and exact successor revisions prevent raw SQL from silently changing ownership or resurrecting tombstones. Organization-row serialization and deletion checks cover the absent-setting case. Revocation remains possible; physical node deletion/unbinding remains blocked by live references. Rollback refuses populated tables before destructive DDL.

This is dormant schema: no production service writes it yet. Opt-in/capability acceptance, verified-manager checks, atomic redacted audit writes and scoped HTTP 409 mapping belong to the following service/API increment. Existing services may currently surface a database constraint failure as a generic error if records are inserted manually; no UI can create such records in this increment. SQL tests are evidence for relational integrity, not for those unimplemented product gates.

Acceptance: red-before-code isolated PostgreSQL regressions; up/down/up; populated rollback refusal; direct ownership and child-cardinality attacks; concurrent destructive changes; tombstone/secret withdrawal; WireGuard resource preservation; deterministic SQLC generation; API build and independent review. Runtime and packet-path gates remain outstanding.

### Relational increment evidence — 2026-09-24

- Initial real-PostgreSQL regression failed on absent migration 158 before implementation (`/private/tmp/s2s-ipsec-schema-red.log`). Final isolated suite passes, including empty up/down/up, populated rollback refusal, complete-shape ownership/bounds attacks, atomic two-tunnel creation/finalization, immutable identities and retained tombstones, revocation, and preserved WireGuard sites.
- Concurrency tests observe actual blocked database sessions before releasing the other transaction, then require the resumed statement to refuse. A separately demonstrated Repeatable Read stale-snapshot deletion bypass failed before the fix (`/private/tmp/s2s-ipsec-rr-red.log`). IPsec create/setting operations now version the locked organization row, so older-snapshot deletion gets a serialization refusal. The existing organization timestamp trigger means these IPsec configuration operations also update organization `updated_at`; WireGuard-only operations gain no such write.
- Five independent guard mutations were behaviorally killed: gateway ownership FK, organization deletion refusal, exact-two children, terminal hard-delete refusal and revision successor. Source was restored byte-for-byte after each; restored up-migration SHA256 `b5d164f082a5384ca838ee679f3e7731b1f2db1481e943b9f95598acabfa60df`. This is bounded mutation evidence, not exhaustive coverage. Log: `/private/tmp/s2s-ipsec-schema-mutations.log`.
- Restored migration suite passes with Go race detector; database package tests without a DSN also pass (unrelated integration tests skip, not database proof). API and migration binaries build. Cached SQLC v1.31.1 generation is identical across two runs; only the four additive models change. Independent schema/test review has no remaining blocking finding within this storage-only scope.
- After these gates, the owned local review CP `tunnexs2scp0924` migrated to version 158, dirty=false, and its API was refreshed. Health and Vite-proxied meta reads pass. The disposable migration fixture is separate, with tmpfs storage; default databases were untouched. No IPsec records were seeded into the review CP, and no activation or live traffic claim follows.

## Next local increment — organization opt-in service/API

Founder requested continued development but explicitly stopped remote publication until later testing/review. All changes in this increment remain local; the earlier feature-branch push authorization is superseded.

GET/PUT `/api/v1/organizations/{orgId}/ipsec/settings` expose only `enabled` and `revision`. GET uses `org:view` and returns the unwritten default `{enabled:false,revision:0}` without creating a row or audit. PUT uses the existing `ipsec:manage` authorization seam plus verified human identity, with actor and org derived from that principal/scope. No licence-tier condition is introduced.

Settings use the repository's body `expected_revision` convention: zero creates the first stored revision 1, and exact current revisions advance once, including identical values. Negative/overflowing values refuse; stale writes return 409 without state/audit changes. This is a scoped settings precondition; connection updates still retain the separate proposed If-Match contract above. Revisions remain bigint/int64; JavaScript clients cannot exactly represent arbitrary integers beyond their safe range, so this does not claim arbitrary-bigint browser roundtrips.

The store locks the live organization then the optional setting and writes a redacted actor/old/new revision audit in the same transaction. Database failures return static errors, and audit failure rolls back the setting and organization timestamp. Current schema cannot contain delivered/active IPsec connections; its eventual activation migration must add opt-out cleanup guards before widening that state model. Opt-in is configuration permission, not activation, capability qualification or a working tunnel. No UI enable switch or connection-write endpoint is added by this increment.

The OpenAPI contract and Go server/client/TypeScript types are generated with pinned cached tools. Route regressions exposed int64-overflow 500 responses, trailing JSON acceptance and validation messages reflecting submitted values; narrowly scoped validation now rejects these with static 400 responses. Shared behavior for other endpoints is unchanged.

Regression-before-code store and handler tests, real isolated PostgreSQL CAS/concurrency/audit tests, real-router validation and store integration, anonymous-route census, four behavioral guard mutations, race/build gates and independent review qualify this bounded increment. Evidence logs remain under `/private/tmp/s2s-settings-*`; no secret delivery or runtime proof is inferred.

## Next bounded increment — redacted reads and never-delivered finalization

Continue locally with the existing schema 158 only. Current gateway reports do not carry an IPsec capability/version contract; their server-generated capability map cannot authorize IPsec creation. Do not invent a capability key, accept manually injected JSON as runtime evidence, or expose creation/activation until that contract is defined and implemented.

This increment adds internal organization-scoped connection reads and revision-checked deletion of never-delivered disabled records. Reads select explicit non-secret fields; ordinary callers receive no tunnel secret presence/revision or envelope. Deletion requires an already authorized verified human caller, locks the live organization and connection consistently, compares the exact positive revision, deletes both secret/tunnel pairs and retains a finalized tombstone with historical assignment and an atomic redacted audit. Stale, duplicate-terminal, wrong-org, invalid-revision and audit-failure paths must preserve state. Opt-in being off or gateway revocation must not prevent cleanup of these never-delivered records. No public route or delivery authority is introduced.

Existing site/gateway destructive operations already meet foreign-key refusal at the database boundary. Map only the specific IPsec reference constraint failures to a static scoped 409; retain unrelated database error behavior. Test bodyless/explicit unbind, site deletion, revoked-node deletion, cross-org scope and resource preservation. Use the separately guarded disposable PostgreSQL fixture for service evidence; do not seed IPsec connections into the review CP.

Acceptance requires regressions before implementation, isolated database execution (not skipped tests), concurrent stale-delete/audit-rollback checks, focused mutation evidence, race/build and independent review. This is an internal service increment; public management APIs, capability negotiation and actual IPsec traffic remain outstanding.

### Read/finalization increment evidence — 2026-09-24

- Added `ConnectionStore.Read/List/Delete` without a public route. Explicit projections omit all tunnel/secret metadata. Internal List uses a read-only consistent snapshot and deterministic ordering; pagination must be specified before exposing a public list. Delete locks organization then connection; it need not read settings/site/gateway eligibility because it only releases references. Existing FK constraints serialize competing destructive operations.
- Compile RED preceded implementation (`/private/tmp/s2s-connections-red.log`). Real PostgreSQL tests pass for live-org scope, redaction, tombstones, positive exact CAS, invalid/overflow revisions, withdrawal with default-off settings and revoked gateway, atomic audit failure rollback, preserved resources, and two simultaneous deletes yielding exactly one success/audit (`/private/tmp/s2s-connections-green.log`). Records were seeded only in unique disposable test databases; this does not prove creation eligibility.
- Existing service tests first failed with the actual unmapped FK error, then passed with narrow named-constraint mappings for site delete, direct unbind, bodyless/explicit site unbind and revoked-node delete. Cross-org refusal, preserved bindings/audits and post-finalization resource operations pass (`/private/tmp/s2s-resource-services-red.log`, `/private/tmp/s2s-resource-services-green.log`). Security revocation behavior is unchanged. Organization soft-delete remains protected by its DB trigger; its specific HTTP error mapping is still deferred, rather than broadly mapping every check violation.
- Four independent mutations (delete CAS, read org scope, list org scope, audit insertion) produced behavioral failures and source was restored exactly (`/private/tmp/s2s-connections-mutations.log`). Final combined settings/connection/resource suite passes with the race detector (`/private/tmp/s2s-connections-race.log`); API builds and independent connection review found no actionable issue. This is bounded local evidence, not public API, runtime or traffic qualification. No schema change, connection creation, remote push or live connection seeding occurred.

## Next bounded increment — public redacted read/delete API

Expose the already qualified never-delivered store through GET collection/detail and DELETE detail routes under `/api/v1/organizations/{orgId}/ipsec/connections`. Creation/activation remain unavailable. Reads require `org:view`; delete requires verified human `ipsec:manage`, with scope/actor taken from authenticated context before any existence-sensitive response.

Collection reads use UUID keyset pagination: `limit` defaults to 50, accepted range 1–100; optional `after` is an exclusive UUID cursor, ascending by connection UUID. Return explicit redacted `items` and optional `next_cursor`. A cursor conveys no resource authority. Each page is a consistent live-organization snapshot; pages are not a frozen multi-request inventory. Tombstones remain visible. Invalid limits/cursors refuse. Credential fields and tunnel metadata remain absent for all readers in this increment.

Detail GET and successful DELETE return the strong ETag containing the quoted decimal desired revision. DELETE requires exactly one `If-Match` strong quoted positive decimal int64, excluding wildcard, weak tags, lists, leading zeroes and overflow. Missing/malformed preconditions return static 400; revision mismatch or already-terminal state returns 409 with no mutation. Successful DELETE returns 200 with the redacted finalized tombstone and successor ETag. Authentication/authorization takes precedence for a syntactically valid organization UUID (an invalid scope UUID returns static 400); a retry after a lost response must GET state before any further write. No runtime acknowledgement is inferred.

Regression-first tests must exercise actual router authentication/validation, header parsing and actor attribution, generated API consistency, scoped pagination and real-store transaction behavior through the isolated fixture. No public creation, engine choice, new persisted state, migration, gateway capability claim or live IPsec material delivery is part of this slice.

### Public read/delete increment evidence — 2026-09-24

- Pagination regression first failed on missing implementation, then real PostgreSQL exposed a duplicate test-fixture site name; fixture IDs now produce distinct names. Final tests cover page boundaries, exclusive cursors, tombstones and cross-org isolation. A deliberately removed org filter initially survived because the test's foreign cursor excluded its sole foreign record; strengthened unfiltered cross-org pages now kill that mutation. Scope, cursor inclusion and next-page boundary mutations all fail behaviorally and source is restored (`/private/tmp/s2s-connections-page-red.log`, `/private/tmp/s2s-connections-page-green.log`, `/private/tmp/s2s-page-mutations.log`).
- Public handlers and generated server/client/TypeScript types implement only the three reviewed operations. Explicit DTO mapping contains no secret fields. Generation is deterministic; `ListAgents` enum variable names are pinned in source to retain existing generated names after the new schema introduced an enum collision. Existing compatibility aliases are unchanged.
- Authorization runs before parameter validation for valid org IDs, including explicit human enforcement on DELETE. Validation, generated UUID binding and strict decode use static scoped error responses. Tests include anonymous requests, member/unverified/machine/nil-user/bootstrap refusals, admin acceptance, duplicate and malformed If-Match, query overflow, malformed connection UUIDs and authority-before-validation. Permission and canonical revision mutations are killed and restored (`/private/tmp/s2s-connection-http-mutations.log`).
- Real router/store integration in a unique disposable database verifies collection/detail, exact ETags, stale/member/malformed refusals, terminal retries, secret withdrawal, preserved shared resources and one correctly attributed audit (`/private/tmp/s2s-connection-wire-green.log`). Settings/connection/resource race suite and final HTTP authorization census pass; both API editions build, CLI generated package compiles and web TypeScript passes. Independent review has no remaining blocking finding. Logs: `/private/tmp/s2s-page-final-race.log`, `/private/tmp/s2s-connection-http-final.log`.
- All work remains local and uncommitted; no migration or live review-CP IPsec record was added. Creation eligibility, gateway capability wire, runtime/package selection and traffic qualification remain outstanding. Existing desktop UI/theme is unchanged by this API increment.

## Next internal increment — capability-gated disabled identity reservation

Define private agent-report field `ipsec_config_version`: only exact version 1 is recognized by this control plane; missing, zero, negative and unknown versions persist as unsupported zero. This is an authenticated gateway assertion, not provider qualification or traffic evidence. The current shipped agent explicitly reports zero and has no positive override; a future runtime slice must implement and qualify the version-1 configuration/withdrawal contract before advertising one. Existing WireGuard reporting remains available. No engine/package is chosen here.

Reuse the existing server-written `nodes.policy_reported_at`, atomically updated with capabilities by `SetNodeWGInfo`; do not add another persisted timestamp. Internal creation requires a receipt no older than 90 seconds (three default 30-second report cycles), rejects absent/future timestamps, and reads database time after resource locks. A generic `last_seen_at` refresh from desired-state polling does not renew this evidence. Slower configured report intervals may cause creation refusal; no running connectivity is affected by this admission-only check.

Add internal `CreateDisabled` only, reserving caller-generated connection/tunnel UUIDs, a bounded display name and two customer PSKs through the already-approved sealed envelopes. It accepts no endpoints, algorithms, remote ranges or opaque runtime text; those still need their provider/configuration contract before a public creation API. Validate request shape, lock organization then its opt-in setting then scoped site and gateway; require enabled opt-in, same-org bound active enrolled gateway, no revocation and fresh exact-version evidence. Preserve all-tier access. Encrypt with authoritative org/connection/tunnel identities and secret revision 1, store both children and one redacted audit atomically, and return only the ordinary nonsecret connection projection.

Caller authority must already be verified human `ipsec:manage`; actor/org come from that boundary. Repeated UUIDs conflict rather than replay/update. Scope, opt-out, unsupported/stale capability, revocation, invalid secrets, encryption or audit failure cannot leave partial records. Existing resource FKs remain the concurrent ownership boundary; concurrent setting changes and revocation serialize against the locked rows. This function is not wired to a public route or production creation UI. All positive-capability tests use explicitly synthetic isolated fixtures; actual agents remain ineligible and no support claim follows.

Acceptance: regression before implementation, real PostgreSQL atomicity/eligibility/concurrency proof, authenticated report normalization and legacy downgrade, production client reporting zero, secret/error/audit redaction, critical-guard mutations, race/build checks and review. No migration, remote push, daemon installation, cloud provisioning or live material delivery is included.

### Capability/disabled-reservation increment evidence — 2026-09-24

- Regression RED captured before code for absent create API and absent explicit node version-zero report (`/private/tmp/s2s-create-red.log`, `/private/tmp/s2s-capability-node-red.log`). The private report field passes through the certificate-scoped existing channel; the server accepts only integer version 1 and replaces other integer/omitted evidence with zero. The production client's payload hardcodes zero; no runtime capability override exists.
- Isolated HTTP/store report tests verify certificate-derived identity ignores a spoofed body node ID, rejects absent/revoked identity, normalizes legacy/unknown versions and uses the existing database receipt timestamp. An initial test compared VM database time to host wall time and failed; the corrected test brackets receipt with database `clock_timestamp()` calls. This is handler/authentication-seam evidence with synthetic certificate state, not a live TLS handshake or runtime proof (`/private/tmp/s2s-capability-wire-green.log`).
- `CreateDisabled` internally reserves disabled revision 1 only. It stores two identity/revision-bound envelopes and a redacted audit atomically. Real PostgreSQL tests prove opt-in and ownership/refusal cases; unsupported, absent, stale and future capability receipts; concurrent duplicate IDs; invalid secrets; encryption failure on the second envelope; second-secret insert failure; audit failure; and existing second-tunnel identity collision. Failed attempts leave no connection/child/audit residue and preserve existing encrypted records. Shared resources remain intact.
- Four opposing-transaction tests observe a real database lock wait before committing opt-out, revocation, capability downgrade or gateway unbind; the blocked create rechecks and refuses. Five independent guard mutations (opt-in, receipt freshness, exact version, envelope revision, audit insertion) are behaviorally killed and originals restored (`/private/tmp/s2s-create-mutations.log`).
- Restored full IPsec store suite passes under race detector, all IPsec HTTP tests pass against isolated databases, node control-client race suite passes, and both API editions build. Independent create review found no actionable defect; its second-tunnel collision coverage suggestion was added. Evidence: `/private/tmp/s2s-create-final-race.log`, `/private/tmp/s2s-capability-api-final.log`, `/private/tmp/s2s-capability-node-final.log`.
- No public create route, provider configuration, migration, activation or live review-CP record was added. Positive-capability creation remains synthetic-fixture-only. The next creation boundary is provider/configuration validation and qualified runtime capability, not turning on the reserved version for current agents. Work remains local/uncommitted with no push.
