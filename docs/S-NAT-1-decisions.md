# NAT-1 authenticated connectivity session

Status: durable store and device-owner API implemented; gateway/transport wiring
incomplete, feature default off. Earlier slice descriptions below are historical.
Current consolidated pickup: [implementation handoff](NAT-implementation-handoff.md).
User authorized CP-authenticated signaling after the native AWS packet proof.
Baseline: main `f240bd5`; separate branch preserves both NAT-0 proof lanes.

## Locked boundaries

- Reuse existing user session plus device-owner/membership checks on the client
  side, and AgentChannel.authenticateAgent on the gateway side. Never trust IDs
  supplied in JSON as authentication. No replacement login or bearer scheme.
- Bind each immutable generation to org, owner, device, gateway and session ID.
  Caller identity and current eligibility must be server-derived on every read
  and write. Disabled, revoked, expired or superseded generations refuse.
- Relay is opt-in/default-off. Direct configuration and existing clients stay
  unchanged. Session authorization does not grant application access; existing
  WireGuard/firewall policy remains authoritative.
- First slice is a pure internal authorization/sequence contract. No HTTP routes,
  migration, TURN secrets, candidate blobs or network side effects. It does not
  satisfy NAT-1 acceptance and must not be used as an in-memory production store.
- Per-side monotonic sequence validation rejects replay. The future durable store
  must compare and update generation/sequence atomically; a pure function alone
  cannot serialize concurrent requests or prove revocation across processes.

## Follow-on implementation order

1. Review and test this contract, including malformed zero values, tenant/owner/
   gateway mismatch, exact expiry, supersession and per-side replay.
2. OpenAPI-first endpoints plus transactional persistence; derive the eligibility
   snapshot from existing canonical device/user/node readers. No cached grants.
3. Bound candidate payloads and rate limits; short-lived coturn credentials from
   scoped secret configuration. Credentials are not an immediate allocation-kill
   mechanism: active-forwarding revocation remains NAT-3 work.
4. Client/node consumers, then one live CP-mediated packet proof. Reuse unchanged
   TCP/TLS evidence; do not call fixture cryptokey tests CP-policy acceptance.

NAT-0 architecture feasibility subsequently passed: see NAT proof branch
`0e867dc`, docs/NAT-execution-plan.md and the CP-policy ledger. This does not
qualify production signaling, Windows, reconnect or GUI behavior.
Full repository gates, exact-head CI and multi-finder review remain prerequisites
for declaring a completed product story. No push, release or merge in this slice.

## Slice 1 result and integration map

Implemented `apps/api/internal/connectivity`: immutable binding, fail-closed
authorization and independent sequential message reducers. Focused open-edition
race tests, enterprise tests and vet pass; package statement coverage is 100%
(not end-to-end coverage). Two independent reviewers reported no actionable
findings and explicitly withheld claims about authentication/storage wiring.

Next integration targets verified in source:

- `internal/http/device_health_handlers.go` shows existing user principal and
  owner-service boundaries; connectivity must also enforce exact device owner.
- `internal/http/agentchannel.go:authenticateAgent` is the single gateway mTLS
  principal seam. Reuse it rather than constructing an agent principal elsewhere.
- `db/queries/devices.sql:GetDeviceForUpdate` supplies the scoped device lock;
  canonical active-device/roster readers contain status, identity, membership,
  posture and valid-WireGuard-key predicates that the new reader must preserve.
- Session persistence must join/lock current eligibility and compare sequence in
  one transaction. Mapping an arbitrary JSON body into Snapshot is prohibited.

No OpenAPI changes yet because no endpoint is exposed. The next slice must add
the spec before handlers and run generation rather than editing generated files.
No cloud work is needed for these deterministic contract tests.

## 2026-09-09 resumption: minimal UI and credential primitive

User requested simple augmentation and implementation. Rebased clean NAT-1 lane
onto remote main `26a36af`; existing reducer retained (rebased tip `161941d`).

Locked UI scope for NAT-4:
- CP Settings → existing Network panel: one Relay fallback card, default off,
  one configured customer relay profile, configuration/readiness and setup help.
  Secret is write-only; never return it in configuration reads.
- Gateway → existing Overview: capability/readiness line, not a new tab.
  Readiness is not a claim that every device uses relay.
- Desktop existing connection status: Direct / Relay / reconnecting plus a safe
  failure reason. No employee-facing ICE/candidate/credential controls.
- No new navigation, dashboard, wizard, fleet management or DNS behavior.
- Rendering follows real API capability/status, never a mock enabled switch.
  New relay configuration permissions must be generated and server-enforced.

Locked narrow next primitive: generate coturn REST credentials only after the
existing reducer authorizes the current session/principal/snapshot. Username
contains expiry and an opaque HMAC-derived scope for the full binding plus side;
no raw user/org/device IDs. Password uses coturn's HMAC-SHA1/base64 convention.
Shared secret stays CP-side, minimum 32 bytes, maximum 4096 bytes. Deployment
must generate random secrets; byte length alone does not establish entropy.
Credential lifetime at most five minutes and never beyond session expiry,
rounded down to whole seconds; no credential when less than one full second
remains. Same session and opposite sides get separate usernames.

Source: https://github.com/coturn/coturn/blob/master/README.turnserver
(checked 2026-09-09). HMAC-SHA1 here is protocol compatibility, not a new crypto
design. These bearer credentials do NOT enforce tenant peer isolation or kill
an active allocation on expiry. Gateway session authorization/forwarding lease
and coturn peer restrictions remain required integration, not satisfied here.

This primitive adds no HTTP route, config UI, persistence or live forwarding.
Do not call NAT-1 done until authenticated APIs and atomic persistence are wired.

Credential primitive implemented with focused open-edition race tests,
enterprise tests and vet passing. Tests cover coturn password shape, expiry,
side/generation separation, secret rotation/configuration bounds, no raw identity
in username, and all existing fail-closed authorization cases. No new dependency,
HTTP surface, UI mutation or cloud change. This is a partial implementation
checkpoint, not story completion; full gates/live product proof remain owed.
Next: OpenAPI session/profile contracts and transactional persistence, followed
by principal wiring; UI card must consume those real contracts.

## Durable mailbox slice

Locked: one current session row per device, fresh server UUID plus monotonic
generation on replacement; no unbounded session history. Ten-minute negotiation
session, maximum 64 messages per side, 16 KiB UTF-8 JSON object per message.
Store only the latest complete signaling snapshot per side (not trickle deltas).
Readers poll that snapshot; generation/sequence reject old updates. Close is
terminal; replacement requires a fresh authorized device-side create. These are
negotiation limits, NOT the lifetime or revocation lease of a running tunnel.

Serialize operations through the canonical device row; read and lock active
owner/membership, assigned gateway, org and opt-in in the same transaction.
Use database wall time after locks for expiry. Profile initially holds only
default-off opt-in; no deployment/config endpoint may enable it in this slice.
No secret/candidate payload logging. New schema is additive; existing clients
and direct configuration unchanged. HTTP principal wiring follows the durable
store tests; no unauthenticated or placeholder route will be registered.

Next full contract decision still owed before forwarding integration: numeric
forwarding lease/CP-loss bounds and relay peer restriction policy. This mailbox
must not be misrepresented as live revocation enforcement.

## Durable store and device API implementation checkpoint

Implemented migration 0139, generated sqlc queries, canonical eligibility locks,
database-clock expiry, bounded per-side snapshots, replacement generations and
close. JSON storage preserves raw bytes, so the exact 16 KiB boundary does not
expand during persistence. No history growth per message. No transport enabled.

OpenAPI-first owner endpoints under
`/organizations/{orgId}/devices/{deviceId}/connectivity-sessions`: create, read,
publish and close. Item operations require exact session ID and generation.
Dedicated `connectivity:use` grants to member/admin/owner, never operator/agent;
canonical ownership still required regardless of role. Generated Go/CLI/TS/RBAC
updated. Existing auth/MFA/CSRF/no-store middleware remains; request body capped
before decoding; database/payload error details are not sent to the caller.

Verified in isolated local PostgreSQL 17 fixture
`tunnex-nat1-store-20260909a` (no default Compose/project changes):
- All migrations to 139, rollback 139→138 and reapply.
- Actual HTTP owner create/read/publish/close; replay, malformed payload,
  wrong owner, operator and unauthenticated rejection.
- Eight competing independent store writes: exactly one sequence accepted.
- Durable read, gateway-side store principal, default-off, supersession,
  posture/malformed-key/device/gateway revocation, membership removal and expiry.
- Exact 16 KiB snapshot persistence; close prevents reads.
- Focused PostgreSQL race tests in both editions; HTTP/RBAC/connectivity package
  suites in both editions; vet and enterprise server build. These are focused
  local results, not full story gates, live relay acceptance or exact-head CI.

The generic auth walk needed valid new query/body fixtures; corrected the
fixture without weakening its 401 assertion. No customer UI toggles added.

Next implementation: authenticated gateway mTLS mailbox delivery and relay
profile/credential wiring with transactional rate limits; then real node/client
consumers and the small Settings card. Candidate semantic validation and
forwarding lease/security decisions still required before those consumers.
Profile enabling/configuration is deliberately not exposed yet. No PR/push,
merge, cloud mutation or production enablement in this checkpoint.

`make generate-check` passed against the staged generated artifacts. Final
PostgreSQL race reruns passed in both editions after the JSON byte-preservation
change. Independent review dispatch was attempted but the agent service refused
with a thread-limit error; no independent-review completion is claimed. Full
story-end multi-finder review remains pending. Local test PostgreSQL is retained
for the next slice; do not touch unrelated containers or default Compose stores.
