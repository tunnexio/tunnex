# NAT-1 authenticated connectivity session

Status: first internal contract slice, not an exposed API or enabled transport.
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

NAT-0 remains partially qualified: native AWS TCP/TLS transport was proven in
tunnex-client `684a8b0`, but automatic fallback and CP-issued policy/GUI were not.
This explicitly authorized contract slice does not retroactively close that bar.
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
