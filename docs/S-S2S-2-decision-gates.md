# S2S-2 — Backend decision gates

Status: **foundation direction approved by Founder on 2026-09-24.** Separate connection/tunnel ownership, preserved shared resources, dedicated verified owner/admin authority, write-only customer PSKs and acknowledged cleanup are approved. Founder chose **Community, Trial and paid tiers**; no licence restriction may be introduced for IPsec. Engine selection, full persistence transitions and packet-path implementation remain separate gates below.

S2S-1 currently adds read-only visibility over existing WireGuard records. Creating IPsec connections is a separate state model and permission boundary. This paper makes the next decisions explicit; it does not select an engine, authorize infrastructure work, or replace the full lifecycle design required by the epic.

## Verified reuse and its limits

| Existing contract | Source | What it permits reusing |
| --- | --- | --- |
| Site transport accepts only WireGuard | `apps/api/db/migrations/0032_sites.up.sql:22`; refusal test in `apps/api/internal/sites/service_integration_test.go` | Existing site ownership; adding an IPsec string alone is insufficient |
| Full desired state and optional transport material | `apps/node/internal/reconcile/reconcile.go:42` and `:63` | Agent reconciliation and withdrawal conventions; OpenVPN absence sweeps its files, which is not yet an IPsec deletion contract |
| Capability/version refusal | `apps/api/internal/nodes/service.go:2293`; `apps/node/internal/egress/egress_linux.go:410` | Explicit compatibility gates rather than assuming that an old node accepts new desired state |
| Authenticated encryption | `apps/api/internal/crypto/aesgcm.go:68` | Existing sealer; its raw API does not itself bind ciphertext to org, connection, tunnel or revision |
| Purpose/owner/revision-bound encrypted envelope | `apps/api/internal/aigateway/key_envelope.go:35` | Established binding pattern, not reuse of AI-specific key semantics |
| Gateway material delivery over authenticated agent channel | `apps/api/internal/nodes/service.go:695`; `apps/api/internal/http/agentchannel.go:429` | Existing mTLS principal and scoped delivery path; IPsec secret authorization still needs a contract |

Evidence is source-based at the current feature checkout. No installation, packet-flow experiment, live provider test or engine/license qualification was performed for this paper.

## Decisions requiring disposition before backend implementation

| Gate | Concrete proposal to review | Required detail before code |
| --- | --- | --- |
| Ownership and lifecycle | Separate connection and per-tunnel records reference existing org/site/gateway ownership. Configuration revision and gateway acknowledgement remain distinct from observations. Deleting a connection preserves shared sites, subnets, policies and customer cloud resources. | Exact desired/observed transitions, retry/idempotency, stale revision refusal, tombstone and cleanup acknowledgement rules, rollback/migration strategy |
| Runtime and compatibility | Evaluate a node-owned IKEv2 engine with a bounded local control interface. Require an explicit IPsec capability/version; incompatible nodes refuse IPsec without disrupting existing WireGuard service. | Engine/license/package selection, supported Linux targets, least-privilege socket/file authority, installation/uninstallation, mixed-version and restart behavior |
| Secret authority | Bind each encrypted PSK to purpose, org, connection, tunnel and revision using the existing sealer pattern. Only the assigned authenticated gateway receives active material. Ordinary reads and diagnostics never return a PSK. | Who may write or export secrets, whether export is allowed at all, rotation staging/acknowledgement, old-secret withdrawal, crash recovery and redaction tests |
| Routing and enforcement | Initial qualification targets customer-created AWS VPN, IPv4, non-overlapping ranges, static routing and both tunnels. Keep tunnel redundancy distinct from gateway-host HA. | Active-path selection, failure detection and withdrawal, return-path handling, nftables/XFRM order, source-prefix binding, deny proof, MTU and restart behavior |
| Product gates and evidence | Preserve existing WireGuard access. Decide IPsec entitlement, opt-in and operator permissions explicitly. Separate configured, applied, SA, routing and verified-traffic evidence. | Exact edition/permission matrix and refusal contract, observation freshness, support-label gate and provider/version qualification matrix |

These gates correspond to D2–D11 in [the epic](EPIC-site-to-site-ipsec.md). The ownership/authority foundation and all-tier product decision are now approved as specified below; the engine, full lifecycle and dataplane gates remain open. Azure remains a later profile; Google HA VPN remains dependent on a separately qualified BGP subsystem. No provider support label follows from configuration acceptance alone.

## Runtime candidate evidence — not a selection

Official sources checked 2026-09-24:

- strongSwan's VICI plugin exposes configuration, control and monitoring of `charon`; `swanctl` uses it. VICI provides no authentication of its own, so upstream recommends a Unix socket with appropriate permissions. A candidate integration would keep that socket local and node-owned; it must not expose it over the control-plane network. [VICI documentation](https://docs.strongswan.org/docs/latest/plugins/vici.html).
- Upstream supports Linux XFRM interfaces, with interface IDs binding policies and SAs. Its route-based guide describes cleartext-bypass risks when interfaces are absent, loop avoidance for IKE/ESP, and a Netfilter policy-match limitation. Reusing current WireGuard enforcement without testing these paths is insufficient; interface lifecycle, explicit route ownership and no-cleartext-fallback tests are design requirements. [Route-based VPN documentation](https://docs.strongswan.org/docs/latest/features/routeBasedVpn.html).
- Upstream distributes strongSwan under GPLv2 and offers commercial licensing for most components. Package composition, notices/source obligations and the selected client-library license need review before packaging; neither a commercial license nor a compliance conclusion is established by this paper. [Upstream license statement](https://strongswan.org/license.html).

No dependency, daemon or package was installed. These sources support evaluating strongSwan; they do not establish compatibility with the Tunnex dataplane or qualify AWS support.

## Approved minimum authority contract

- Read topology and redacted status with existing `org:view`. Secret presence/revision/fingerprint metadata is manager-only; ordinary reads never return plaintext or ciphertext.
- Add a dedicated `ipsec:manage` permission, initially granted only to owner/admin, and require verified email for mutations. Keep `site:manage` unchanged. Reusing the site-management permission was considered but is not the approved contract.
- IPsec is available in Community, Trial and paid tiers. Require default-off organization opt-in and explicit gateway capability; do not introduce a licence-tier condition or build-time edition fork.
- Licence lapse does not remove IPsec access because Community also includes it. Redacted reads, maintenance and authorized lifecycle operations retain the same permission/opt-in/capability contract. The earlier Trial/paid-only expansion restriction is superseded by Founder's all-tier choice.
- Accept customer-provided PSKs through revision-checked writes. Do not echo or export them. Use authenticated encrypted envelopes bound to purpose/org/connection/tunnel/revision; deliver only to the assigned authenticated gateway. Audits record actor, target and revision, never the key. No generated-secret issuance/recovery feature in this first slice.

Reuse evidence: `apps/api/internal/rbac/rbac.go:100` (network management authority), `apps/api/internal/licence/entitlements.go:10` (runtime feature map), `apps/api/internal/http/fqdn_resource_handlers.go:230` (allow disabling without an enabling entitlement), plus the envelope and channel sources above. These are precedents, not an existing IPsec authorization contract.

## Approved ownership direction and pending detailed transitions

One organization-owned connection references one existing local site and assigned gateway, and owns the external endpoint configuration plus its two tunnel records. It does not own the site's shared subnet or access-policy rows. Remote prefixes are validated connection configuration; they do not imply authenticated people or automatically add allow rules.

| Operator intent | Proposed transition and refusal rule |
| --- | --- |
| Create/update | Accept an exact expected revision (or create idempotency key), produce a new desired revision, and report pending application. No route/traffic success follows from an accepted API write. |
| Reconcile | Only the assigned gateway may acknowledge the exact org/connection/revision. Old observations cannot replace newer state. Installation and observations remain distinct. |
| Disable | Advance desired revision, withdraw only connection-owned routes/SAs/material, retain redacted configuration and cleanup status. Keep shared sites/policies and customer cloud resources. |
| Delete | Tombstone the connection, await assigned-gateway cleanup acknowledgement, and retain enough generation/ownership evidence to reject stale re-creation. An offline gateway yields pending cleanup, not a false completed deletion. |
| Rotate PSK | Stage a new per-tunnel secret revision, coordinate remote-end configuration, apply and acknowledge it, then retire the prior revision. Exact timeout/rollback/retention rules must be specified before rotation code. |
| Gateway reassignment | Defer automatic reassignment in the first implementation until old-gateway withdrawal and new-gateway activation ordering is fully defined. No simultaneous secret delivery is inferred. |

Desired intent, gateway acknowledgement and timestamped observations must be separate records/fields. Exact migrations, retention durations, idempotency lifetime, mutation endpoint census and rotation failure transitions remain the next detailed paper; no values are silently chosen here.

## First backend increment — permission and secret-envelope primitives

Implement the dedicated `ipsec:manage` grant and its generated web mirror, with owner/admin-only and mutating/verified-email classification tests. Existing `org:view` remains the redacted read authority. This increment adds no IPsec HTTP route or UI connect action; permission availability is not feature availability.

Introduce an internal `ipsec` package using the existing authenticated-encryption sealer. `PSKBinding` carries `OrgID`, `ConnectionID`, `TunnelID` (nonzero UUIDs) and positive `Revision`. `SealPSK`/`OpenPSK` bind a version-1 envelope with purpose `tunnex-ipsec-psk`, JSON fields `version`, `purpose`, `org_id`, `connection_id`, `tunnel_id`, `revision`, `value`. Expected identity must later come from authoritative stored ownership and an authenticated principal, never caller claims.

Envelope input bounds: 1–4096 UTF-8 bytes, not whitespace-only, no control characters; preserve accepted input exactly. This is a bounded storage primitive, not provider PSK-format validation. Sealed input is bounded at 16,384 bytes to accommodate JSON escaping plus authenticated-encryption/base64 overhead. Refuse nil sealer, invalid IDs/revision, malformed or oversized ciphertext, wrong purpose/version/binding, unknown envelope fields, extra JSON values, wrong master key and tampering. All failures return one static error and empty output; no raw secret or ciphertext is included. Clear temporary plaintext byte buffers after use; Go string copies are not guaranteed to be erased.

Tests precede implementation. Mutation-check each binding/purpose/revision refusal; prove nonce uniqueness and static errors with synthetic credentials. Run affected Go tests/race checks, RBAC generation twice with no second-pass drift, web RBAC tests/typecheck, and independent review. No database migration, API endpoint, agent delivery, secret export or IPsec daemon is part of this increment, and unit tests do not prove those absent integrations.

### First backend increment evidence — 2026-09-24

- RBAC regressions failed before the owner/admin grants were added; generated client policy changed only those two roles and is byte-identical across two generator runs. All other roles, unknown roles and role-set combinations remain refused.
- Black-box envelope tests were written before the new implementation (initial RED: missing package implementation). Round trips include the 4,096-byte boundary, Unicode and JSON/HTML-sensitive bytes, with strict refusal and no credential values in test errors.
- Six guard mutations were each rejected by a behavioral regression: org, connection, tunnel, revision, purpose and version. The original implementation was restored byte-for-byte after each mutant; all six mutants were killed. No claim of exhaustive mutation coverage.
- Race tests pass for `internal/ipsec`, `internal/rbac` and `internal/crypto`. The actual shared authorization seam passes new anonymous/unverified/cross-org/bootstrap-password/unrelated-role refusal cases and verified owner/admin success. No IPsec HTTP handler exists yet.
- API server builds. Web TypeScript, all 1,583 tests across 132 files and production build pass; the existing bundle-size warning remains. Independent envelope/security and RBAC cross-reviews found no actionable findings.
- Local evidence logs: `/private/tmp/s2s-envelope-mutations.log`, `/private/tmp/s2s-ipsec-race.log`, `/private/tmp/s2s-ipsec-authorize.log`, `/private/tmp/s2s-ipsec-web-full.log`. No database command, dependency download, daemon installation, cloud action or deployment was part of these gates. IPsec remains unavailable in the UI.

## Next executable boundary

The concrete lifecycle direction is now in [the persistence contract](S-S2S-2-persistence-contract.md), including revision/retry semantics, terminal cleanup, existing destructive-path guards, migration acceptance and a bounded isolated database fixture. Following Founder's instruction to continue after reviewing this proposal, implementation starts with dormant relational storage only. Its create-only UUID/recover-by-GET rule replaces the earlier generic create-idempotency-key proposal for the later public API; no HTTP operation is introduced by the schema increment.

After disposition, write the full state-transition and API call-site/mutation census, with a regression/failure matrix before schema or handler changes. The first backend implementation must stay behind capability and product gates and have migration/rollback, permitted/refused entitlement scenarios, applicable API build configurations, deterministic generation and assigned-gateway secret refusal evidence. Actual Linux IPsec and behind-host allow/deny tests remain mandatory before support can be claimed. Cloud provisioning or deployment requires its own concrete approved resource plan.

## Packet-path constraints found during read-only preparation

- `apps/node/internal/egress/egress_linux.go:356` recognizes WireGuard and optional OpenVPN as authenticated ingress; `:746` treats forwarding outside that set as native traffic. XFRM must enter enforcement explicitly, without trusting a physical LAN interface.
- `apps/node/internal/egress/egress_linux.go:970` site grants match prefixes/protocols. The IPsec design must additionally bind remote prefixes to authenticated tunnel identity.
- `apps/node/internal/reconcile/reconcile.go:465` currently passes all policy routes to the WireGuard backend; `wgctrl_linux.go:949` reconciles/prunes its owned route set. New connection-owned XFRM routes must not enter that sweep or delete unrelated routes.
- `apps/node/cmd/agent/main.go:350` logs policy-apply failure without propagating it to the next backend convergence step. IPsec activation must have an explicit successful-enforcement boundary before exposing a new SA/route.
- `apps/node/internal/egress/egress_linux.go:775` accepts established flows before grants; removed-grant flushing follows successful atomic policy apply. Disable/delete ordering must cover established-flow withdrawal and failed cleanup without claiming completion.

These source findings are requirements for the later runtime design, not proof that current WireGuard policy enforcement already covers IPsec.

## Regression/failure matrix

| Boundary | Required proof before that boundary ships |
| --- | --- |
| Ownership | Cross-org site/gateway references refuse without records, revisions or notifications; valid records own exactly their tunnel set |
| Authority | Non-manager/unverified principals refuse; reads remain redacted; all tiers retain identical IPsec access |
| Revision/idempotency | One concurrent expected-revision successor; exact retry makes no duplicate; conflicting retry refuses without change |
| Envelope | Org/connection/tunnel/revision/purpose/version substitutions, tampering, wrong master key and malformed/bounded input refuse with static error and empty output |
| Secret delivery | Assigned certificate-derived gateway only; forged body identity, other gateways, revoked principals and obsolete assignments receive no key |
| Acknowledgement | Wrong scope/revision cannot advance state; duplicate ack is idempotent; accepted config/SA reports do not assert traffic verification |
| Disable/delete | Offline agent remains pending cleanup; tombstone prevents stale resurrection; shared site/subnet/policy/cloud resources survive |
| Rotation | Staging/application/withdrawal crash points preserve the defined active revision; timeout/rollback contract precedes implementation |
| Atomicity/mixed versions | Store/seal/commit failure causes no partial state or precommit notification; unsupported nodes refuse IPsec while preserving WireGuard |
| Migration/rollback | Isolated PostgreSQL up/down/up and cross-org constraints; populated rollback preserves data or refuses explicitly according to its documented contract |
| Mutation tests | Removing each critical ownership/binding/revision/withdrawal guard must make a targeted behavioral regression fail; restore every mutant |

Only the permission and envelope rows are implemented in the first backend increment. Database, delivery, lifecycle and packet-path evidence must not be inferred from those unit tests.
