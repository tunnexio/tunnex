# F04 — Managed runtime synchronization — decision record

Paper before product wiring. This record locks only decisions already established
by the current schema and CLI acceptance evidence. Unresolved decide-items are
held below; no implementation may silently choose them.

## Acceptance question

Can one managed AI-agent runtime receive and apply server-owned configuration
without accepting the wrong principal, leaking bootstrap/runtime secrets,
regressing applied state, or disabling a previously working tunnel during a
transient control-plane failure?

## Decisions — LOCKED

### D1 — Runtime credential: hash-only, exact device binding

**RULED.** The runtime bearer is accepted only by a stored hash. The credential
row must bind simultaneously to the claimed organization and the exact agent
device; the device must be `kind='agent'`, live, and not deleted, and the
credential must not be revoked. Human devices, cross-organization device IDs,
revoked credentials, and user/session bearer tokens are refused through the
same external authentication failure. Raw runtime credentials are never
persisted or returned after minting.

The existing substrate is `agent_runtime_credentials` plus
`GetAgentRuntimeCredential` in `apps/api/db/queries/agent_bootstrap.sql:18-26`.
The implemented service performs the exact org/device/agent/revocation
binding and hashes the presented secret before lookup at
`apps/api/internal/agentruntime/service.go:69-82`; the live F2 matrix and root's
runtime walk cover the resulting refusal/no-oracle behavior.

### D2 — Poll/report payloads are secret-free

**RULED.** Steady-state poll and report payloads contain no runtime bearer,
bootstrap token, private key, or other secret material. A poll may return only
server-owned runtime configuration and revision/diagnostic fields. The
one-time bootstrap response is the only credential delivery point.

The CLI model already separates this boundary: `ManagedAgentConfig` and
`AgentRuntimeReport` in `apps/cli/internal/cli/agentruntime.go:13-36` contain
no credential or private-key field. The generated API DTOs and route tests now
preserve the same absence invariant; the live wire capture found no forbidden
response fields or headers.

### D3 — Cold start fail-closed; after last-good, fail-static

**RULED.** With no successfully applied configuration, an invalid or unavailable
poll, or a failed first apply, the runtime disables the tunnel and reports an
inconclusive state. After one successful apply, a transient poll, apply, or
report failure preserves the last-good local configuration; it does not clear
the tunnel or invent a new revision. A failed candidate apply restores the
previous configuration bytes exactly and re-applies that interface. If the
restore itself fails, the returned diagnostic joins the candidate-apply and
restore failures instead of hiding either one.

Measured in `apps/cli/internal/cli/agentruntime.go:149-156` and the existing
CLI tests `TestAgentRuntimeColdStartFailsClosed`,
`TestAgentRuntimeApplyFailureKeepsLastGoodRevision`, and
`TestAgentRuntimeReportFailureDoesNotRollBackAppliedConfig`.

### D4 — Revisions are monotonic and server-authoritative

**RULED.** The server returns configuration only when its desired revision is
strictly newer than the runtime's applied revision. Reports reject backwards,
negative, and ahead-of-desired revisions. Concurrent or out-of-order reports
use monotonic maxima: an older report cannot lower `applied_revision` or
`last_attempted_revision`, and cannot resurrect an obsolete error.

The database state and report query establish the current foundation in
`apps/api/db/migrations/0091_agent_runtime_sync.up.sql:7-20` and
`apps/api/db/queries/agent_runtime.sql:41-78`. The existing contract tests
`TestAgentRuntimeSyncSchemaIsAgentOnlyAndSecretFree` and
`TestAgentRuntimeQueriesAreOrgScopedAndMonotonic` are green. The service and
route contracts, plus the live runtime's overlapping reports, now prove the
HTTP path and server state remain monotonic.

### D5 — Error reporting uses bounded stable codes

**RULED.** Reports carry a small allowlisted stable error code, never raw
command output, file paths, tokens, configuration bodies, or arbitrary error
strings. Error revision and code are paired; a report without an error has no
error revision. The database length bounds are necessary but insufficient: the
API/CLI boundary must reject codes outside the product allowlist.

The current CLI emits `invalid_config` and `apply_failed` at
`apps/cli/internal/cli/agentruntime.go:121-127`; the 0091 schema bounds the
stored text at `apps/api/db/migrations/0091_agent_runtime_sync.up.sql:13-20`.
The API allowlist and malformed/ahead refusal are covered by the route and
service contracts; raw runtime output is not accepted or stored.

### D6 — Reconciliation is single-flight

**RULED.** A runtime has at most one poll/apply/report cycle in flight. The
single-flight guard covers the complete cycle so privileged applies cannot run
concurrently and an older result cannot overwrite a newer result. The guard is
context-compatible: a blocked dependency that honors cancellation must release
the cycle; dependencies that ignore context may still hold the call until they
return.

Root's current mutex at `apps/cli/internal/cli/agentruntime.go:67-140` is
reviewed against this ruling. The acceptance tests
`TestAgentRuntimeConcurrentChecksNeverRegressAppliedRevision` and
`TestAgentRuntimeCancellationReleasesSingleFlight` pass repeatedly and under
`-race`.

### D7 — Permission ordering and no-oracle refusals

**RULED.** Runtime-channel authentication is a machine-credential boundary,
not a user/session endpoint. Authorization and identity checks must not reveal
whether an agent, organization, device, or credential exists. Human-device,
cross-org, revoked, malformed, absent, and user/session bearer inputs receive
the same external refusal shape and do not disclose which check failed.

The current API exposes the generated poll/report operations through
`apps/api/internal/http/agent_runtime_handlers.go`. The F2 live matrix proves
uniform 401 status/body shape for absent, malformed, human/session, human
device, cross-org, and revoked bearer classes; the separate shipped-runtime
walk proves valid 200/204 traffic without secret-bearing responses.

### D8 — Capability is default-off and explicitly opted in

**RULED.** Managed runtime synchronization is unavailable by default. An
organization must explicitly opt in before the runtime control channel becomes
usable. Default-off means no implicit enrollment, polling, policy authority,
or tunnel activation. Unlocking a capability does not silently turn enforcement
on. Explicit operator opt-out is terminal for the machine channel: the next
poll/report receives the same uniform 401 used for offboarding and disables the
managed tunnel. Edition/licence unavailability remains a distinct non-terminal
403 so a transient entitlement read cannot silently become a revocation.

The implemented gate requires the paid edition and explicit organization flag,
with `agent_runtime:manage` checked before edition for the admin toggle. The
default-off behavior is covered by migration/tenancy tests and the live
runtime walk.

## Acceptance mapping

| Surface | Required proof | Current evidence/status |
|---|---|---|
| Data | Hash-only credential bound to org+agent device; revoked/human/cross-org rejected; runtime state is agent-only and secret-free | 0090/0091 schema and SQL contracts plus `service.go` binding; default/enterprise route tests and live no-oracle matrix pass |
| Backend poll | Authenticated machine credential; bounded long-poll with cancellation/ticker recheck; uniform terminal opt-out refusal; edition-unavailable remains distinct; strictly newer desired revision; no secret/private-key material | `agent_runtime_handlers.go`, service/route contracts, and live poll 200/204/refusal evidence pass |
| Backend report | Org/device binding; monotonic attempted/applied revisions; backwards/ahead rejection; bounded stable errors; concurrent non-regression | Service/route contracts and live overlapping 204 reports with status applied=attempted=1 pass |
| CLI | Cold-start disable; transactional last-good restore and re-apply; single-flight apply; cancellation release; no revision regression | Existing lifecycle tests plus executable candidate-failure/restore-failure regressions green; concurrency/cancellation acceptance passes 20× and `-race` 10× |
| UI | No runtime status/capacity claim until authenticated API payload and opt-in semantics exist; visibly distinguish ready, last-good, inconclusive, and stale reports; never render unavailable data | Released-route wiring/absence/org-switch tests pass; no secret-bearing runtime fields are rendered |

## Historical red evidence superseded by implementation

The original `TestF04RuntimeChannelAcceptanceSpec` was intentionally red while
the handler/service seam was absent. That state is superseded: current service,
route, default/enterprise, and live evidence now cover the same assertions.
The red route-test expectation at
`apps/api/internal/http/agent_runtime_route_integration_test.go:146` is a stale
cross-org quota expectation (403); the established org boundary correctly
returns 404 to avoid an organization-existence oracle and must not be changed
to satisfy that test.

### Approved disposition — cross-org quota test correction

**LOCKED.** Preserve the established product behavior: a non-member receives
404 `org_not_found`, whether the target organization exists or not. Correct the
focused route test's stale 403 expectation and no-oracle message to assert
404 plus normalized body equality. Do not alter `authorize`, RBAC, edition
ordering, or the quota handler.

## Decide-items — disposition recorded 2026-08-14

The user explicitly approved the recommended set. H1, H2, H4, H5, and H6 are
therefore ruled as stated below; H3 remains deliberately delegated to F05.
Implementation may now build the common security-and-state seam. Numeric
cadence/backoff constants and the new entitlement/permission identifiers must
be measured and recorded before the later transport/opt-in slice; approval of
the product shape is not permission to invent those values or reuse an
unrelated permission.

1. **H1 — RULED: long-poll plus bounded ticker safety net.** Reuse the node
   watch/reconcile shape. The runtime requests a 30-second hold, the OpenAPI
   boundary caps it at 60 seconds, and the server rechecks durable state every
   second so changes written by any API replica wake within the bounded ticker.
2. **H2 — RULED: server-owned mutable runtime configuration.** The server owns
   revision, address, gateway endpoint/public key, AllowedIPs, DNS, and
   keepalive. The runtime owns its private key, credential file, apply mechanics,
   local process state, and local health observation.
3. **H3 — DEFERRED TO F05: credential rotation.** Define overlap,
   revocation, lost-response recovery, and one-time delivery. F04 must consume
   the F05 contract; it must not invent rotation or persist a second secret.
4. **H4 — RULED: licensed unlock plus organization opt-in, default OFF.** The
   implemented `agent_runtime:manage` permission is checked before edition on
   the toggle path; the paid-edition check and persisted org flag are both
   required, and no unrelated permission is reused.
5. **H5 — RULED: bounded backoff plus ticker and last-good health.** Health
   distinguishes ready, last-good, and inconclusive. Transient control-plane
   failure never disables a last-good tunnel. Runtime reports are fresh for
   three minutes. A successful unchanged cycle may consume the 30-second server
   hold plus the 30-second client safety interval, so the freshness window
   covers three worst-case default cycles. Older reports are disconnected and
   stale, with an applied revision surfaced as last-good rather than ready.
6. **H6 — RULED: dedicated zero-touch F04 box-walk.** It must include the
   negative/no-oracle matrix, cold-start disable, last-good during outage,
   restart recovery, concurrent reports, and wire-level secret absence, with
   committed in-session artifacts. Unit tests remain substitutes.

## Measurement slice — options for held decisions

The following are evidence-backed options, not dispositions. The **recommended**
option is marked for the root/user sitting; each item remains **HELD** until
explicitly ruled.

### H1 — Polling cadence and transport: measured options

The node already combines a change-triggered long poll with a periodic safety
net: `ControlClient.Watch` is documented as long-polling at
`apps/node/internal/reconcile/reconcile.go:164-171`, the HTTP implementation
uses `/agent/watch?v=<since>` at `apps/node/internal/control/client.go:294-309`,
and `Reconciler.Run` runs both Watch and a ticker at
`apps/node/internal/reconcile/reconcile.go:397-435`. Watch failures back off
with context-aware sleep at `:417-424` and `:448-455` while the ticker keeps
converging.

Options:

- **H1-A — long poll plus bounded ticker safety net (RECOMMENDED, HELD).**
  Reuse the measured Watch/ticker shape for runtime poll. It gives low change
  latency, survives a broken push path, and has an existing failure/backoff
  precedent. It requires deciding the long-poll timeout, ticker interval, and
  whether the runtime credential endpoint may use the existing mTLS channel.
- **H1-B — bounded short polling.** Simpler deployment and proxy behavior, but
  creates fixed request load and slower convergence or a smaller interval with
  higher load. It does not reuse the existing Watch wakeup contract.
- **H1-C — streaming/SSE/WebSocket.** Lowest idle request overhead after
  connection setup, but adds reconnect, proxy, and half-open-session state that
  this repository's current control client does not use for desired state.

### H2 — Configuration ownership boundaries: measured options

The existing node model is a full desired snapshot: `DesiredState` carries
interface address, MTU, listen port, version, peers, and policy at
`apps/node/internal/reconcile/reconcile.go:34-58`; `runOnce` applies the
snapshot before peer and route convergence at `:313-394`. The node's WireGuard
private key is explicitly local state on `Reconciler` at `:174-179`, while
`ManagedAgentConfig` labels its mutable fields server-owned and omits runtime
credential/private key at `apps/cli/internal/cli/agentruntime.go:13-36`.

Options:

- **H2-A — server owns mutable runtime network configuration; runtime owns
  private key and local process state (RECOMMENDED, HELD).** Server owns
  revision, address, gateway dial, AllowedIPs, DNS, and keepalive; the runtime
  owns its private key, credential file, apply mechanics, and local health.
  This matches the existing DesiredState/ManagedAgentConfig split and keeps
  private material out of poll/report.
- **H2-B — reuse existing device/config issuance ownership.** F04 would poll
  only a revision and consume the existing managed-device dial/config path.
  This reduces duplicate fields but risks mixing static issuance facts with a
  continuously managed runtime; the existing API already distinguishes managed
  from static provisioning and records re-export facts in
  `apps/api/internal/devices/service.go:594-620`.
- **H2-C — gateway-derived dial, server-owned policy only.** This minimizes
  server configuration but makes endpoint/public-key/address provenance
  ambiguous and complicates exact revision and last-good proofs.

### H3 — Credential rotation: F05 ownership confirmed

**HELD and delegated to F05.** F04 consumes the credential/overlap/revocation
contract that F05 defines; it does not add rotation history, a second secret,
or lost-response recovery. The current one-time credential creation/hash path
at `apps/api/internal/devices/service.go:621-634` is evidence of the existing
boundary, not permission for F04 to extend it.

### H4 — Edition and opt-in boundary: measured options

The repository's established model is unlock-then-opt-in. OpenVPN is OFF by
default and the handler gate is documented at
`apps/api/internal/http/ovpn_handlers.go:41-45,109-110`; its service keeps the
opt-in at organization scope, and desired state mirrors it at
`apps/api/internal/nodes/service.go:108,653`. Device approval tests separately
prove that an enterprise-only enforcement capability does not trap an open
edition at `apps/api/internal/devices/posture_test.go:48-76`. Edition entitlement
is runtime-license based via `apps/api/internal/licence/manager.go:146-147`.

Options:

- **H4-A — licensed capability unlock plus organization opt-in, default OFF
  (RECOMMENDED, HELD).** Mirror OpenVPN: license makes the feature available,
  an org setting enables it, and open/unlicensed deployments receive the
  established refusal shape. This preserves downgrade safety and avoids
  implicit runtime activation.
- **H4-B — organization opt-in in all editions, default OFF.** Simpler product
  model, but it changes the established edition-gate precedent and may expose
  an enterprise-only control channel to community deployments.
- **H4-C — license-only enablement.** Strongest operational guard but removes
  explicit customer choice and conflicts with the repository's unlock-then-
  opt-in convention.

The unresolved part is the exact feature entitlement, permission name/order,
org field, and refusal shape; D8 locks only default OFF.

### H5 — Retry, backoff, and health semantics: measured options

The node currently marks health false on fetch/config/reconcile failure without
touching the backend (`apps/node/internal/reconcile/reconcile.go:313-345`),
keeps the last-good data plane through control-plane failure, retries Watch
with a bounded backoff (`:417-424`), and marks ready only when enrolled,
control-connected, and backend healthy (`apps/node/cmd/agent/main.go:380-405`).
The CLI runtime independently preserves last-good after initialization and
disables cold-start failures (`apps/cli/internal/cli/agentruntime.go:93-145`).

Options:

- **H5-A — reuse watch-backoff plus ticker safety net and three-state health
  (RECOMMENDED, HELD).** Keep `healthy/ready`, `last-good`, and `inconclusive`
  distinct; retry transport failures with bounded exponential/jitter backoff
  while the safety ticker continues. This reuses measured behavior but needs
  exact thresholds and stale/unknown rules.
- **H5-B — fixed interval retry with last-good.** Easier to reason about and
  test, but can create synchronized fleet load and has no existing jitter
  precedent in this path.
- **H5-C — failure budget then disable.** Adds a bounded safety response for
  prolonged uncertainty, but risks turning a transient control-plane outage
  into a tunnel outage and must define the operator-visible health transition.

### H6 — Box-walk requirements: measured conventions

The existing walk standards require diagnostic-only hand commands and zero-touch
product behavior: `docs/S10.3-boxwalk.md:11-17,77-119`. The recovery walk adds
that staging is declared and separate from procedure, refusals must leave the
target row unchanged, and a witness must be alive across the certified window
at `docs/S13-boxwalk.md:63-76`. It also requires prerequisites and provenance
to be staged before the clock-dependent legs at `docs/S13-boxwalk.md:80-124`,
with evidence committed during the session under `walk-artifacts/`.

Options:

- **H6-A — dedicated F04 live box-walk with negative and continuity legs
  (RECOMMENDED, HELD).** Walk credential refusal classes (human, cross-org,
  revoked, bearer), no-oracle responses, cold-start disable, last-good during
  CP outage, recovery after restart, concurrent reports, and secret absence in
  captured poll/report traffic. Use zero-touch, declared staging, live-window
  witnesses, and committed artifacts.
- **H6-B — extend the existing node control-channel walk.** Cheaper setup and
  reuses live mTLS/health infrastructure, but can conflate F04 bearer semantics
  with the existing node identity channel and hide missing negative cases.
- **H6-C — local integration substitute only.** Fast and repeatable, but under
  the repository rule it is a substitute, not story completion; it cannot
  certify proxy behavior, restart persistence, or wire-level secret absence.

## Smallest common product slice after disposition

After H1/H2/H4/H5/H6 are ruled, the smallest implementation common to every
option is the security-and-state seam, not the transport or UI:

1. Hash the presented runtime credential and resolve one uniform authenticated
   principal bound to exact org + live agent device; refuse every other
   principal without an existence oracle.
2. Add pure validation for the locked revision and bounded-error contract, plus
   org-scoped monotonic SQL transition tests for poll/report inputs.
3. Define one secret-free runtime snapshot/report DTO that every selected
   transport carries, leaving local private-key ownership explicit.
4. Add the already measured single-flight/last-good CLI tests as the client
   compatibility gate.

This slice can back long-poll, short-poll, or streaming transport and any
licensed opt-in choice. It must not choose cadence, ownership of disputed
fields, retry thresholds, edition entitlement, or credential rotation.

## Production runtime execution contract (LOCKED)

The F04 library reconciler is not a shipped process. The following contract
was approved on 2026-08-14 and is now the implementation boundary.

### Recommended contract

- **Binary:** `tunnex-agent-runtime`, a separate managed-agent executable. It
  is not `/usr/local/bin/tunnex-node` and is not a mode of the human `tunnex`
  CLI.
- **Service:** `tunnex-agent-runtime.service`, systemd-managed, enabled only
  by an explicit managed-agent install/bootstrap action.
- **Files:** `/etc/wireguard/runtime.conf` (0600, contains the local private
  key and server-owned mutable fields; the standard path is required by the
  enforced Ubuntu 26.04 `wg-quick` AppArmor profile),
  `/etc/tunnex-agent/runtime-credential` (0600, runtime bearer), and
  `/var/lib/tunnex-agent/runtime-state.json` (0600, applied revision and
  client version). The state directory is distinct from
  `/var/lib/tunnex-node` and `~/.config/tunnex`.
- **Identity/capabilities:** the current narrow slice runs as `root` because
  the approved installer contract creates root-owned 0600 config, credential,
  and durable-state files. `CapabilityBoundingSet=CAP_NET_ADMIN`,
  `AmbientCapabilities=CAP_NET_ADMIN`, `DeviceAllow=/dev/net/tun rw`, and
  explicit `ReadWritePaths` retain the narrow systemd boundary. The unit sets
  `NoNewPrivileges=false` because Ubuntu 26.04's enforced `wg-quick` AppArmor
  profile must transition into its `ip` and `wg` child profiles; live audit
  evidence proved that `true` blocks those transitions before the bounded
  capability can be used. All other hardening remains in force, and this
  exception is scoped to the managed runtime unit. The unit's address-family
  allowlist includes `AF_NETLINK` because the bounded `wg-quick` control path
  requires netlink to create/configure the WireGuard interface; an exact
  matched-unit proof rejected the prior list with `Address family not
  supported by protocol`. No other address family is added. A future
  privileged-helper split may return the process to an unprivileged identity;
  it must not receive or log the runtime bearer.
- **Retry/loop:** perform an immediate poll, then bounded long-poll requests
  with a ticker safety net. Transport/apply failures use bounded exponential
  backoff with jitter; after a successful apply, retain the last-good config.
  Cold start with no valid config disables the interface and reports only a
  stable error code.
- **Apply:** preserve the local private key byte-for-byte, validate the
  secret-free server snapshot, render a candidate beside the current config,
  atomically replace it, and apply through the privileged boundary. A failed
  apply leaves both the active config and last-good revision unchanged.
- **Revoke:** the next poll/report receives uniform 401; after successfully
  disabling the peer, the runtime exits cleanly so `Restart=on-failure` leaves
  the service inactive. The unit remains enabled and rechecks authorization on
  boot; it receives no self-disable or `/etc/systemd/system` write privilege.
  A disable failure remains nonzero. Removing the unit and local runtime
  credential/state belongs only to the explicit uninstall procedure.
  Bootstrap failure must preserve any pre-existing fixed config and credential
  files.
- **Pending approval:** a valid credential bound to a pending agent receives a
  no-config wait, never revision data. The cold runtime keeps the interface
  absent and polls with bounded backoff until approval. Pending is not treated
  as terminal revocation; suspended/revoked/deleted credentials remain uniform
  unauthorized offboards.
- **Packaging/version:** ship the binary and unit from one versioned release
  artifact; the runtime reports the binary’s bounded build version. Package
  installation must validate `wg` plus the documented resolver dependency
  (`resolvconf` or `openresolv`) before writing runtime state or enabling the
  service.

### Alternatives

- **A — extend `tunnex-node`:** rejected. That binary is the gateway mTLS
  agent with root/NET_ADMIN, host networking, and `/var/lib/tunnex-node`; it
  has a different identity, trust channel, and blast radius.
- **B — add `tunnex agent run`:** possible for developer operation, but not
  sufficient as the production contract without a separately packaged unit,
  privilege boundary, paths, and restart policy.
- **C — reuse human CLI state:** rejected. `~/.config/tunnex/credential.json`
  is a human bearer credential and `device.conf` is a human one-time profile;
  neither is an agent runtime secret/config contract.

### Exact stop condition

Do not claim F04 runtime completion until the binary/unit ownership, paths,
identity/capabilities, retry policy, resolver prerequisite, and
revoke/offboarding behavior are exercised by the tests below, and the
current-head generated/default+enterprise/repository gates pass. The two live
runs must be counted by coverage, not duplicated: root's live run supplies the
real WireGuard interface, gateway peer/handshake, revision 1, restart
persistence, and revoke-triggered interface removal; the F2 shipped-runtime
run supplies CP outage last-good byte/revision retention, proxy recovery,
restart poll/report, overlapping wire reports, and secret-free fingerprints.

### Joint live coverage ledger

| Acceptance leg | Authoritative evidence | SATISFIES status |
|---|---|---|
| Apply, real interface, gateway peer/handshake, revision 1 | Root's current-runtime live run | SATISFIES |
| CP outage preserves last-good config/revision/interface/peer | F2 shipped-runtime run; proxy stopped for 7 seconds | SATISFIES for shipped control path; F2 peer fingerprint is container-shimmed |
| Recovery and report | F2 run: poll 204/report 204 after proxy restore | SATISFIES |
| Restart persistence | Root real-runtime restart plus F2 container restart | SATISFIES |
| Concurrent/overlapping monotonic reports | F2 wire reports both 204 with admin applied/attempted=1; PostgreSQL service contract final state 3/3 | SATISFIES |
| Revoke and interface removal | Root's current-runtime live run | SATISFIES |
| No-oracle refusal classes | F2 live matrix, identical normalized 401 hash | SATISFIES |
| Secret absence | F2 projected poll/report/refusal headers/bodies plus runtime fingerprints | SATISFIES |

### Production-entrypoint acceptance test names

- `TestManagedAgentBootstrapCreatesRuntimeStateWithoutLoggingSecrets`
- `TestManagedAgentRuntimeEntrypointPolls204AppliesReportsAndCancels`
- `TestManagedAgentRuntimeLongPollTickerAndBoundedBackoff`
- `TestManagedAgentRuntimeApplyPreservesPrivateKeyAndLastGoodConfig`
- `TestManagedAgentRuntimeRestartPersistsAppliedRevision`
- `TestManagedAgentRuntimeRevokedCredentialStopsAndDisables`
- `TestManagedAgentRuntimeMissingResolverLeavesNoPartialState`
- `TestManagedAgentRuntimeFailedStartPreservesExistingFiles`
- `TestManagedAgentRuntimePackageUsesDedicatedIdentityAndPaths`
- `TestManagedRuntimeStateRefusesLegacyEmbeddedCredential`
- `TestRunWireGuardQuickDownOnlyIgnoresAbsentInterface`

## Status

The recommended set was approved by the user on 2026-08-14. The common
security/state and production-runtime slices are implemented and the semantic
plus joint live review is recorded in `docs/F04-runtime-acceptance-review.md`.
F04 remains In Progress pending the current-head repository gate bundle,
independent refold review, and exact-source live rerun; no plan status is
changed here. The former cross-org route-test mismatch is closed: the test now
asserts the established 404 no-oracle behavior. F02 is independent and its
status is not changed here.

### Locked systemd restart-rate disposition

The real Colima systemd proof exposed that `StartLimitIntervalSec=60s` and
`StartLimitBurst=6` were placed in `[Service]`; systemd reported the interval
key as unknown and used its default effective interval instead. The user
approved the narrow correction: both directives belong in `[Unit]`, must be
absent from `[Service]`, and the rest of the hardening remains unchanged.
The retained F3 Colima harness must verify `systemctl show` reports an effective
60-second interval and burst 6, alongside `systemd-analyze verify`.
