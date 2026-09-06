# Epic: automatic NAT traversal and customer-hosted relay

Status: development plan, not implemented or acceptance-tested by this document.
Planned against main `231f63f493641caacb2ff3d2f409f7ac06825b24` on 2026-09-06.
Story namespace: NAT. Independent of the AI gateway epic.

## Customer outcome

An employee can reach an authorized private application when a direct UDP path
to the Tunnex gateway is unavailable. Tunnex tries a direct path and falls back
automatically to a customer-hosted relay. The employee does not configure TURN
servers, open router ports, or change application URLs.

WireGuard remains the end-to-end encryption and network-policy boundary. A relay
forwards encrypted traffic; it is not a replacement gateway, DNS resolver, or
authorization service. Customer relay infrastructure must itself be reachable.
Some corporate proxies can block TURN even on port 443: do not promise universal
connectivity or disguise TURN/TLS as HTTPS.

## Reuse first; prove the transport before building the product surface

| Responsibility | Decision |
| --- | --- |
| ICE candidate gathering, connectivity checks and nomination | Reuse Pion ICE; do not implement ICE or STUN |
| STUN/TURN server, including TURN over TCP/TLS | Reuse upstream coturn container, pinned by version and digest |
| Traffic encryption and existing access rules | Preserve current WireGuard and Tunnex authorization |
| Transport integration | Build a narrow adapter for encrypted WireGuard datagrams, not a new VPN protocol |
| Signaling, credentials, policy and diagnostics | Integrate with existing CP, node and desktop lifecycle |
| Relay deployment | Customer-hosted; reuse Compose/Helm installation conventions |

Pion ICE is MIT-licensed and coturn is BSD-3-Clause. Record exact versions,
licenses and advisories in the implementation decision paper before adoption.
Do not copy another VPN's relay implementation based on its project name or
headline license; subdirectories may have different terms.

**The critical uncertainty:** coturn is not a drop-in WireGuard relay. Desktop
helpers use userspace WireGuard while Linux gateway networking uses kernel
WireGuard. A working adapter must preserve endpoint ownership, authenticated
peer mapping, return traffic and route exclusions on both sides. Evaluate a
userspace bind adapter and a per-peer local UDP bridge in the proof; choose one
supported design based on real packet flow. Do not replace the whole gateway
network stack to make the first demo pass.

## Bounded development stories

Points are relative complexity estimates, not elapsed days. Re-estimate once
NAT-0 resolves the transport risk. Each story has one independently reviewable
outcome; no implementation PR is required for this planning-only commit.

| Story | Pts | Outcome and acceptance | Depends on / repositories |
| --- | ---: | --- | --- |
| NAT-0: transport feasibility | 3 | Timebox to two engineer-days. Pin upstream versions; connect a real macOS helper to a Linux gateway through coturn TCP/TLS with direct UDP deliberately blocked. Reach one authorized private service; deny one unauthorized service. Capture redacted packet-path evidence and select the adapter, or stop with a precise blocker. | None; tunnex-client + tunnex |
| NAT-1: authenticated connectivity session | 3 | CP binds candidates, relay credentials and session generation to tenant, device and gateway. Expired, replayed and cross-tenant signaling is rejected; coturn credentials are short-lived and rate-limited. Existing direct clients remain compatible. | NAT-0; tunnex |
| NAT-2: automatic direct/relay transport | 5 | Ship the proven adapter on gateway and macOS/Windows helpers. Exercise direct, failed-direct-to-relay, relay interruption and bounded reconnect. Relay IP routes avoid the VPN routing loop; MTU and return paths work. No plaintext application fallback. | NAT-1; tunnex + tunnex-client |
| NAT-3: lifecycle and isolation | 3 | Revocation terminates forwarding within a documented bounded interval, not merely on the next credential issue. Network changes and helper/gateway restarts cannot reuse a stale authorized session. Limit allocations and bandwidth; prevent unauthenticated relay use and cross-tenant forwarding. | NAT-2; tunnex + tunnex-client |
| NAT-4: install and explain the connection | 3 | Opt-in customer-hosted coturn deployment with valid TLS, explicit ports, scoped secrets and rotation. Reuse upstream chart if qualification passes, otherwise keep a thin deployment wrapper. UI/CLI report direct vs relay, last failure and recovery guidance without exposing credentials. | NAT-1 contract; tunnex + tunnex-web, final integration after NAT-3 |
| NAT-5: real-network beta qualification | 3 | Pass the compact matrix below on actual desktop helpers and a Linux gateway. Publish setup/troubleshooting and bandwidth-cost guidance. Preserve default direct behavior and demonstrate feature-disable rollback. | NAT-2–4; all three repositories |

Total initial estimate: 20 points. NAT-0 is a go/no-go checkpoint, not an excuse
to extend an unsuccessful prototype indefinitely. If the adapter requires a
major architecture change, return a separate decision and estimate before
expanding the epic.

## Fast execution order

1. One transport owner completes NAT-0 before parallel production work starts.
2. Freeze the session/capability and diagnostic schemas. CP/signaling,
   helper/node transport, and deployment/UI can then proceed in parallel using
   contract fixtures. Keep one integration owner across tunnex and tunnex-client.
3. Land small compatibility-preserving PRs behind an off-by-default flag; record
   required client/server versions explicitly. Website instructions must name
   released versions, not an unreleased main build.
4. Run focused tests on each change; run the full repository-required final
   gates on the final content SHA. Reuse valid evidence for unchanged scenarios;
   rerun the scenario affected by a fix and its adjacent security boundaries.

NAT-4 can start after NAT-1's contract without waiting for every recovery test.
Do not block this epic on AI work, provider-specific cloud provisioning, or a
global managed relay fleet.

## Minimal proof matrix and release bar

| Scenario | Required proof |
| --- | --- |
| Direct UDP available | Direct selected; existing private IP/FQDN access unchanged |
| NAT/direct path unavailable | Automatic TURN path; actual allowed request succeeds; denied resource still denied |
| UDP unavailable but TURN/TLS reachable | Actual WireGuard traffic passes over TURN/TLS, not just a successful ICE handshake |
| Relay unavailable or blocked | Bounded failure with useful diagnosis; no plaintext or policy bypass |
| Auth lifecycle | Expiry, revocation, tenant isolation and credential rotation behave as documented |
| Device lifecycle | macOS and Windows network switch/restart plus Linux gateway restart recover without manual repairs |
| Routing and performance | Relay route exclusion, bidirectional traffic, useful MTU and recorded latency/throughput overhead |

Automate signaling/auth failures and deterministic network cases. Use a small
real-network walkthrough for OS integration, not repeated full cloud rebuilds.
Store only redacted evidence with component SHAs, pinned upstream versions,
network condition and result. If a remedial patch is necessary, the repaired
case must be rerun from the supported install path before counting it as passed.

Beta requires both supported desktop platforms, no open critical/high isolation
or routing defect, story-end review and applicable exact-final checks. A macOS
prototype alone is not a cross-platform beta. This epic does not silently close
existing Windows crash-recovery or ordinary host-rebootstrap deferrals.

## Deliberate exclusions and operational ownership

- No device-to-device full mesh, new native WireGuard-client support, mobile
  client, Tunnex-operated relay fleet, or global relay autoscaling in this epic.
- No changes to DNS authorization, internal service discovery or FQDN semantics.
- No promise to bypass arbitrary corporate HTTP proxies or inspection policies.
- Customer owns the reachable relay host, certificate, bandwidth and cloud bill;
  Tunnex supplies supported configuration, credential lifecycle and diagnostics.
- Keep allocation/traffic metadata minimal; do not log secrets or packet payloads.
- Existing self-hostable-relay constraints remain intact; client-to-gateway
  fallback is distinct from the older deferred device-to-device mesh proposal.

## References

- [Pion ICE implementation and license](https://github.com/pion/ice)
- [coturn implementation and supported transports](https://github.com/coturn/coturn)
- [coturn license](https://github.com/coturn/coturn/blob/master/LICENSE)
- Existing baseline: [self-hosting](self-host.md),
  [network decisions](S7.5.1-decisions.md),
  [FQDN access resources](EPIC-21-fqdn-access-resources.md).
- Companion: [identity-based AI gateway](EPIC-ai-gateway.md).

External capabilities reviewed on 2026-09-06; implementation must qualify a
specific upstream release rather than assume a floating branch is a contract.
