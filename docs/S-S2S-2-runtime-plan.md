# S2S-2 — Proposed Linux IPsec runtime plan

Status: initial design retained as historical context, updated 2026-09-24. Foundation and retained-guard cleanup disposition are approved. Dedicated strongSwan6.1.0 packaging, authenticated delivery, lifecycle API, policy projection, serialized controller/journal, actual platform probe and default-off node wiring are implemented locally. The [completion contract](S-S2S-2-completion.md) tracks current evidence and remaining integrated native/API/UI gates. Existing deployed nodes are unchanged. The new local candidate can report capability1 on actually qualified LinuxARM64; nativeAMD64 remains pending and refused. No publication or complete release readiness is claimed.

## Implemented boundaries

The pure evaluator remains logic evidence only. Independent VICI, kernel XFRM/route/interface and firewall readback now feed the serialized controller. Secure material delivery commits its cleanup obligation before responding, and private node polling acknowledges only exact completed apply/cleanup. Startup restores saved refusal before forwarding or daemon startup; new installations discover opt-in without binding IPsec ports while disabled. Missing-journal cleanup proves absence without adopting matching objects.

The sections below record the original design alternatives. Later [delivery](S-S2S-2-runtime-delivery.md), [enforcement](S-S2S-2-enforcement-contract.md), [packaging](S-S2S-2-packaging-plan.md) and cleanup contracts govern their implemented dispositions. Candidate allocator ranges and earlier unimplemented statements are not current acceptance evidence.

## Candidate and ownership

Propose a dedicated strongSwan `charon` instance controlled by the existing Tunnex node through VICI, over a node-owned Unix socket. VICI provides configuration, control and observation, but has no built-in authentication; its documentation recommends restricted Unix sockets. Library choice remains open; the official page links a Go client, whose version and licence still need review. [Official VICI documentation](https://docs.strongswan.org/docs/latest/plugins/vici.html).

Proposed operational boundary:

- One node supervisor owns its daemon lifetime, private runtime directory, socket, configuration names and credentials. No TCP listener, shared host daemon adoption or arbitrary user-supplied daemon configuration.
- A root-owned directory and narrowly permitted socket keep other workloads from issuing control commands. The node verifies socket ownership/type and daemon identity before accepting control readiness. Container and host deployments need separate qualification; do not mount the socket into the web/API containers.
- PSKs arrive only through the authenticated assigned-node channel after a durable delivery obligation exists. Pass them through bounded in-memory VICI requests, never argv, environment, diagnostic events, request logs or generated downloadable files. Keep debug/control-log payloads out of product logs. No claim that all runtime copies can be erased from memory.
- A reviewed packaging slice must select/pin the daemon, VICI/kernel plugins and client dependency, include notices/source obligations and verify binaries in the final image. strongSwan publishes GPLv2 and commercial licensing information; this is not a distribution compliance determination. [Official licensing](https://strongswan.org/license.html).

## Current source seams

| Source | Existing behavior | Required integration boundary |
| --- | --- | --- |
| `apps/node/internal/reconcile/reconcile.go:409` | Applies policy callback, then WireGuard peers/routes | Add an explicit result-bearing IPsec enforcement stage; no success acknowledgement from a callback that only logs failure. |
| `apps/node/cmd/agent/main.go:350` | Policy callback logs egress reconciliation failures | Runtime activation must wait for successful enforcement/readback and remain blocked on error. Preserve existing WireGuard behavior. |
| `apps/node/internal/reconcile/reconcile.go:465` | Compiled routes feed the WireGuard backend | IPsec paths need a separate transport/ownership representation; do not inject them into current WG route intent. |
| `apps/node/internal/reconcile/wgctrl_linux.go:949` | Prunes routes using WG interface, protocol and metric | Independent IPsec owner must neither adopt nor delete WG/host routes. |
| `apps/node/internal/egress/egress_linux.go:356` | Authenticated tunnel set contains WG/optional OpenVPN | Add only verified owned XFRM interfaces, never the physical LAN interface. |
| `apps/node/internal/egress/egress_linux.go:746` | Ordinary native forwarding bypasses tunnel adjudication | XFRM ingress/egress must be excluded from this bypass before carrying traffic. |
| `apps/node/internal/egress/egress_linux.go:535` | nft transaction preserves prior rules on failure | Failed replacement is not evidence that a newly revoked IPsec path is blocked. Retain a separately verified refusal boundary. |
| `apps/node/internal/egress/egress_linux.go:553,775` | Removed-grant conntrack cleanup; established flows accepted early | Revocation/disable must block established IPsec flows too and prove scoped conntrack cleanup. |
| `deploy/docker/node.Dockerfile` | Existing WG/OpenVPN/iproute2/nft runtime packages | No IPsec daemon is packaged by this plan. Add and inspect required binaries/plugins only after engine disposition. |

`deploy/systemd/tunnex-agent-runtime.service` belongs to the managed client runtime, not automatically this gateway daemon. Do not reuse or loosen that service's permissions as a shortcut. Locate the actual selected gateway installation path before host packaging changes.

## Proposed XFRM and policy boundary

Official documentation links XFRM interfaces to SAs/policies by interface ID. A routed interface without matching SAs drops traffic, but missing interfaces leave outbound policies ineffective. It also documents peer-routing loops and limitations of outbound Netfilter IPsec policy matching; explicit interface matches are supported. [Route-based VPN documentation](https://docs.strongswan.org/docs/latest/features/routeBasedVpn.html).

The following are Tunnex design requirements, not guarantees obtained merely by selecting XFRM:

1. Allocate two distinct, collision-checked interface IDs and stable ownership names from authoritative node/connection/tunnel identities. Readback must match interface kind, ID, namespace and the complete route/rule ownership tuple. Refuse foreign collisions; never overwrite an interface based on name alone. Allocation/reservation persistence is a decision gate.
2. Give the node sole route ownership; disable daemon route installation for its instance. Reserve routing table/protocol/metric/mark space after a live conflict check. Never run global route, XFRM, credential or nft flushes.
3. Before making a route eligible, install and verify an independent destination/ingress refusal boundary for protected traffic. A missing SA, deleted interface, lost route, daemon crash or unsuccessful cleanup must not send protected packets through the ordinary default route. Include host-originated OUTPUT and forwarded traffic, both address families accepted by the profile, and established conntrack flows. Reject unsupported families before activation.
4. Permit traffic only using authenticated tunnel identity plus approved source/destination/protocol policy. CIDR identity alone cannot distinguish forged physical-LAN traffic. Scope anti-spoof, reverse direction, WG/IPsec transit and NAT behavior explicitly; no automatic broadening of shared site grants.
5. Keep IKE/ESP/NAT-T peer transport outside protected payload routing using an explicit reviewed mark/rule scheme. Validate interaction with existing marks and policy tables before choosing numeric values. Peer addresses never become payload bypass grants.
6. Fail activation on policy/readback failure. Preserve denial while retrying. Successful VICI commands and installed routes are configuration evidence, not packet-delivery proof.

## Proposed two-tunnel behavior

Initial scope is two configured tunnels with one selected outbound path per connection, no ECMP or BGP implementation. Establish/observe both independently; select only a tunnel whose assigned revision, CHILD_SA, owned XFRM objects and enforcement all match. Keep inbound handling safe for either authenticated tunnel because the remote peer may select a different return path. Cross-cloud/provider compatibility remains a separate test claim.

Use an explicit deterministic preference and bounded failover hold-down, with their values documented before code. Do not switch on a single delayed event or stale snapshot. Daemon events wake reconciliation; fresh complete observation is authoritative. If neither path qualifies, retain refusal routes/rules. Route replacement must be ordered so no transient ordinary-route fallback occurs. Report desired revision, application result, per-tunnel SA observations and selected outbound path separately; none means verified end-to-end traffic.

## Proposed delivery, cleanup and restart protocol

- Control plane marks the exact assigned revision as potentially delivered in a transaction before exposing secret material. Recheck assignment, certificate revocation, organization intent and revision inside the delivery boundary. A timeout or process crash retains cleanup owed.
- Node serializes apply, revoke, route switch and cleanup on its existing command lane. Before mutating the host, reserve a durable non-secret ownership record. Reject stale revisions. Startup first reinstates refusal and inventories daemon/kernel objects, then fetches current desired state; disk intent alone cannot reactivate a connection.
- Disable/delete first revokes payload permission, including established flows; verifies refusal; prevents automatic reinitiation; unloads owned connection definitions; terminates all owned/rekey-overlap SAs; removes owned shared credentials; removes forwarding objects while retaining any needed refusal boundary. Only exact owned objects may be touched.
- VICI has targeted termination, shared-secret unload and enumeration operations. Use bounded deadlines and re-enumeration; a command return alone does not prove cleanup. Never substitute global credential clearing. [Official VICI protocol operations](https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/vici/README.md).
- Acknowledgement is allowed only after readback establishes no owned active SAs/policies, no usable forwarding path, no loaded credential/configuration capable of recreation, and no relevant established flow. Define explicitly whether retained safety-only refusal objects count as finalized cleanup; their ownership must survive any release of identity references. This requires a persisted lifecycle disposition.
- Bind acknowledgement to authenticated assigned gateway, desired revision and cleanup result. Lost responses replay the exact result without new effect. Unknown/disconnected/revoked gateways remain pending; neither TTL nor administrator assertion proves host cleanup. Retain tombstones as the approved lifecycle requires.

## Bounded implementation sequence after disposition

1. Approve engine/packaging/client choice, kernel support floor, ownership allocator, single-path policy, durable restart record and exact acknowledgement/finalization predicate. Fix numeric routing identifiers and failover timing through the reviewed plan, not incidental implementation defaults.
2. Write pure intent/observation reducer and fake VICI/kernel tests first. Prove stale revisions, missing observations, collision refusal, deadline handling, rekey overlaps and no secret serialization. These tests do not qualify runtime capability.
3. Add isolated Linux namespace lab adapter tests for owned XFRM/readback and refusal boundary. Prove allow/deny, LAN spoof refusal, no cleartext fallback on each object loss, established-flow revocation, unaffected WG/host routes and recovery after crash at every stage. No cloud resource needed for this gate.
4. Add transactional delivery/cleanup state schema and authenticated endpoints with regression-first database races: revoke versus delivery, delete versus acknowledgement, opt-out versus enable, duplicate/conflicting/stale acknowledgements. Do not broaden the current disabled-only schema before these decisions/tests.
5. Package and qualify the daemon in the supported node deployment, then permit capability version 1 only after all required local probes pass. Run separate two-tunnel traffic/failure/provider acceptance before enabling production activation UI or making AWS support claims.

All work remains local until the user requests publication. This paper does not change current eligibility, create an IPsec connection or install a daemon.
