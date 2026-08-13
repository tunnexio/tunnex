# EPIC — Site Connectivity Experience

Status: **registered / decision-first; no implementation authorized by this paper.**

**Roadmap boundary:** SCX-7 through SCX-9 are **post-beta roadmap** items. They are recorded so
the beta does not grow into monitoring/MTU/DNS work; no implementation starts before the Founder
opens the post-beta planning window.

**Related but separate:** cloud gateway VM provisioning, billing ownership, and retirement are
owned by `docs/EPIC-gateway-provisioning-lifecycle.md`. This Epic consumes an enrolled gateway;
it must not silently acquire infrastructure ownership.

## Founder outcome

An owner should be able to create and operate a site-to-site connection primarily from Tunnex:
choose sites and gateways, understand the required cloud-fabric changes, prove behind-host
connectivity, and distinguish overlay HA from real cloud-route failover. The same model must work
for two gateways in one cloud/VPC/VNet, gateways across clouds, and customer-operated on-prem
networks.

The cross-cloud AWS/Azure walk on 2026-08-12 is the evidence source. It reached live bidirectional
behind-host traffic, but required manual discovery and cloud CLI actions for forwarding, firewall,
and routing. It also exposed a network-map projection defect: a primary gateway that belongs to a
site appears both as the synthetic hub and as the site gateway.

## Product acceptance

1. A guided Site Connectivity flow creates sites, binds enrolled gateways, advertises/approves
   CIDRs, and makes bidirectional policy intent reviewable before applying it.
2. It clearly separates **Tunnex overlay state** (enrolment, policy, WireGuard link, elected hub)
   from **cloud fabric state** (NIC forwarding, source/destination check, firewall/NSG/SG, and
   subnet route-table next hop). Neither layer may be shown healthy on the strength of the other.
3. The operator can run a bounded, named source-to-destination reachability check and receive
   actual packet loss/RTT/error evidence. The UI must never manufacture “reachable” status from a
   gateway handshake.
4. The Network map shows each logical site once. Gateway placement and HA roles are annotations of
   that site, not duplicate topology vertices. A site-to-site edge represents the actual
   relationship.
5. HA states are explicit: **overlay failover ready** and **cloud-route failover ready** are
   independently measured. A static VPC route to a single ENI is never represented as automatic
   end-to-end failover.
6. A no-cloud-connector customer still gets exact, reviewable provider instructions and can record
   completion; a connector-enabled customer can complete only the provider permissions it has
   explicitly granted.
7. Vault-backed cloud automation is optional. A customer who supplies neither Vault access nor
   cloud credentials still receives the complete guided setup, preflight checklist, rollback plan,
   and traffic validation workflow.
8. On-prem is a first-class fabric, not a cloud fallback: it uses the same site, gateway, HA,
   preflight and validation model. Provider-specific cloud fields are absent when not measured;
   the on-prem equivalent is an operator- or connector-reported router/firewall/next-hop fact.
9. Once a customer has approved the initial gateway pair, provider route plan, and automation
   permission, an eligible cloud-fabric failure is handled without an operator changing a route
   during the outage. Tunnex must promote, change only the pre-approved local-cloud next hop,
   validate behind-host traffic, and retain evidence of every transition.

### Recommended topology default

Use **hub-and-spoke** for site connectivity. Each site owns a local primary/standby gateway pair;
the cloud route remains local to that site, while Tunnex coordinates the overlay and provider
route failover. This contains policy, health and failover state as sites grow. Do not promise a
cross-cloud route target: AWS/Azure route tables must point at a reachable local gateway.

Selective direct site-to-site mesh is a later, explicit optimization for a named high-throughput
or latency-sensitive pair. It is not the default topology and must not create an unbounded
all-sites mesh or a separate policy/failover model.

## Non-goals

- No CP-held unrestricted AWS/Azure credentials, Docker socket, host root, SSH private keys, or
  arbitrary remote command execution.
- No generic subnet scanner, port scanner, or free-form target probe from the control plane.
- No claim that a WireGuard handshake proves behind-host traffic.
- No automatic cloud route change until a provider-specific health, rollback, and ownership design
  is ruled.
- No requirement that a customer use AWS, Azure, Vault, or any cloud connector to create a site.
- No change to routing/policy reconciliation in the visualization slice.

## Current evidence and reuse

- Existing Sites UI owns site enrolment, route approval, hub priority and site-to-site policy
  surfaces.
- **Failover walk (2026-08-12):** in the AWS/Azure two-site layout, deliberately stopping the
  AWS primary gateway container caused CP to demote the primary after **4m 11.694s**. The AWS
  behind-host to Azure behind-host probe first recovered after **4m 59.362s** total packet loss,
  only after an operator repointed the AWS route to the verified local standby ENI. Restoring the
  original gateway took **2m 29.561s** for CP to accept it for failback; the route was then
  deliberately returned and the final behind-host ping was 5/5 at about 124 ms. This proves
  overlay promotion and local-standby forwarding, but also proves that current cloud-route
  failover is manual. No enrolled desktop-client probe participated, so this walk does not claim
  an exact client-device outage.
- Existing map projection adds a synthetic `__hub` plus one node per site; the same primary gateway
  can therefore be represented twice.
- Current UI correctly documents that AWS ENI routes and Azure UDRs are cloud-owned steps, but it
  only renders static prose.
- The provider-neutral manual path is the on-prem baseline: gateway forwarding plus upstream
  router/firewall routes are customer-owned facts, not cloud-console abstractions.
- The existing node-agent desired-state channel is the appropriate Tunnex-owned seam for
  reconciliation evidence; ad-hoc `wg set`/iptables cannot become a product mechanism.

## Proposed slices

### Slice 0 — paper and state contract

Define provider-neutral `SiteConnectivity` state, evidence timestamps, permission boundary, audit
events, all allowed state transitions, and a red matrix. Rule the decide-items below before code.

### Slice 1 — role-aware network map

Replace synthetic hub duplication with a logical-site graph. Render the inter-site links once;
render `primary`, `standby`, `promoted`, and `unavailable` as gateway annotations. Make all
unavailable facts absent/unknown when they were not measured. Include empty, one-site, same-cloud
HA, cross-cloud HA, and long-label visual proof.

### Slice 1a — gateway fleet truth

Expose the actual gateway build identity (release version, immutable image digest/source revision,
and compatibility state), not only the current coarse agent protocol/version string. Surface
certificate renewal health and next expiry without exposing credential material. Render overlay
HA and cloud-fabric HA as separate facts: active overlay hub, configured standby, current cloud
next-hop, and whether a tested automatic or manual route-switch plan exists. Reduce no-op
reconciliation log noise so meaningful forwarding/policy failures remain visible. This slice does
not automatically upgrade a gateway or mutate cloud routes.

### Slice 1b — site and gateway operations UI

Replace the current mixed table, card and topology-toggle experience with a site-first master/detail
surface. The left side is a compact logical-site list with CIDR, active-path health and an explicit
attention state; selecting a site opens one operational detail surface rather than duplicating the
same facts into several cards. Gateway membership stays an annotation of the selected site.

High availability is one guided state model, not raw pin/unpin mechanics. The operator sees
`No pair configured`, `Ready`, `Failover active`, `Validating`, `Manual cloud action required`, or
`Automatic transition armed`, with the current active gateway, preferred primary, eligible standby,
overlay evidence and cloud next-hop shown as separate facts. The actions are phrased as **Set preferred
primary**, **Add standby**, **Remove standby**, and **Start controlled failover**. A disruptive change
always previews the resulting order and its effect; an unavailable action explains which measurable
precondition is missing. “Unpin” remains an implementation verb, never the primary product action.

The detail surface uses a compact lifecycle rail: Site identity and ranges → Gateway pair → Overlay
health → Cloud-fabric route → DNS/service discovery → Validation history. Each phase may link to an
action, but an unmeasured phase renders as unknown/required rather than a reassuring empty card.
Overlay readiness, cloud-route readiness, DNS-forward availability and end-to-end validation are
intentionally independent rows. The UI includes an exact transition timeline and a copyable runbook
whenever automatic cloud action is not armed.

Before product implementation, produce a local clickable visual proof with a single-gateway site,
a healthy local primary/standby pair, an active failover, long names/CIDRs, unavailable provider facts,
and keyboard/assistive-text labels. The review must answer the absence questions: every reachable
site/gateway/HA mutation has a named call-site or an intentional refusal, and every destructive
membership action describes its resulting site topology.

**Current UI audit — 2026-08-12.** The Gateway table's healthy/degraded filters, site subtitle,
terminal revoke confirmation and explicit NAT requirement are good operational foundations and
must be preserved. The Sites surface already avoids repeating full cards per site, but the live
page still mixes a network map, selected-site actions, an HA card, raw pin controls, a table and
repeated setup teaching. The result makes a normal operator reconstruct one site's condition from
several places. The visual proof must keep the selected logical site as the primary object: its
members, route, DNS and validation history live in one detail pane; the gateway inventory links
into that detail rather than duplicating a topology control.

Gateway version/provenance and certificate-expiry status belong on the inventory/detail only when
reported, with an explicit "not reported yet" state and troubleshooting action rather than `n/a`.
Any action that can move devices, unbind a gateway, delete a site or alter active preference must
preview the server consequence and link the resulting audit event. Overlay health, cloud-fabric
next-hop health, DNS-forward health and source-to-destination proof remain separate timestamped
facts; a fresh handshake cannot stand in for them.

### Slice 2 — guided site connectivity UI

Create a review-first flow: site CIDR, gateway, direction/policy summary, provider fabric
requirements, and explicit rollback instructions. It consumes current Tunnex API seams rather than
reimplementing policy or hub election in the browser.

The fabric chooser begins with **On-prem / manual** and adds AWS, Azure, or another connector only
when the operator opts in. It asks for the equivalent facts — gateway LAN address, upstream route
owner, forwarding, firewall coverage, and rollback owner — without inventing VPC, ENI, or UDR
fields for an on-prem network.

### Slice 3 — cloud preflight connector contract

Define a customer-run, least-privilege connector that reports only required facts: gateway NIC
forwarding, route target, subnet association, provider firewall rule coverage, and source/dest
check. It returns provider evidence and an exact proposed mutation; the owner approves each
mutation in Tunnex before the connector applies it. Manual mode remains first-class.

**Optional credential source:** a customer may configure its own Vault for the connector. The
connector authenticates locally using the customer's chosen workload identity, requests a
short-lived policy-scoped cloud credential, applies the approved plan, then releases it. Tunnex
stores only connector identity, capability grants, plan digest, approval, and resulting evidence —
never a Vault token, lease secret, cloud access key, or client secret. A Vault outage degrades only
the automation action; it must not block manual guidance, existing tunnels, validation of already
configured paths, or recovery.

### Slice 4 — bounded traffic validation

Add an explicit validation job bound to a configured source and destination that are already inside
approved site CIDRs. Report actual ICMP/TCP outcome, loss, RTT, and failure phase. It must use a
customer-installed probe capability or another ruled source of truth; a gateway-only probe cannot
be labelled behind-host-to-behind-host proof.

### Slice 5 — provider-aware fabric HA

For same-cloud and cross-cloud layouts, surface the active cloud next-hop and its standby plan.
The default topology is hub-and-spoke with a local primary/standby pair per site; a site route
never targets a remote-cloud gateway. Automated route switching is separately enabled only after
provider-specific health, lease/leader, rollback and split-brain proofs. When it is enabled, the
customer approves the static route/permission plan at setup and Tunnex performs the pre-approved
local-cloud route transition, traffic validation and audit automatically during an outage. Until
then, present a tested runbook and explicit “manual cloud route failover required” status.

### Slice 5a — automatic failover controller and recovery experience

Turn the demonstrated manual path into one bounded, provider-aware state machine. It has distinct
states: `healthy`, `suspect`, `fenced`, `promoting overlay`, `switching local fabric route`,
`validating traffic`, `active on standby`, `recovering primary`, and `needs attention`. The
controller must never point an AWS/Azure route at a remote-cloud gateway: it changes only the
pre-approved **local** standby target for that site.

Promotion requires two independently reported facts: a gateway-agent control-health signal and a
bounded approved data-path probe. An ambiguous or contradictory result refuses automatic route
actuation and enters `needs attention` with the exact manual runbook. The health cadence,
miss threshold, and stability window are explicit configuration/evidence, not hidden constants;
the current measured 4m59.362s is the baseline, not a promised target. A sub-60-second P95
end-to-end recovery objective may be published only after provider-specific live walks prove it
without increasing false promotion risk.

The customer-run connector consumes one pre-approved, least-privilege route-transition plan. Each
provider call is idempotent, is fenced by the active failover lease/leader, records a plan/action
digest and before/after next-hop evidence, and has a bounded rollback path. A connector or
provider denial never fabricates recovery or retries an unbounded mutation; it preserves the
existing route and reports the blocked phase. Vault-backed short-lived credentials remain optional
under Slice 3; CP still stores no cloud secret.

The Site UI presents overlay and fabric truth separately: current active gateway, configured
standby, current cloud next-hop, whether automatic transition is armed, the exact state timeline,
last measured outage, validation source/destination provenance, and a copyable manual runbook.
It must explain that existing TCP sessions can reset during a path change rather than promising
session preservation. An enrolled-client probe is optional but, when configured, is displayed as
a separate client-impact measurement; a behind-host probe cannot be relabelled as client proof.

### Slice 5a acceptance and proof

1. Deliberately losing the active local gateway produces a fenced overlay promotion, one
   provider route transition to the approved local standby, and a successful source-to-destination
   proof; no operator route edit occurs during the outage.
2. A lost heartbeat without a corroborating path result, an expired connector lease, a denied
   provider action, and a stale completion each refuse safely and render their exact phase.
3. Recovery does not flap: the prior primary must satisfy the configured stability window before
   any controlled failback, and every route transition is attributable to one elected action.
4. The UI timeline and API evidence agree on timestamps, route targets, validation result and
   outcome; unknown client impact is absent, not inferred from gateway health.
5. The box walk measures both behind-host and, when enrolled, client-to-site downtime. It reports
   detection, promotion, route-transition, validation and total-recovery durations separately.

### Slice 6 — box walk

Prove a same-cloud two-gateway layout and a cross-cloud layout on real behind hosts. Each walk must
cover preflight failure, policy denial, successful bidirectional packet proof, overlay promotion,
cloud-route failover truth, and rollback. Unit tests substitute for no provider account, but do not
satisfy this live-wire proof.

### Slice 7 — continuous path assurance

Let an owner schedule a bounded, approved source-to-destination probe after the initial setup.
Show packet-loss/latency history, distinct failure phase, and owner-configured alert delivery.
The monitor is opt-in, rate-bounded, and has no ability to discover arbitrary hosts or ports.

### Slice 8 — path diagnostics and policy templates

Provide a reviewed MTU/path diagnostic and reusable site-policy templates such as full site link,
web-only, and deny-between-environments. Templates compile through the existing resource/policy
seams and remain normal editable/audited rules; they do not create a second policy language.

### Slice 9 — private service discovery handoff

Extend the existing cross-site DNS-forwarding surface with a clear site-local discovery and
troubleshooting experience. This story must not imply device reachability until the actual route
and policy facts say the device can reach the resolver.

Before a forwarded zone is saved, run a bounded **test-before-publish** preflight from the
declaring site's gateway: UDP/TCP reachability to the private resolver, an owner-supplied
representative query, resolver response code, and latency. A failed or unmeasured preflight
cannot be rendered as an enabled service. The resolver stays private: the agent listens only on
the WireGuard interface and forwards only declared zones; every other zone is refused.

The site detail renders each zone as an operational row, not an opaque card: zone, resolver IP,
owning site, last successful query and latency, last error, gateway revision, and a bounded
**Test** action. It explains domain conflicts before submission and makes removal's reconciled
scope explicit. Gateway forwarding proof and client/behind-host resolver installation are two
separate facts; macOS, Windows and selected site-host results must be individually marked
`unknown`, `passed` or `failed`, never inferred from a gateway query.

The live proof is: publish a temporary private zone through the supported CP surface, resolve it
from a remote gateway over the tunnel, prove an undeclared zone is refused, then remove the
forward and resolver fixture. A later device walk proves resolver handoff on each supported
desktop platform without exposing a public resolver or retaining test records.

## Story map and proof ladder

| Story | Deliverable | Required proof before the next story |
| --- | --- | --- |
| SCX-0 | Decision record, lifecycle/state model, RBAC/audit contract, red matrix | Review dispositions; red tests for forbidden state transitions and no-credential persistence. |
| SCX-1 | Role-aware logical-site Network map | Pure view-model tests plus visual proof for one site, two same-cloud gateways, two cross-cloud sites, unavailable data, and long names. |
| SCX-1a | Gateway fleet truth | Digest/revision and certificate evidence are provenance-safe; version drift is visible; overlay and cloud-fabric HA cannot be conflated; no-op reconcile cycle does not emit misleading INFO noise. |
| SCX-1b | Site and gateway operations UI | Local clickable visual proof; no raw pin/unpin primary action; role-change preview; visible overlay/fabric/DNS/validation truth; keyboard labels and absence-question call-site census. |
| SCX-2 | Review-first Site Connectivity wizard | API/wiring tests proving preview equals submitted intent; cloud and on-prem forms omit inapplicable fields; policy/hub operations remain server-owned; cancel leaves fleet unchanged. |
| SCX-3 | Customer-run cloud connector and preflight | Connector capability denial, exact proposed-diff preview, owner approval/audit, no cloud secret in CP/database/browser, and rollback red. |
| SCX-4 | Bounded behind-host validation | Source/destination CIDR guards, permission guards, result provenance/timestamp, timeout/refusal/error render, and a live packet proof. |
| SCX-5 | Cloud-fabric HA posture | Same-cloud and cross-cloud state matrix; no false automatic-failover claim; manual switch runbook and provider-specific failure red. |
| SCX-5a | Automatic cloud-fabric failover and recovery UX | Two-signal/fenced state-machine red matrix; idempotent local route transition; provider denial and stale completion refusal; live primary-loss walk with phase timings, behind-host proof and optional enrolled-client measurement. |
| SCX-6 | Full box walk and operational runbook | Two real environments: same-cloud and cross-cloud; successful path, deliberate policy denial, deliberate preflight failure, promotion, cloud-route truth, and rollback. |
| SCX-7 | Continuous path assurance — **post-beta** | Rate-limited scheduled probe, clear state/error provenance, alert only after an observed failure, and no arbitrary network-scanning capability. |
| SCX-8 | Path diagnostics and policy templates — **post-beta** | MTU failure evidence; templates are emitted as ordinary reviewed/audited policy rules; a denied template flow proves default deny remains authoritative. |
| SCX-9 | Private service discovery handoff — **post-beta** | Test-before-publish validates private resolver reachability and a representative record; gateway and each client/host handoff render independently; undeclared zones refuse; a live publish-query-remove walk leaves no fixture behind. |

### Test sequence

1. **Pure state tests** — every connector/preflight/probe/HA result is modelled as `unknown`,
   `required`, `passed`, or `failed`; absence is never coerced to passed.
2. **API and authorization tests** — owner/admin permission, organization scoping, audit payload
   safety, connector registration, approval transaction, and cancellation/rollback invariants.
3. **UI wiring and visual tests** — the rendered plan must match the API response; role-aware map
   never renders a gateway twice; unavailable or unmeasured cloud facts are absent, not green.
4. **Connector contract tests** — fixture providers return a route/NSG/NIC delta; malformed or
   overbroad requests refuse before any provider call; only allow-listed actions are possible.
5. **Live provider preflight** — first prove the red: missing forwarding, missing route, and
   missing firewall each report the specific unmet prerequisite without changing cloud state.
6. **Live wire walk** — owner approves the reviewed plan; connector action is audited; both
   behind-host directions carry packets; a policy denial blocks them; rollback restores the
   previous cloud and Tunnex desired state.
7. **HA walk** — show overlay promotion separately from cloud-route behavior. A static route that
   remains pinned is a truthful `manual action required`, not a failed test disguised as HA.

## Decide-items held for Founder ruling

1. **Cloud actuation:** customer-run connector with delegated least privilege (recommended), or
   guidance-only v1. Vault-backed connector credentials are an optional source, never a setup
   prerequisite. CP-held cloud credentials are refused.
2. **Behind-host probe:** optional installed probe on a customer-selected host (recommended for a
   real end-to-end claim), or gateway-to-target validation labelled narrowly. SSH-based probing is
   refused as a product dependency.
3. **Cloud-route HA:** manual runbook first (recommended) versus provider-specific automatic route
   switch after its safety design and failure walk are approved.
4. **Policy scope:** wizard creates reviewed all-protocol site rules only when the owner requests
   it, versus requiring resource-scoped rules by default.
5. **Provider order:** provider-neutral manual/preflight contract first (recommended), then AWS
   connector, then Azure connector; do not ship two privileged integrations before one is proven.
6. **Automatic-failover health decision:** corroborated agent control health plus an approved
   data-path probe (recommended), versus a WireGuard-handshake-only signal. The latter is refused
   because the live walk already showed that overlay state and forwarded traffic are different
   claims.

## Completion condition

This Epic is complete only after a customer can see what will change, approve it once, obtain
truthful preflight and traffic evidence, and recover from a failed or unavailable cloud path
without losing site connectivity or being shown a false healthy state.
