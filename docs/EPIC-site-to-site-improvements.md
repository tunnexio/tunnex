# EPIC — Site-to-site improvements: safe by default, quick to set up

Status: **registered / decision-first; no implementation authorized by this paper.**
Planned against main `f47924f1` on 2026-11-20. Story namespace: **SSI**.

Each story below starts with its own `docs/SSI-<n>-decisions.md` (commit-one is paper) and a red
test that reproduces the defect before product code. Stories build one at a time, in the order
given, on `story/site-to-site-improvements`.

## Evidence status

The findings come from a static read of main at `f47924f1`, plus one live observation on the AWS
demo control plane (v0.1.43) on 2026-11-20. **Nothing in the findings table has been reproduced by
a test yet.** Each story's first slice is the reproduction; a finding that does not reproduce is
closed in that story's paper, not patched.

Live observation: a routed range of `172.19.0.0/16` was accepted, and traffic from the co-located
gateway to that range went to the Compose bridge `tunnex_default` (`172.19.0.0/16`) on the same
host. The range had to be moved to `10.50.0.0/16`.

## Founder outcome

An operator links two private networks in one guided flow and can trust three things:

1. A wrong range is refused before it can redirect traffic.
2. Linking two networks opens nothing until the operator grants it, and a port-scoped grant works.
3. The flow tells the operator what is still missing outside Tunnex, and proves the path with a
   real probe before it says "connected".

## Relationship to registered epics

| Epic | Relationship |
| --- | --- |
| [Site Connectivity Experience](EPIC-site-connectivity-experience.md) (SCX) | SCX owns the full guided experience, cloud connector and fabric HA. This epic fixes defects in today's path and ships a narrow guided flow. SSI-9 must reuse the SCX-2 review-first contract and the SCX-4 probe guards if those rule first; it does not fork a second wizard. |
| [Site Address Translation](EPIC-site-address-translation.md) (SAT) | SAT owns translation for **overlapping** site CIDRs. SSI-8 is different: source NAT at the destination gateway's LAN egress for **disjoint** sites, the same treatment device traffic gets today. Overlap refusal is unchanged. |
| [NAT traversal and relay](EPIC-nat-traversal-relay.md) | Out of scope. A site link still needs one gateway with a public endpoint. |

## Findings and the story that owns each

| # | Severity | Finding | Where (main `f47924f1`) | Story |
| --- | --- | --- | --- | --- |
| F1 | High | A site subnet has no private-range, reserved-range or minimum-prefix check. A public or very wide range can be approved and becomes a route on every other gateway and device. | `apps/api/internal/sites/service.go` (`ApproveSubnet`), `apps/api/internal/subnetguard/subnetguard.go` | SSI-1 |
| F2 | High | With Zero Trust enforcement off (the default), linking two sites opens all traffic between approved ranges, both directions, any protocol. | `apps/node/internal/egress/egress_linux.go` (mesh forward rules) | SSI-4 |
| F3 | High | A site-source rule to a **resource** is placed only on the source gateway. The hub and the destination gateway never receive the grant, so the rule shows active and traffic drops. This is the only way to port-scope site traffic. | `apps/api/internal/policy/compiler.go` (site-source placement) | SSI-2 |
| F4 | Medium | The rule builder pre-fills the destination with the chosen source group on all ports. | `apps/web` Add rule panel | SSI-3 |
| F5 | Medium | Site create, subnet advertise, bind and unbind write no audit row. | `apps/api/internal/sites/service.go` | SSI-5 |
| F6 | Medium | Site mutations do not push to gateways; changes, including removals, appear to wait for the agent tick. | `apps/api/internal/sites/service.go`, `apps/api/internal/http/site_handlers.go` | SSI-6 |
| F7 | Medium | The wizard path (`RouteLAN`) and `DeleteSite` do not reconcile the persisted hub set, so the hub can change with no hysteresis and no audit. | `apps/api/internal/http/site_handlers.go` | SSI-6 |
| F8 | Medium | Nothing checks a range against the gateway's own interfaces or container networks. | `apps/api/internal/subnetguard/subnetguard.go`, `apps/node/internal/reconcile/wgctrl_linux.go` | SSI-7 |
| F9 | Medium | A second gateway can be bound to a site that already has one; the hub then holds two peers with identical AllowedIPs. | `apps/api/internal/sites/service.go` (`BindNode`), `apps/api/internal/nodes/service.go` | SSI-7 |
| F10 | Low | `site_subnet_unreachable` fires for a reachable range that the gateway has no address in, for example a peered network. | `apps/node/internal/reconcile/siteroute.go` | SSI-7 |
| F11 | Low | Register and bind are not one transaction; a failed bind leaves an orphan site and a retry returns `site_name_taken`. | `apps/api/internal/sites/routedranges.go` | SSI-1 |
| F12 | UX | A site link needs cloud return routes and forwarding on both sides. The wizard never says so. | `apps/web/src/pages/NetworkSetup.tsx`, `apps/web/src/pages/Sites.tsx` | SSI-8, SSI-9 |
| F13 | UX | Failover never triggers for a same-site gateway pair with no other site to observe it, and the Failover tab does not say so. | `apps/api/internal/nodes/failover.go`, `apps/web/src/pages/Sites.tsx` | SSI-9 |

## Story map

| Story | Outcome | Depends on |
| --- | --- | --- |
| SSI-0 | Epic decisions paper, red matrix, decide-items ruled | None |
| SSI-1 | A wrong range is refused with a reason | SSI-0 |
| SSI-2 | A port-scoped site rule works end to end | SSI-0 |
| SSI-3 | The rule builder never proposes a broad destination | SSI-0 |
| SSI-4 | Linking two sites opens nothing by default | SSI-2 |
| SSI-5 | Every site mutation is audited | SSI-0 |
| SSI-6 | Site changes reach gateways promptly; the hub is stable and audited | SSI-5 |
| SSI-7 | The gateway refuses a route that collides with its own networks | SSI-1 |
| SSI-8 | Quick mode: a site link works with no cloud return route | SSI-2, SSI-4 |
| SSI-9 | One guided flow with preflight and a live test | SSI-1 to SSI-8 |
| SSI-10 | Box walk on two real clouds, docs updated | SSI-9 |

## What each story changes

### SSI-0 — decisions and red matrix

| Area | Change |
| --- | --- |
| `docs/SSI-0-decisions.md` | Rule the decide-items below; record the red matrix (one failing test per finding F1 to F11). |
| Code | None. |

### SSI-1 — range guard (F1, F11)

| Area | Change |
| --- | --- |
| `apps/api/internal/subnetguard` | Add an allowlist (RFC 1918, RFC 6598) and a reserved set: loopback, link-local, multicast, the control-plane address, every gateway endpoint. Add a minimum prefix length. |
| `apps/api/internal/sites/service.go` | Apply the guard on advertise and on approve. An override, if ruled in, is a separate permission and is audited. |
| `apps/api/internal/sites/routedranges.go` | Register and bind in one transaction. |
| `openapi/openapi.yaml` | Named refusal codes: `range_not_private`, `range_too_wide`, `range_reserved`. |
| `apps/web/src/pages/NetworkSetup.tsx` | Show the refusal reason next to the field; no partial site is left behind. |
| Tests | Table test for each refused class; existing approved ranges on upgrade are reported, never silently removed. |

### SSI-2 — port-scoped site rules (F3)

| Area | Change |
| --- | --- |
| `apps/api/internal/policy/compiler.go` | For a site or CIDR source whose destination resource sits in another site, place the grant on the destination gateway and the transit hub as well as the source gateway. |
| Tests | Compiler golden for site → resource across two sites and across a hub; a denied port stays denied on every gateway. |
| Web | None, apart from removing any wording that says such a rule is active when it is not. |

### SSI-3 — safe rule builder default (F4)

| Area | Change |
| --- | --- |
| `apps/web` Add rule panel | Destination starts empty. Review stays disabled until the operator picks one. |
| Tests | Component test: choosing a source never sets a destination. |

### SSI-4 — site links are closed by default (F2)

| Area | Change |
| --- | --- |
| `apps/api/internal/policy/compiler.go`, `apps/node/internal/egress/egress_linux.go` | Site ↔ site forwarding is rendered only from compiled grants, whatever the org's device-enforcement setting. Device behaviour is unchanged. |
| Migration | Existing orgs with linked sites and enforcement off keep working: the migration writes explicit site ↔ site grants that match today's reach, marked as migrated, so the operator can narrow them. |
| `apps/web/src/pages/SiteToSite.tsx` | Each link shows what is allowed across it; an empty state says nothing is allowed yet. |
| Tests | Two linked sites with no rule: no traffic. Upgrade fixture: reach is unchanged and the grants are visible. |

### SSI-5 — audit for site mutations (F5)

| Area | Change |
| --- | --- |
| `apps/api/internal/sites/service.go` | Audit rows for site create, subnet advertise, bind and unbind, inside the same transaction as the write. |
| Tests | One assertion per verb; a failed audit rolls the write back. |

### SSI-6 — prompt convergence and a stable hub (F6, F7)

| Area | Change |
| --- | --- |
| `apps/api/internal/http/site_handlers.go` | Call `ReconcileHubSet` from `RouteLAN` and `DeleteSite`. Push desired state to the org's gateways after every committed site mutation. |
| Tests | Removing a range reaches the gateway without waiting for the tick; with two public gateways the hub does not change on a single stale report. |

### SSI-7 — the gateway protects its own networks (F8, F9, F10)

| Area | Change |
| --- | --- |
| `apps/node/internal/reconcile` | Refuse a remote route that overlaps a connected network on the host; report a new health kind naming the interface. |
| `apps/node/internal/reconcile/siteroute.go` | Decide `site_subnet_unreachable` from a route lookup, not from address containment. |
| `apps/api/internal/sites/service.go` | Rule on a second gateway per site (see decide-item D4); either refuse the bind or dedupe the peers. |
| `apps/web/src/pages/Sites.tsx` | Show the new health kind on the network row. |
| Tests | Fixture with a container bridge that collides with a remote range; a peered range does not raise a false alarm. |

### SSI-8 — Quick mode: site egress NAT (F12)

| Area | Change |
| --- | --- |
| Schema, `openapi/openapi.yaml` | Per-site setting `lan_egress`: `preserve_source` (today's behaviour) or `gateway_address`. |
| `apps/node/internal/egress/egress_linux.go` | In `gateway_address` mode, masquerade site-sourced traffic as it leaves the destination gateway's LAN interface, after the forward policy has matched. |
| Policy and audit | Unchanged: every gateway still enforces and records the original source. Only the LAN host sees the gateway address. |
| `apps/web` | The setting sits on the network, with one sentence on what the destination host will see. |
| Tests | Policy matches the original source in both modes; `preserve_source` renders byte-identical rules to today. |

### SSI-9 — guided flow, preflight and live test (F12, F13)

| Area | Change |
| --- | --- |
| `apps/web/src/pages/SiteToSite.tsx`, `apps/web/src/components/SitePairReview.tsx` | "Connect two networks": choose two networks, preflight, routing mode, access, test. |
| API | Preflight endpoint: one public endpoint present, ranges disjoint, no collision with gateway networks, hub reachable on its WireGuard port. Bounded probe endpoint: one TCP connect from a gateway to an address inside an approved range. |
| Access step | The operator picks a destination resource and ports; ordinary rules are created through the existing rule path. |
| `apps/web/src/pages/Sites.tsx` Failover tab | Say when no other site can observe the pair, so automatic failover cannot trigger. |
| `preserve_source` mode | Show the exact return route and forwarding steps for the operator's cloud; the flow does not claim "connected" until the probe passes. |
| Tests | Preview equals submitted intent; cancel leaves no state; the probe refuses any address outside an approved range. |

### SSI-10 — box walk and docs

| Area | Change |
| --- | --- |
| `docs/SSI-10-boxwalk.md`, `walk-artifacts/` | AWS ↔ GCP: both routing modes, one allowed port, one denied port, a refused range, a colliding range, range removal. |
| tunnex-web | Update `sites-routing` and add a short "Connect two networks" guide. Name released versions only. |

## Decide-items held for Founder ruling (SSI-0)

| # | Question | Recommendation |
| --- | --- | --- |
| D1 | May a public range ever be routed through a site? | Refuse by default; allow only with a separate named permission and an audit row. |
| D2 | Minimum prefix length for a site range. | `/8` for RFC 1918 space, `/10` for RFC 6598; nothing wider. |
| D3 | SSI-4 changes behaviour for orgs with enforcement off. Migrate with explicit grants, or keep the old behaviour behind an opt-out? | Migrate with explicit, visible grants. New orgs start closed. |
| D4 | A second gateway on one site: refuse the bind, or support it as the HA pair it is used for today? | Support it, and dedupe the hub's peers; the failover design depends on a same-site pair. |
| D5 | Default routing mode for a new site link. | `gateway_address` (Quick) for new links; existing links stay `preserve_source`. |
| D6 | Does the bounded probe in SSI-9 need its own permission? | Yes, a named permission; it is a capability, not a view. |
| D7 | Is SSI-9 built here or folded into SCX-2? | Build the narrow flow here against the SCX-2 contract if that contract is ruled first. |

## Interface constraints

- Use the shared tokens in `packages/shared/src/tokens.ts`; no new colour, and no hex in a
  component.
- `ok` (green) means alive right now. A passed probe is live state and may use it; "saved" and
  "created" use the accent.
- Reuse the `s2s-*` classes in `apps/web/src/site-to-site-workspace.css` and the existing
  components (`Button`, `ActionButton`, `ResourceSummary`, `AppAccessEmptyState`) before adding one.
- Follow `docs/ux-console/00-principles-and-design-system.md`, including the keyboard and
  responsive baseline.
- Every UI story answers the two absence questions in `AGENTS.md`: what the API allows that the
  screen cannot do, and what the operator is told after each destructive verb.

## Non-goals

- No change to overlap refusal between sites, the device pool, Service or VIP ranges.
- No translation for overlapping sites (SAT).
- No cloud credentials in the control plane, and no cloud route written by Tunnex (SCX-3).
- No NAT traversal for two gateways that are both behind NAT.
- No change to device enforcement defaults.

## Required checks per story

The gates in `AGENTS.md`, both editions, on the story's final content commit. A unit test
substitutes for a wire proof and never satisfies it; SSI-10 is the wire proof.

## Completion condition

On two real clouds an operator links two networks from one flow. A wide or colliding range is
refused with a reason. Nothing crosses the link until a rule allows it, and a port-scoped rule
works. Quick mode needs no cloud route. Every change is audited and reaches the gateways promptly.
