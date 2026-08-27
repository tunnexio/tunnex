# EPIC 21 — Provider-neutral FQDN access resources

**REGISTRATION ONLY. No S21 branch, no commit-one decisions, and no product code.** EPIC 20 remains the
active story and must finish first. This paper preserves the founder-directed product objective and sizes
the work; `docs/S21-decisions.md` is still required before implementation.

## Outcome

An organization can grant a specific People Group (and every existing policy-source kind that is proven
compatible) access to one exact private service hostname on explicitly approved protocol/ports, without
granting the surrounding subnet and without rewriting policy when the service's DNS answers change.

Examples the core must express without provider-specific code:

- an AWS Route 53 private name fronting EC2, ECS/Cloud Map, an internal load balancer, or RDS;
- an Azure Private DNS name fronting a private endpoint or internal service;
- a GCP Cloud DNS name fronting a private service or internal load balancer;
- an on-premises or other-cloud name resolvable from the selected Site/Gateway context.

Manual exact-FQDN entry is the core product. Native cloud inventory/discovery is optional convenience and
must not become a prerequisite for enforcement.

## Security boundary that must not be blurred

An FQDN policy is enforced at L3/L4 by resolving the name to a bounded current address set and compiling
only those addresses plus the approved protocol/ports. DNS selects addresses; it does not itself authorize
traffic.

Two hostnames sharing the same destination IP and port are indistinguishable at L3/L4. Therefore the core
can strictly isolate an RDS endpoint, dedicated load balancer/listener, or otherwise distinct address/port,
but it cannot honestly promise per-host isolation for multiple virtual hosts on one shared `IP:port`.
Strict SNI/HTTP Host-aware enforcement is a separate named story, not marketing copy for this epic.

Split-horizon names must resolve in the destination network context selected by server-owned policy. A
browser/control-plane public resolver is not an authoritative substitute for a private Site/Gateway
resolver.

## Story plan — backend and UI ship together

Functional UI is not postponed to S21.5. Every slice ships the smallest truthful UI needed to operate its
new contract; S21.5 consolidates operational UX, accessibility, and cross-slice consistency.

| Story | Backend / control-plane work | UI / UX work | Exit proof and estimate |
|---|---|---|---|
| **S21 — Decision paper** | Lock exact-name versus wildcard scope; resolver placement and trust; answer/staleness bounds; RBAC → entitlement → org opt-in order; licence-tier disposition; migration and rollback; shared-endpoint boundary; support-or-deferral census for every existing Resource consumer. | Lock IA and URL ownership; Resource/Rule flows; owner/restricted personas; loading/empty/error/stale/permission states; destructive impact/recovery; desktop and narrow-layout wireframes. | Founder-approved `docs/S21-decisions.md`; no product code. **Total 3–5 days; UI 2–3 days.** |
| **S21.1 — FQDN Resource contract and inventory** | OpenAPI-first `cidr \| fqdn` destination shape; exact hostname normalization and validation; protocol/port reuse; storage, audit, compatibility migration, rollback, generated clients, and unchanged CIDR behavior. | Access → Resources list, create, edit, and detail surfaces with Type/FQDN, protocol/ports, validation, loading/error/read-only states, and canonical links from Rules. | Create `orders.internal.example.com` on TCP/443; API/CLI/web agree; every mutation has a rendered caller; CIDR regressions stay green. **Total 1–2 weeks; UI 5–7 days.** |
| **S21.2 — Resolver and answer lifecycle** | Resolve in selected Site/Gateway context; A/AAAA/CNAME handling; TTL plus jitter; bounded answer count; atomic generations; last-known-good maximum age; NXDOMAIN/SERVFAIL/timeouts; private/special-range and rebinding policy; fail closed. | Resource detail shows resolver scope, current answers, generation, TTL, last refresh/last good, and distinct resolving/healthy/stale/failed/NXDOMAIN/permission states with bounded retry. | Fixture changes an answer without a policy edit; new answer enters and retired answer leaves within ruled bounds; failure never renders false zero or preserves access forever. **Total 2–3 weeks; UI 4–6 days.** |
| **S21.3 — Policy compilation and enforcement** | Compile Group/User/Agent-compatible sources → FQDN Resource → current answer set plus protocol/ports; deterministic artifact/hash; default deny; address withdrawal semantics; standard/JIT/template consumer census; no alternate-IP inheritance. | Rule builder selects FQDN Resources; impact preview names source, hostname, protocol/ports, current answer count and affected principals; Test access explains allow/deny/unknown without sending traffic unless explicitly invoked. | Allowed team reaches only the approved service/port; restricted team, sibling port, retired answer, and direct alternate IP fail unless separately granted. **Total 2–3 weeks; UI 4–6 days.** |
| **S21.4 — Gateway/client routing, DNS handoff, and HA** | Deliver bounded answer routes to the correct Gateway/client; split DNS; dual-stack; HA/failover; reconnect and answer-generation convergence; minimum compatible versions; one-binary/edition parity. | Show authoritative Site/Gateway resolver and route context, dual-stack state, failover/readiness, version incompatibility, and DNS failure separately from tunnel failure. | Live private name survives an answer change and Gateway failover without broad CIDR access; DNS-down is not shown as tunnel-down. **Total 1–2 weeks; UI 3–5 days.** |
| **S21.5 — Operational console UX** | Add only bounded server projections required for inventory, impact, and diagnostics; no client-side organization-wide Device sweep or fabricated aggregate. | Search/filter/sort; FQDN detail workspace; current answers; impacted Rules/Groups; audit links; safe bulk behavior; edit/delete confirmations with exact impact and recovery; keyboard, screen-reader, narrow-layout, owner/member and permission-denial passes. | Founder live review of populated, empty, stale, failed, permission, loading, destructive, and recovery states; no false healthy/zero; caller census complete. **Total 1–2 weeks; UI 7–10 days.** |
| **S21.6 — Multi-cloud box-walk and hardening** | Disposable fixtures and live proofs for changing answers, split horizon, dual-stack, failover, edition parity, scale bounds, recovery, audit, and generated-contract drift. | Realistic multi-cloud fixtures; responsive/visual/a11y regression pass; copy and state consistency; founder-found corrections only after disposition. | AWS private Route 53/RDS or internal service plus a second-cloud live proof; provider-neutral DNS fixture covers the generic contract; full local gates, both editions, story-end multi-finder review, box-walk, and founder UI approval. **Total 1–2 weeks; UI 4–6 days.** |
| **S21.7 — Native discovery (optional follow-ups)** | Separate AWS, Azure, and GCP read-only discovery/import connectors with least-privilege credentials, pagination, refresh, and no enforcement dependency. | Provider/account/region/project picker, resource search, import preview, permission/error/refresh states, and a manual-FQDN escape hatch. | Does not gate S21 core. **Approximately 3–5 weeks total engineering and 5–8 UI days per provider.** |
| **S22 — Strict shared-endpoint hostname enforcement** | SNI/HTTP Host-aware proxy or a dedicated endpoint/listener integration; certificate and protocol limits; bypass analysis. | Host-aware policy builder, shared-endpoint warning, certificate/SNI state, diagnostics, impact and recovery. | Prove two names on the same `IP:port` are independently authorized. **Separate epic; UI approximately 1–2 weeks.** |

## Core estimate

S21 through S21.6 is approximately **12–16 person-weeks** or **9–13 calendar weeks with two engineers**,
including approximately **29–43 frontend days (6–8 frontend person-weeks)**. Estimates assume reuse of the
existing Resource, Rule, compiler, Gateway, audit, RBAC, and console primitives. Discovery connectors and
strict L7 hostname enforcement are excluded.

## Required decision items for commit-one

No implementation begins until `docs/S21-decisions.md` dispositions these items:

1. exact FQDN only in core, or any wildcard syntax and its non-overlap rules;
2. authoritative resolver location and how a Resource selects Site/Gateway context;
3. CNAME depth, answer-count ceiling, TTL floor/ceiling/jitter, and last-good maximum age;
4. fail-closed behavior for NXDOMAIN, SERVFAIL, timeout, partial A/AAAA, and resolver disagreement;
5. address withdrawal and existing-flow/conntrack semantics;
6. private, public, loopback, link-local, metadata, multicast, and rebinding validation;
7. RBAC names, licence tier, and whether an org opt-in is necessary — unlock never auto-enforces;
8. compatibility for every current Resource consumer: People, Devices, AI Agents, JIT, templates, CLI,
   audit, Test access, and generated clients;
9. whether the core box-walk requires two or three live clouds, and what a provider-neutral fixture may
   substitute but never satisfy;
10. edit/delete impact response and recovery when Rules reference the FQDN Resource.

## Proof matrix

The story is not complete from CRUD or DNS unit tests alone. The final proof must include:

- exact-team allow and neighboring-team deny;
- exact protocol/port allow and sibling-port deny;
- direct-IP attempt denied unless another Resource grants it;
- answer rotation: add, overlap window if ruled, and retirement;
- split-horizon answer visible only from the selected private context;
- NXDOMAIN, SERVFAIL, timeout, stale-last-good expiry, and answer-count overflow;
- IPv4-only, IPv6-only, and dual-stack answers;
- Gateway failover and reconnect convergence;
- Resource edit/delete impact, audit, recovery, and no orphaned Rule behavior;
- owner, restricted member, missing permission, missing entitlement, and opt-in-off ordering;
- one binary in both editions, generated-code drift guard, full web gate, and live box-walk evidence.

## Explicit non-goals and named follow-ups

- **No cloud-provider lock-in:** core enforcement consumes DNS, not AWS/Azure/GCP APIs.
- **No client-side unbounded inventory:** organization-wide Devices, connectors, or cloud resources are not
  swept in the browser to decorate this feature.
- **No DNS-equals-authorization claim:** DNS supplies candidate addresses; compiled policy authorizes them.
- **No strict shared-ALB hostname claim:** owned by S22 unless a dedicated address/listener makes the
  destinations distinguishable at L3/L4.
- **No opaque enrollment-status expansion:** existing server-owned enrollment-status deferrals remain
  separate.
- **Native provider discovery:** S21.7 follow-ups, independently reviewable and never required for manual
  provider-neutral FQDN Resources.

## Start condition

EPIC 20 is merged and its PLAN checkpoint is final; the founder explicitly starts EPIC 21; the implementation
branch is created from then-current `main`; and commit-one is the ruled `docs/S21-decisions.md`. Re-verify the
live schema, OpenAPI, compiler, Resource callers, DNS/Site ownership, and current licence/RBAC facts at that
time rather than trusting this registration paper.
