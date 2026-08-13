# EPIC 8 SMOOTH WALK — record (2026-07-23)

The acceptance walk from MERGED MAIN. Fresh org "Nykaa", single provenance (digest-pinned
v0.2.0 agents), browser-driven; the only terminal touches were the emitted enroll pastes +
the two named entity-gated exceptions + TEST-ACTION fault injection.

## Substrate (census-pinned)

- CP `104.45.208.156` @ main **`fa195ae`** (v0.2.0 + the deploy hotfix below), **enterprise**,
  **protocol_version 6**, node-agent **digest-pinned** `@sha256:de8c9cefb614…22f114`.
- Gateways (v0.2.0, digest-pinned via the emitted command): aws-gw-1 (Sydney, 172.31.0.0/16,
  hub) + aws-gw-2 (Sydney, HA standby) + azure-gw (West US, 10.0.0.0/16, NAT'd spoke).
  Device pool 10.99.0.0/24; behind-hosts 172.31.10.85 (aws) / 10.0.0.4 (azure-cp) / azure-gw 10.0.0.5.
- Pre-walk gateway baseline: `iptables -S DOCKER-USER` = empty-or-agent-managed on all three
  (clean-slate evidence, per the census law).

**Pre-walk deploy hotfix (main `fa195ae`):** `docker-compose.yml` never forwarded
`TUNNEX_NODE_AGENT_IMAGE` into the api container — the .env digest pin silently no-op'd. Fixed
so single-provenance is enforceable (the emitted enroll command carries the digest).

## Legs — outcomes

| Leg | Result |
|---|---|
| 1 Onboarding | PASS — fresh signup → org → landing, `org.created`, empty-states guide |
| 2 First gateway (emitted enroll) | PASS — digest-pinned image in the emitted command (single provenance proven at the seam); all agents enrolled→ready |
| 3 First site + bind | PASS |
| 4 Second site + CW confirm | Behavior PASS; **CW v5/v6-confirm screenshot NOT captured** → S8.3 Leg-6 substitute stays formally UNDISCHARGED (carried, re-triggerable) |
| 5 Subnets / approval | PASS — advertise→pending→approve, disjointness quiet, `policy v6` served+applied |
| 6 Access / ZTNA | PASS — default-deny (with the "enable with NO rules?" confirm), grant-gates-flow, scoped-deny, **conntrack flush proven both faces** (delete-immediate + expiry-autonomous ~20s sweep cadence) |
| 7 Topology / health | PASS — live byte counters, **C4 clean-baseline: NO flush-degraded badge on healthy gateways** |
| 8 HA pinning | PASS — 2nd gateway bound (D4), hub set forms, **warm standbys proven** |
| 9 Users / Audit | PASS — `hub_set.promotion`/`failback`, `node.hub_priority_set`, `grant_expired` all legible |
| Test A HA failover | **PROMOTION + FAILBACK PROVEN** (see below) + surfaced the findings |
| Test B ZTNA rules | PASS (folded into Leg 6) |

## Proven on shipped v0.2.0 (the core)

- **A3b device→remote-site transit, ZERO-TOUCH** — SSH/ping mac→azure behind-host (cross-cloud
  via hub) + aws behind-host, zero gateway commands. The WF-1 fold, wire-proven on shipped code.
- **ZTNA** — default-deny, scoped grants, conntrack flush on grant-delete (immediate) AND
  temporary-grant expiry (autonomous, ~20s sweep cadence). S8.7's expired-ping-killer proven.
- **Hub HA** — warm standbys (keepalive-alive, AllowedIPs-empty), **failover PROMOTION**
  (`hub_set.promotion`, banner, hub set version bump) on a clean single-primary data-plane kill
  (`docker stop && ip link del wg0`), and **FAILBACK** (M=5 fresh → reclaim PRIMARY) — cycled
  multiple times (v2→v6). The overlay failover works.
- **Single provenance** — digest-pinned agents end to end.

## Findings (WF-numbered, HELD for disposition — fix-forward)

**WF-A (high, decision-first) — VPN client does not re-home on hub failover.** A device peers
with ONE gateway (its assigned node, static endpoint). When that gateway's data plane dies, the
client is stuck "Connecting…" and recovers ONLY when ITS gateway returns (confirmed: the mac
reconnected the moment aws-gw-1 restarted, not when aws-gw-2 was promoted). Hub HA = site-transit
redundancy, NOT device-connectivity redundancy. FIX IS A FEATURE: multi-endpoint device config
+ client failover, OR CP device-reassignment to the promoted hub. Needs a commit-one paper + ruling.

**WF-B (documented cloud requirement, NOT a code bug) — behind-host site-to-site HA needs a
cloud-fabric route failover.** The overlay fails over correctly (aws-gw-2 promoted, azure-gw
re-homed transit — `wg show` proved correct peers + fresh handshakes). But the VPC route to the
gateway ENI is STATIC, pinned to the primary's ENI (the zero-touch boundary Tunnex won't cross).
Behind-host reach restored the instant the VPC route `10.0.0.0/16`+`10.99.0.0/16` was repointed
to aws-gw-2's ENI (0% loss, 139ms). So: NO agent/CP hotfix — this is a docs/architecture item
(AWS route-table health-check/Lambda repoint, or GWLB; document the cloud-HA pattern + surface
it in the fabric panel). The `wg show` asymmetry (hub got 125KB, sent 4KB) was the behind-host
REPLY dying at the un-repointed VPC route.

**WF-C (med) — `docker stop` orphans wg0 in the host netns.** With `--network host` + wgctrl,
wg0 lives in the host netns; stopping the agent kills control-plane (reconcile, "offline") but
wg0 keeps forwarding headless. Consequences: (1) zombie hub — carries traffic, can't reconcile;
(2) failover is data-plane-driven (correct) so agent-death alone never triggers it; (3) graceful
SIGTERM should Teardown-delete wg0 but doesn't (cleanup gap). This is why the first failover
attempts (docker stop only) didn't fire — the data plane survived.

**WF-D (med) — site-link-down badge fires on the dead demoted peer + doesn't name which peer.**
Post-failover, azure-gw shows "site link down" for its DEAD demoted-aws-gw-1 keepalive peer while
the ACTIVE aws-gw-2 path is up — the badge can't distinguish "expected, demoted-dead" from "real
problem." Fix: don't alarm site_link_down for a demoted member's link + name the peer in the badge.

**WF-E (low) — NAT'd gateway offered as a hub pin candidate.** azure-gw (no endpoint, can't be a
hub, B2) is offered "pin #3". The derivation filters it, but the UI shouldn't present it.

**WF-F (low) — dashboard device-count legibility.** Overview read "0 Devices / No devices yet"
while a device was Connected (10.99.0.2) — count/state gap (WF-2 sibling; the desktop refetch
fix landed for the revoked-count case, this is the connected-but-uncounted case).

**Observability nit (not a WF):** "expires in 1m" temporary grants actually enforce up to one
sweep interval (~20-30s) past the stated expiry (the S7.5.4 delete-on-sweep cadence). Worth a
tooltip; bounded + deterministic, not a defect.

## Harvest verdicts — OWED (Pawan's PROMOTE / KEEP-DEFERRED calls)

- group-membership-no-UI — hit live (rule sourced per-user/org, "No groups yet"; can a group be
  created + populated in-UI at all?)
- resource-no-port-field — the Resources add-form protocol/port grain
- site-link-down-badge-names-which-peer — **strongly evidenced PROMOTE** by WF-D (the badge's
  inability to name the peer was the exact confusion during failover)
- conntrack-kind-needs-a-badge — deferred (C4 clean baseline held; no degraded state hit)
- standby-stale-flicker-residue — none observed (240s window; verdict = GONE, tentatively)

## Retractions (honest record)

- My "inverted liveness" hypothesis (site-card vs HA-card) was WRONG — retracted. The cards
  measure control-plane (agent heartbeat, "offline") vs data-plane (WG handshake, "warm"); both
  correct. Root of the confusion = WF-C (orphaned wg0).
- My "site-link-down is a false alarm, transit is fine" guess was WRONG — transit was genuinely
  broken (WF-B, the VPC route), corrected by the clean test.

## Disposition path

WF-A + WF-D → commit-one paper (client-failover design + badge fix), founder ruling, then build.
WF-B → docs/architecture (cloud-HA route-failover pattern) + fabric-panel note. WF-C → agent
Teardown wg0-cleanup on SIGTERM (decision-first — interacts with failover-liveness). WF-E/WF-F →
small UI fixes. Harvest verdicts → Pawan's calls. Nothing patched during the walk (discipline held).
