# EPIC 8 — Batch-Day Walk Manifest

Three stories held at walk-ready, walked together in one session, then merged as a
train. Ruled order: **S8.5 → S8.6 → S8.7 → epic-close UI walk**. Pawan drives; this
manifest is the script. Observed columns are filled ON the wire during the walk and
committed to `walk-artifacts/` DURING the session (not after).

## Train shas (git-verified 2026-07-20, `git cat-file -t` each)

| Story | Branch | Walk sha | State |
|-------|--------|----------|-------|
| S8.5 routed-subnets | `story/S8.5-routed-subnets` | `5daf729` | walk-ready (branch tip) |
| S8.6 hub-HA | `story/S8.6-hub-ha` | `842cfb3` (code @ `ae2405b`) | walk-ready (branch tip) |
| S8.7 CIDR-src + live conntrack flush | `story/S8.7-cidr-conntrack` | `7b68777` | walk-ready (branch tip, pushed to origin) |

**BATCH-DAY REBASE RULE (pre-agreed — do not litigate on walk day):** any defect an
EARLIER-in-order walk surfaces that touches SHARED machinery (the route reducer, site-link
health, `siteLinkGraph`, the hub-set derivation, the egress Manager) is fixed on the owning
story's branch, then the later branches REBASE onto it before their legs run. A defect in a
story's OWN surface is fixed in place. Merge order to `main` follows walk order, ff-only,
linear — **only on explicit in-session sign-off.**

---

## PRE-FLIGHT (before any leg)

**Env — the fleet (from the S8.6 D6 manifest, no new VM):**
- **Primary hub** `aws-gw` — public `16.176.32.176`, private `172.31.28.80`, VPC `172.31.0.0/16`.
- **Standby** — AWS instance 2 — public `3.25.125.203`, private `172.31.17.64`, SAME VPC. Enrolls as a
  gateway AT walk time. Needs **SG UDP 51820 open** + **source/dest-check OFF**.
- **Spoke/leaf** `azure-gw` — public `20.245.69.218` (make STATIC before batch day), private `10.0.0.5`,
  VPC `10.0.0.0/16`.
- **CP** — `40.65.63.141` / `10.0.0.4` (Azure).
- **Device** — a real macOS client (split-tunnel capable) + a Windows client for the NRPT/crash legs.

**Builds to deploy (name them in the walk log):**
- node-agent image built from each branch tip at walk time; record the sha deployed per gateway.
- client build from the S8.5 tip for the routed-ranges + resolver legs.
- Confirm each gateway reports its deployed agent sha before Leg 1.

**Pre-flight gate — paste back BEFORE legs (per branch, local):**
```
make generate-check && make build-editions && make test-node && make test-helper && helper-crosscompile
pnpm --filter @tunnex/web typecheck && pnpm --filter @tunnex/web test && pnpm --filter @tunnex/web build
```
(S8.7 is a node-only diff; S8.5/S8.6 carry the API/web/helper surfaces. Run the full set on the
tip that is checked out per deck.)

---

## DECK A — S8.5 routed-subnets (cross-cloud, split-tunnel + declared LANs + ZT layering)

| # | Leg | Expected | Observed |
|---|-----|----------|----------|
| A1 | **Pritunl-parity (money leg)** | split-tunnel device gets a declared LAN range in `AllowedIPs`, reaches a host on that LAN via the gateway; everything else routes DIRECT (not through tunnel) | |
| A2 | **Routed ≠ permitted (enforcing red)** | same device, ZT enforcing, 0 grants → range IS in `AllowedIPs` (routed) but the forward chain DROPS it; add a grant → it flows | |
| A3 | **Cross-gateway routed range** | declared LAN on a DIFFERENT gateway than the device's peer → packet rides the S8.2 site link + fronting gateway SNAT (two-hop, un-NAT'd inner + SNAT at front) | |
| A4 | **Device→site DNS (D4 handoff)** | range carries a resolver → split-tunnel device resolves that range's names; macOS `/etc/resolver` + Windows NRPT (S8.4b) | |
| A5 | **Crash-sweep ordering leg** | device up with resolvers installed → force-quit/crash the client → owned resolver files SWEPT, no stale `/etc/resolver` or NRPT residue pointing at a dead tunnel. macOS + Windows | |
| A6 | **L1 metrics render** | Sites topology card shows site-link tx/rx TOTALS + handshake age (render-floor, totals not rates) | |
| A7 | **Blast-radius** | declare a new routed range → EVERY device re-fetches + gains the route within the push interval | |
| A8 | **Home-LAN-collision** (registered) | a device whose home LAN overlaps a declared range — the ruled collision behavior holds | |

Artifacts: `walk-artifacts/S8.5/` — pcaps for A1/A3, `nft list` ON/OFF for A2, resolver-file before/after for A5.

---

## DECK B — S8.6 hub-HA (three-VM primary-kill)

**Walk-prep (per D1/D2):** primary + standby are TWO gateways of the SAME AWS site (`172.31.0.0/16`) —
the hub set, not a second site. Pawan **PINS the two AWS gateways** via `PUT /organizations/{orgId}/nodes/{nodeId}/hub-priority`
(the Slice-6 UI surface exists; the walk may drive the API). azure-gw stays UNPINNED (the leaf).

| # | Leg | Expected | Observed |
|---|-----|----------|----------|
| B1 | **Pin the hub set** | both AWS gateways pinned → hub set = `{primary, standby}` of the AWS site; azure-gw excluded (leaf). `node.hub_priority_set` audited old→new | |
| B2 | **Warm standby posture** | standby's transit tunnels present but route-DEPRIORITIZED (higher metric); leaf's standby-peer AllowedIPs empty (the asymmetric pre-promotion link — leaf drops standby's non-keepalive traffic; that drop is the SAFETY property) | |
| B3 | **Primary-kill failover** | kill the primary hub → within the staleness threshold the CP re-elects → pushes the demoted set → standby PROMOTED (metric flip, not tunnel build); banner/audit name the demotion (`hub.promotion`/`failback`) | |
| B4 | **Spoke continuity (tcpdump)** | on the leaf: spokes STOP sending to the dead primary and continue via the standby — tcpdump confirms on iron what the flap/keepalive reds pin | |
| B5 | **Rejoin as standby** | restart the killed primary → it rejoins as a STANDBY (no automatic flap back); a deliberate failback is one election | |
| B6 | **Flap damping** | an oscillating primary triggers exactly ONE failover (asymmetric hysteresis), not a storm | |

Artifacts: `walk-artifacts/S8.6/` — tcpdump for B4, hub-set-view JSON across B3/B5, audit rows for B1/B3.

**Enterprise-enforcing #1-blackhole variant** (from the S8.6 review fold): run B3 under an ENFORCING org and
confirm the demoted-hub blackhole fix holds (the failover doesn't strand the enforcing forward).

---

## DECK C — S8.7 live conntrack flush + CIDR source

**SCOPE NOTE (round-4 escalation):** the BOOT restart-sweep (revoked-while-DOWN, and the mesh-interlude
while-UP gap) is DEFERRED to S8.7b — NOT walked here. This deck walks the LIVE while-UP flush only.

| # | Leg | Expected | Observed |
|---|-----|----------|----------|
| C1 | **Live expiry flush (the money leg)** | ZT enforcing, a grant permits device→hostX; a ping/SSH RUNNING to hostX → the grant EXPIRES (or is deleted) while the agent is UP → the established flow STOPS within the sweep interval (conntrack entry flushed). The founder's exact scenario | |
| C2 | **Innocent neighbor survives** | a second live flow (different src/dst/proto/port, still granted) KEEPS flowing across C1's flush — scoped, proven by survival | |
| C3 | **CIDR source /32-precise grant** | a `src_kind='cidr'` grant enforces on exactly its CIDR; a `cidr_outside_org_ranges` warn shows read-time when the CIDR isn't placed; warn sheds when a subnet+gateway lands it | |
| C4 | **Flush-fail is degraded-not-broken** | if the flush can't run (CAP_NET_ADMIN absent) the rule removal STILL succeeds; `conntrack_flush_unavailable` surfaces on the health plane, clears on the next successful flush | |
| C5 | **Device revocation exempt** | revoking the DEVICE (peer removal) kills the tunnel outright — no conntrack semantics needed (crypto-death) | |

Artifacts: `walk-artifacts/S8.7/` — conntrack dump before/after C1, health-surface JSON for C4.

---

## DECK D — epic-close UI walk

| # | Leg | Expected | Observed |
|---|-----|----------|----------|
| D1 | **S8.3 Leg-6 CW confirm** (named substitute, trigger = this walk) | an Access-rule edit that `crossesMultiSiteThreshold` shows the confirm-on-write dialog; the `meta.protocol_version` ceiling holds | |
| D2 | **Sites topology end-to-end** | the topology card renders the full EPIC-8 world (sites, hub roles, site-link + routed-range metrics) coherently on live data | |
| D3 | **Stale-add-rule-button** (S8.3 walk-found, fixed in S8.5) | add a group → the Add-rule affordance is not stale (one-truth React fix holds) | |

---

## POST-WALK

- Fold any walk-surfaced defects per the rebase rule; a feature-sized fold RE-EARNS a review.
- Commit walk evidence to `walk-artifacts/` DURING the session.
- **Merge only on explicit in-session sign-off** — PR per story, ff-only, walk order, linear history.
- S8.7b registered (boot + mesh-interlude conntrack reconcile); its named limitation stands until then.

## Honest duration

Three cross-cloud decks + a UI deck, run live. Realistic: **half a day to a full day** —
Deck B (three-VM HA, second-gateway enroll + kill + tcpdump) is the long pole; Deck A has
8 legs across two client OSes; Deck C is quick (one kernel, one flow). Env pre-flight (static
azure IP, SG rules, source/dest-check, second-gateway enroll) is real setup time BEFORE Leg 1.

---

## Deck B scope note (2026-07-21) — device-transit variant DEFERRED (A3b)

Deck B's continuity legs are **behind-host paths** — an Azure behind-host ↔ the AWS LAN via the promoted
standby (the A1 / S8.2c-class eth0-side geometry, proven on the folded train). The **device→remote-site
transit** variant is **explicitly dropped from Deck B** — it depends on A3b (device→remote-site hub transit,
WG cryptokey-routing), a registered follow-up story, not this deck. Keeping the leg list honest: Deck B proves
hub-role failover for behind-host site traffic; it does NOT prove device-through-hub-to-remote-site.
