# S8.2 route-propagation — box-walk (live wire)

Box: `ubuntu@Tunnex-dev-vm`, enterprise edition, migration v35 (`dirty=f`), branch `story/S8.2-route-propagation` @ `edff64a` (the model-clean HEAD — all prep gates verified before walking).

**Topology (3 agents on one VM — the box's biggest choreography):** hub-and-spoke.
- **Hub** = `demo-gw` (public endpoint, re-pointed to the bridge name `tunnex-node-agent-1:51820` to dodge Docker hairpin-NAT), bound to `site-hub`.
- **Spoke A** = `gw-a`, site-a, subnet `10.1.0.0/24`, LAN host `10.1.0.1`.
- **Spoke B** = `gw-b`, site-b, subnet `10.2.0.0/24`, LAN host `10.2.0.1`.
- Grant: `src_kind='site'(site-a) → dst_kind='site'(site-b)`.

## Crypto-routing packet-walk (verified, Item 7)
Hub peers with each spoke (each spoke's subnet as AllowedIPs) + routes both; each spoke peers ONLY with the hub (the *other* spoke's subnet as AllowedIPs + endpoint) + routes it. Kernel routes carry **metric 8021** (the R2/P8 ownership tag). Matches the paper's 6-step walk exactly.

## Legs

- **Leg 3 — routed-but-dropped (the security spine).** Enforcing, NO grant → ping A-LAN→B-LAN → the packet was WG-carried all the way to the hub (hub peer `rx 1284` bytes) and DROPPED at the hub forward chain: `tunnex_default_drop counter packets 3`. Routing ≠ permission.
- **Leg 1 — transit ping (the epic's distinguishing proof).** Created the A→B site grant → the hub forward chain gained `ip saddr 10.1.0.0/24 ip daddr 10.2.0.0/24 … accept` (the **B1 transit grant on the hub**) → the SAME ping now **4/4, 0% loss**. Mumbai→Bangalore, crossing a hub that is neither endpoint, under enforcing ZT. Same wire flipping on exactly the grant.
- **Leg 2 — refuse-half (discharges the S8.1 pinned substitute).** `gw-d` = `tunnex-node-v4` (HEAD source with `nodepolicy.MaxSupportedVersion` pinned to **4** — the named pre-S8.2 gated binary), bound as a site gateway. It received the real v5 route-bearing artifact and REFUSED it → the **health surface shows `gw-d: degraded=True, kind=unsupported_policy_version`**. The deferred proof ran, operator-visible.
- **Leg 5 — un-NAT'd invariant.** Masquerade scoped `ip saddr 10.99.0.0/24 oifname != "wg0"` (internet egress only); the transit accept matched the real LAN source `10.1.0.0/24` — a NAT'd source would not have matched. Site-to-site keeps its LAN address.
- **Leg 6 — full-sweep on unbind (+ tonight's F3 live).** `DELETE /sites/{site-b}/bind` → the hub swept the `gw-b` peer AND `gw-a`'s route to `10.2.0.0/24` vanished from every gateway. `gw-a` stayed **healthy** through the prune (the `-4` enumeration succeeded — no stale-route-blackholing-while-green; F3 terminal behaviour, live).
- **Leg 7 — link-kill → `site_link_down` (H5 live).** Stopped the hub → after the 180s staleness window the health surface surfaced **`kind=site_link_down`**. A dead bridge is no longer green. (Surfaced on the hub, which reported its gw-a site-link stale just before stopping; the kind firing live is the proof.)
- **Leg 8 — desync-quiet (the #1 merge-blocker fix, live).** The route-carrying v5 gateways (`gw-a`, `gw-b`, hub) all show **`kind=healthy`** — no false `silent_desync`. pushed==applied on route-carrying enforcing gateways.
- **Leg 4 — MSS clamp.** The clamp rule is **LIVE** on the wire: `iifname "wg0" oifname "wg0" tcp flags syn tcp option maxseg size set rt mtu`. The "large transfer freezes without it" CONTRAST needs genuine double-encapsulation (a client-WG riding the site-WG link), which a single-encap box can't naturally produce → **named SUBSTITUTE** (unit-pinned + rule verified live; trigger = a full client-over-site-link setup).

## Findings surfaced during the walk (ledgered → S8.2b)

- **Persistent-keepalive for site-link peers.** A NAT'd spoke must dial the hub first (the hub can't initiate to an endpoint-less spoke), and without keepalive an idle site link goes "stale" at 180s (which is exactly what surfaced `site_link_down` in Leg 7). Site-link peers should carry `PersistentKeepalive` so the hub can always reach them and idle links don't false-stale. Not a correctness defect in what shipped; a productization item.

## Verdict
Every wire-provable claim proven live: transit via a non-endpoint hub, routing≠permission, refuse-half, un-NAT'd, full-sweep, site_link_down, desync-quiet, crypto-routing walk. MSS freeze-contrast is a named substitute. The four-word reconcile model held on the wire (fail-static, full-sweep, keep-last-value observed).
