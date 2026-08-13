# WF-A / WF-B / WF-C box-walk — RECORD (2026-07-24, live cross-cloud)

**Branch:** `walk/epic8-smooth-walk`. **Deployed tip at walk time:** `a1729cd` (CP + agents + client),
then `3eaea5b` (WF-A-FT-1 fix, re-run mid-walk). **Post-walk folds:** `c0becc8`.
**Provenance:** single session, sha-first per the gate law. Screenshots + probe streams captured live.

## Topology (this walk)

| Box | Public | Private | Role |
|---|---|---|---|
| azure-cp | 104.45.208.156 | 10.0.0.4 | Control plane (enterprise) + D-WFA-4 carve-out target (`:80`) |
| aws-gw-1 | 15.134.60.253 | 172.31.1.217 | Hub PRIMARY (pin #1) — **upgraded to tip agent** (kill target) |
| aws-gw-2 | 15.135.130.96 | 172.31.9.62 | Hub STANDBY (pin #2) — old `0.1.0` agent |
| azure-gw | 52.190.140.51 | 10.0.0.5 | spoke (azure-site) |
| aws-behind-host | — | 172.31.10.85 | behind-host (not exercised) |
| Mac | 119.252.201.164 (NAT) | 10.99.0.3 | client (device `10.99.0.3`, pubkey `LyAg7EZk…Ekk=`) |

Hub set pinned `[aws-gw-1, aws-gw-2]`. Only aws-gw-1 carried the tip agent (condition (a) of the
WF-A-FT-1 ruling — a promoted standby on the OLD agent serving traffic is itself informative, and it did).

## Legs — all 5 GREEN

### Leg 1 — WF-A split-tunnel re-home (both directions) ✅
- Before: device `LyAg7EZk…Ekk=` / `10.99.0.3/32` on aws-gw-1 (`wg show`).
- Kill aws-gw-1 (honest `docker stop` on the tip agent) → **wg0 GONE** (WF-C L1, Leg 3 folded in free).
- Failover fired: `hub_set.promotion` (`condition=primary_stale`, gen 7), aws-gw-2 → PRIMARY. Device
  re-homed to aws-gw-2 — **same pubkey + `10.99.0.3`**, ping resumed with NO manual reconnect.
- Failback: `docker start` aws-gw-1 → reclaimed PRIMARY (gen 8, `hub_set.failback recovered`), device
  re-homed BACK to aws-gw-1, ping blip ~3 packets. **One mechanism, both directions** (D-WFA-1c/-3).
- Numbers: failover ≈ 4–5 min (240s stale window + demote ticks); re-home ≈ one poll after promotion.

### Leg 2 — WF-A full-tunnel re-home + D-WFA-4 carve-out ✅
- **Carve-out ruleset (pfctl -a tunnex -sr):** `block drop out all` + `pass out udp to 15.134.60.253
  port 51820` (WG) + `pass out tcp to 104.45.208.156 port 80` (CP) + lo0/utun/DHCP/NDP — **block-all
  minus EXACTLY the named exceptions, no `to any`.** whatismyip = the gateway IP (full-tunnel capturing all).
- **Kill-switch invariant on the wire (probe streams):** during the tunnel-down window the CP probe held
  **`CP=200` unbroken** (control channel independent via the carve-out) while the exit probe was
  **`TIMEOUT`** (zero cleartext leak). Port-scoped bonus: SSH (`:22`) to the two carve-out IPs was BLOCKED
  (only their one named port passes) — the carve-out is scoped to IP **and** port.
- **WF-A-FT-1 found here (merge-gating):** full-tunnel re-home first STUCK on "connecting" (split worked).
  Root cause: `SetGatewayPeer`'s endpoint host-route re-pin used `gatewayFor()`, which after the tunnel
  default is installed returns the TUNNEL next-hop → new gateway's outer packets loop → handshake never
  completes. **Fixed live** (`3eaea5b`, store the physical gateway at Up) → re-run: full-tunnel re-homed
  **automatically aws-gw-2 → aws-gw-1, no reconnect**, exit flipped `15.135.130.96` → `15.134.60.253` with a
  ~14–21s peer-swap blip. **Leg 2 PASS.**

### Leg 3 — WF-C L1 graceful wg0 teardown ✅
Folded into Leg 1: honest `docker stop` on the tip agent → `wg0 GONE` (the deferred `Close` = `ip link del`).
The un-upgraded agents leave wg0 orphaned; the tip agent does not.

### Leg 4 — WF-C L2 real zombie (true positive) ✅
- SIGKILL aws-gw-1 → **wg0 SURVIVED** (defer skipped), container gone.
- Console: aws-gw-1 **"agent down — still forwarding (restart agent)"** (`hub_forwarding_not_reconciling`),
  correct + persistent. HA panel: aws-gw-1 **still PRIMARY, warm** — failover did NOT fire (wire fresh).
- Mac ping: **58 packets, 0 loss** — device still reaching the org THROUGH the zombie.
- Validated the WF-C-L2-1 settle fix: a live zombie keeps the handshake age low, so the settle preserves it.

### Leg 5 — WF-B demoted badge ✅
During the Leg-1 failover: aws-gw-2 online/HUB with subordinate **"site link down: aws-gw-1 (demoted)"** —
a named subordinate note under a healthy transit headline, not a headline outage. The `(demoted)` qualifier
reads "expected, failed-over-past."

## By-design clarifications recorded (not findings)
- **VPC-route independence:** device↔gateway↔spoke-gateway is 100% WireGuard over public endpoints → hub
  failover needs NO cloud route change (Pawan's `ping 10.0.0.5` worked without touching the VPC route). The
  cloud-fabric-pinning caveat applies ONLY to a **behind-host** (LAN return path via the gateway ENI).
- **Manual-disconnect exit-IP:** the real-IP exit readings were during a MANUAL VPN Disconnect (graceful Down
  releases the kill-switch by design) — not a leak during the armed window.
- **Console agent-version is enroll-time:** an in-place agent upgrade shows the OLD version until re-enroll
  (cosmetic; the image tag is the real marker). Noted, not folded.

## Findings + dispositions

| ID | Sev | Disposition | Commit |
|---|---|---|---|
| **WF-A-FT-1** | merge-gating | FIXED + wire-re-verified (store physical gateway at Up; explicit-gw pin) | `3eaea5b` |
| **WF-C-L2-1** | not merge-gating | FOLDED — zombie settle-hysteresis (`agentAge−wireAge >= hubStaleWindow`) + clean-death true-negative red | `c0becc8` |
| **WF-A-obs-1** | low | FOLDED — `gateway_peer_swapped` breadcrumb (darwin+windows) | `c0becc8` |

## Gate shas
- Walk-deployed: `a1729cd`. WF-A-FT-1 fix: `3eaea5b` (helper darwin green + win crosscompile; reds:
  physGatewayFor per-family, pinHostRouteVia via-given-gateway, empty-gw skip). Folds: `c0becc8` (both
  editions build; nodes zombie red open+enterprise; helper darwin+cross; generate-check clean).

**Next:** targeted re-review over the fold set (WF-A-FT-1 + WF-C-L2-1 + WF-A-obs-1) → on clean, merge summary.
