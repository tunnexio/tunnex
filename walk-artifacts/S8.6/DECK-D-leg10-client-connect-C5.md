# Deck D — Leg 10: desktop client connect + C5 device-revoke (2026-07-23)

CP for this session: `104.45.208.156` = the SAME walk env RE-ADDRESSED (census-confirmed
on-host: `~/tunnex` @ `782d036`, branch story/S8.7-cidr-conntrack, dirty = `.env.example`
only; stack rebuilt from local compose 2 h before this leg — Deck D header's
`40.65.63.141 @ 782d036` is this box's prior address, same sha). Gateway agents run
`ghcr.io/iotunnex/tunnex-node-agent:latest` (~20 h old) — mixed provenance (CP local-built,
agents ghcr) recorded per census law. WF-1's root (`siteLinkGraphFrom` pool omission)
verified present at BOTH 782d036 and the local S8.6 tip. Client: dev-mode
Electron (direct-binary launch), helper manually installed with dev trust dir.
Topology: aws-site 172.31.0.0/16 (aws-gw-1 HUB primary + aws-gw-2 standby),
azure-site 10.0.0.0/16 (azure-gw spoke), device pool 10.99.0.0/16 (mac = 10.99.0.2).
Zero Trust OFF (open mesh) for the whole leg.

## Known limitation (NOT a WF) — Gatekeeper "Malware Blocked"

Sequoia hard-blocks the unsigned .pkg-installed app ("contains malware" wording for
a fully-unsigned bundle). Confirmed live on the founder's machine. No code fix exists:
requires Developer ID signing = S6.5b, entity-gated (founder-desk item). The dev-build
fix IS the documented workaround (ad-hoc `codesign --force --deep --sign -` +
`xattr -dr com.apple.quarantine`); walk proceeded via direct-binary launch + dev-trust
helper install. Recorded as **known-limitation-confirmed-live (S6.5b, entity-gated)**.

## Leg 10 journey — observed

1. Client configured to fresh CP (state wipe → setup screen → new CP URL accepted via
   /healthz validation). Sign-in via browser flow → dashboard live.
2. Device enroll: `tunnex-desktop-Pawan-Gupta-MBP.local` minted `10.99.0.2`, split
   tunnel. Routes applied on mac: `172.31/16`, `10/16`, `10.99/24` via utun4 —
   BOTH sites' ranges pushed correctly (routed-ranges channel VERIFIED; an earlier
   "missing route" scare was a netstat display-format misread, `10/16` == 10.0.0.0/16).
3. Device → hub's own site: **PASS** (all 3 AWS machines reachable after WF-1 manual
   unblocks below; ttl=63 behind-host, ttl=127 Windows peer device).
4. Device → remote site via hub transit: **FAIL by construction** → WF-1.
5. Live flow established (ping to 172.31.10.85), then **C5: revoke from Devices UI**.

## C5 — device-revoke crypto-death (PROVEN)

- Pre-revoke `wg show wg0` on hub (walk-artifacts evidence, /tmp/wg-before-revoke.txt):
  peer `n+lu141l4RmTWVfEW7ojtYHVWVZv4LvV2ftjrWNFIWY=` allowed-ips `10.99.0.2/32`,
  handshake 1m16s, transfer 138 KiB rx / 47 KiB tx (live flow).
- Revoke clicked in web UI → device row flips to `revoked`.
- Post-revoke `wg show wg0`: device peer **ABSENT** — only the azure-gw site-link peer
  remains. Flow dies by PEER REMOVAL (crypto-death), no conntrack semantics involved.
  **D6 exemption proven on the wire.**
- Live-flow death trace (mac): replies through icmp_seq=149 (ttl=63, ~282 ms), then
  unbroken `Request timeout` from seq=150 — flow died AT the revoke, mid-stream.
- Client banner FIRED: "Device revoked — reconnect to re-enroll" + "Your device was
  revoked or removed on the server. The local profile has been cleared — reconnecting
  will enroll a fresh device." (RevocationMonitor loud-banner path, screenshot taken.)

## WF findings (HELD for disposition — no fold)

**WF-1 — device-to-remote-site-via-hub broken by construction (root cause in code).**
`siteLinkGraphFrom` (apps/api/internal/nodes/service.go:832-844) compiles a spoke's
hub-peer AllowedIPs from remote SITE subnets only (`routeCIDRs`); the device pool is
compiled into NO site-link peer. Three surfaces, one root:
  a. **wg crypto-routing:** azure-gw's hub peer allowed-ips = `172.31.0.0/16` only →
     inbound device-sourced (10.99.0.2) transit packets dropped at the wg layer;
     replies unroutable (no peer covers 10.99.0.0/16). tcpdump wg0 on spoke: silent.
  b. **agent forward rules:** `tunnex-site-fwd` DOCKER-USER accepts cover site routes
     only → device-pool traffic falls to Docker's FORWARD policy DROP even on the
     hub's own site (230 drops counted live). Same class as S8.2c WF-4.
  c. **cloud fabric teaching text:** no mention that the DEVICE POOL CIDR needs a
     return route (AWS route table / Azure UDR) alongside the site ranges.
WIRE-PROVEN FIXABLE: manual `wg set … allowed-ips 172.31.0.0/16,10.99.0.0/16` on the
spoke's hub peer + manual DOCKER-USER pool accepts (both gws) + pool routes in both
clouds → full 4-leg path alive (mac → hub → azure-gw → 10.0.0.4 → back, ttl=62,
~7 s of replies)…
**…until the agent reconcile REVERTED the manual wg mutation (~7 s) and the path died
again — drift-detection convergence live-proven as a positive side-proof.**
Candidate fix (needs disposition): compile pool CIDR into the spoke's hub-PRIMARY peer
AllowedIPs only (standby stays empty — preserves the S8.6 single-valued invariant;
failover recompile carries it) + agent-owned DOCKER-USER pool accepts + fabric text.
Alternatives: NAT at spoke egress (rejected-leaning: destroys source identity);
out-of-scope ledger to a follow-up story.

**WF-2 — revoked device inflates the dashboard device count (CONFIRMED, founder-ruled).**
Post-revoke, the Overview tile still reads "1 Devices" — the revoked device counts.
Reassuring-count class: the first number an admin sees overstates live inventory.
(Positive rider on the same screen: the S6.4 revocation banner fired at its exact
design moment — "Device revoked — reconnect to re-enroll" + profile-cleared text —
the user is TOLD why the connection died, not left guessing.)

## Manual walk-time mutations (to sweep/revert)

- aws-gw-1 + azure-gw: `iptables -I DOCKER-USER` pool accepts (2 rules each, NOT
  agent-owned, do not survive as product state).
- AWS VPC route table: `10.99.0.0/16 → aws-gw-1 ENI` (KEEP if WF-1 fix lands; it is
  the documented fabric step).
- Azure tunnex-rt: `vpn-rt 10.99.0.0/16 → 10.0.0.5` (same).
- wg allowed-ips mutation: already reverted by reconcile (nothing to sweep).

## Verdicts carried

- Leg 10 core (enroll → connect → live flow → C5 revoke): **PASS**.
- C5 (D6 exemption): **PASS, proven by peer removal**.
- Device cross-site transit: **FAIL → WF-1**, held.
- Drift-convergence (desired-state reconcile vs manual mutation): **PASS (bonus proof)**.
