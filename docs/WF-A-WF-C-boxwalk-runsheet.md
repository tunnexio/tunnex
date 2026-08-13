# Combined box-walk run-sheet — WF-A re-homing + WF-B badge + WF-C L1/L2 (for Pawan)

**What this proves on the wire:** device re-homing (WF-A, both tunnel modes, with the failover→re-home
stopwatch), the site-link badge (WF-B), the graceful-stop wg0 teardown (WF-C L1), and the zombie-hub
honest state (WF-C L2). One session, one provenance. Legs are ordered so each builds on the last box state.

**Branch tip under test:** `story/S8.6-hub-ha` (WF-A slices 2a `fbba363` / 2b `206f144` / 3 `16839da`,
fold `e48196a`; WF-C L1 `52e3f7e`, L2 `6900509`). Rebuild ALL three tiers from this tip — the re-homing
lives in the client, the dial channel + zombie kind in the CP, the peer-swap + carve-out in the helper.

## 0 — Prerequisites (rebuild + redeploy to the tip)

1. **CP + agents** (the cross-cloud stack, established topology):
   - CP: Azure `Tunnex-dev-vm` / `40.65.63.141` — `git pull` to the tip, `sudo TUNNEX_BUILD_TAGS=enterprise docker compose … up -d --build`, confirm `make migrate` applied.
   - **aws-gw** (primary hub): `16.176.32.176` / `172.31.28.80` — redeploy the node-agent to the tip.
   - **inst-2** (standby hub): `172.31.17.64` — enroll into the SAME site's hub set as standby.
   - **azure-gw** (spoke/leaf): `20.245.69.218` / `10.0.0.5`.
2. **Mac client:** rebuild `Tunnex-0.1.0` from the tip, reinstall the `.pkg` (the helper `set_gateway_peer`
   verb + the CP carve-out + the client dial tier all ship here). Confirm the helper version handshake picks
   up the new build (an OLD helper answers `unknown_verb` to `set_gateway_peer` → the client fail-statics =
   no re-home; if a leg shows no re-home, check the helper is the new build FIRST).
3. **Hub set pinned:** in the console, pin the site's hub set = `[aws-gw (primary), inst-2 (standby)]`.
   Confirm the site card shows aws-gw active-primary, inst-2 standby, both links fresh.
4. **Device enrolled:** the Mac's device (`10.99.0.3`) connected split-tunnel, reaching the org.

Record the deployed sha at the top of the walk artifact before Leg 1 (the gate-report-needs-sha law).

## 1 — WF-A split-tunnel re-home (the headline, STOPWATCH)

1. Mac connected **split-tunnel**. `wg show` on the Mac (or the helper status) → note the CURRENT peer
   pubkey = aws-gw's, endpoint = aws-gw. Confirm you can reach an org LAN host through the hub.
2. **Kill the primary's data plane** on aws-gw: `docker stop tunnex-node`. (Layer 1 `52e3f7e` now deletes
   wg0 on the graceful SIGTERM — `ip link show wg0` on aws-gw → **absent**. This is Leg 3's L1 proof, folded
   in here for free.) The data plane is genuinely dead → failover will fire.
3. **START the stopwatch.** Watch the console: aws-gw link goes stale → after the N-stale ticks the
   controller demotes aws-gw + promotes inst-2 (the site card flips active-primary to inst-2).
4. **The re-home:** within one poll cycle after promotion, the Mac's dial tier fetches the new active-hub
   dial and calls `set_gateway_peer`. `wg show` on the Mac → the peer pubkey is now **inst-2's**, endpoint
   inst-2 — **and the interface's own private key + address `10.99.0.3` are UNCHANGED** (no re-enroll: the
   device identity never re-fetched). Traffic to the org LAN resumes through inst-2 **with no manual
   reconnect**. **STOP the stopwatch** — this is the demo's SECOND number (joins the failover time).
5. **Fail-back (one mechanism, both directions):** `docker start tunnex-node` on aws-gw. After M-fresh ticks
   the controller reclaims aws-gw as primary → the Mac re-homes BACK the same way (peer pubkey → aws-gw's).
   Confirm the swap + traffic, same no-reconnect.

**PASS:** peer swapped both directions, device key/address unchanged, no manual reconnect, stopwatch recorded.
**FAIL modes to check first:** old helper (`unknown_verb`) · a null dial (single-gateway — the hub set must
be pinned) · the dial tier gated off (should be on for split).

## 2 — WF-A full-tunnel re-home + kill-switch carve-out (D-WFA-4, macOS)

1. Reconnect the Mac **full-tunnel**. Verify the kill-switch is armed AND the CP carve-out is live:
   `sudo pfctl -a tunnex -sr` → the anchor shows `block drop out all` + `pass out proto udp to <aws-gw> …`
   (WG endpoint) + **`pass out proto tcp to <CP-ip> port 443`** (the D-WFA-4 carve-out) + loopback/tunnel/
   DHCP/NDP. Confirm the CP (`40.65.63.141`) is reachable (control channel independent of the tunnel), and
   a NON-carved host is NOT (the kill-switch still blocks everything else — e.g. `ping 8.8.8.8` fails while
   the tunnel's own DNS/routes carry normal traffic). **This is the block-all-minus-exactly-the-named-
   exceptions proof on the wire.**
2. **Kill the primary** (`docker stop tunnex-node` on aws-gw) → promotion, as Leg 1.
3. **The full-tunnel re-home:** the Mac re-homes to inst-2 — the helper swaps the peer AND re-points the pf
   carve-out + WG host-route to inst-2. `pfctl -a tunnex -sr` → the WG endpoint pass now names **inst-2**,
   the CP pass unchanged, `block drop out all` still present. **Watch for a cleartext leak during the swap**
   (a pcap on the Mac's physical NIC across the re-home window → zero cleartext to a blocked host). Traffic
   resumes full-tunnel through inst-2.

**PASS:** full re-home works IDENTICALLY to split (the refusal seam is retired on macOS), the kill-switch
stays armed throughout (no leak window), the CP pass persists across the swap.
**Windows note:** Windows full-tunnel re-home is DEFERRED (S8.6b-win-carveout) — if you have a Windows box,
its full-tunnel re-home should REFUSE (`rehome_full_tunnel_unsupported`, the client fail-statics, manual
reconnect); Windows SPLIT re-home should work like Leg 1. If no Windows box, this SUBSTITUTES to the unit
reds (helper crosscompiles; the refusal is unit-proven) with the trigger = first Windows full-tunnel HA walk.

## 3 — WF-C L1 graceful-stop wg0 teardown

Already exercised in Leg 1 step 2 (`docker stop` → `ip link show wg0` absent on aws-gw). If you want it
isolated: on a hub NOT mid-failover, `docker stop tunnex-node` → `ip link show wg0` → **absent** (Layer 1),
vs the pre-`52e3f7e` behaviour where it lingered. **PASS:** graceful stop leaves no orphaned wg0.

## 4 — WF-C L2 zombie hub — the honest state (the new observation)

This is the hard-crash residual: SIGKILL skips Layer 1's defer, so wg0 SURVIVES and forwards headless.

1. With aws-gw the active primary and the Mac connected, **hard-kill the agent** (SIGKILL, NOT graceful):
   `docker kill -s KILL tunnex-node` on aws-gw. **Do NOT `ip link del`** — the point is that wg0 survives.
2. On aws-gw: `ip link show wg0` → **still present**; it keeps forwarding (a spoke still handshakes it →
   the data-plane handshake stays fresh). The agent is gone (`docker ps` → the node container down).
3. **On the dashboard / site card:** within `hubStaleWindow` (~90s, aws-gw's `last_seen` goes stale while
   its wire stays warm) the aws-gw gateway shows **`agent down — still forwarding (restart agent)`** (kind
   `hub_forwarding_not_reconciling`, danger tone). **It must NOT show green** (that would deny it's stale)
   **and must NOT show plain "offline"** (that would deny it forwards). Screenshot this — it's (a)'s live
   proof, and it costs the walk exactly ONE extra observation, not a new leg.
4. **Recovery:** `docker start tunnex-node` on aws-gw → the agent reports again → the zombie kind clears
   (back to healthy) as `last_seen` refreshes.

**PASS:** the zombie renders as the distinct honest kind, lying in NEITHER direction; recovery clears it.

## 5 — WF-B site-link badge (subordinate note)

During a failover where the DEMOTED member's link is dead while transit rides the fresh active primary
(the Leg-1 window, after promotion but before you `docker start` aws-gw back): the site card headline stays
**healthy/transit-up** (transit rides inst-2 at 0% loss) with a SUBORDINATE line naming the demoted-dead
peer — e.g. **`site link: aws-gw (demoted)`** — NOT a headline `site link down`. A real transit failure
(kill the ACTIVE primary's link with no standby) instead shows the headline down (the inverse-red guard).

**PASS:** the demoted-dead link is a subordinate note under a healthy headline (a healthy failover reads
transit-healthy), never a reassuring green over a real outage.

## Census / observations (record even if "nothing")

- **(c)-trigger evidence check (WF-C L2):** during the zombie leg, **did any device keep dialing the zombie
  aws-gw?** WF-A makes devices dial the active primary, so post-promotion they should be on inst-2 — but if
  a device is observed dialing the zombie (agent dead, still forwarding it), **that is D-WFC2-1's option (c)
  trigger firing on evidence** — record it verbatim in the walk artifact (it promotes (c) from registered to
  actionable). Expected today: none (the device re-homed off aws-gw in Leg 1).
- **Stale-enforcement (bounded, WF-C L2):** optionally, while aws-gw is a zombie, revoke the Mac's device in
  the console → confirm the Mac's OWN client tears the tunnel down (RevocationMonitor) even though the zombie
  hub still holds the stale peer — the multi-point-enforcement bound the paper claims. Record it.
- **Every leg's kill command** — write down which kill you used (`docker stop` = graceful/L1, `docker kill
  -s KILL` = zombie/L2), because the two produce OPPOSITE wg0 outcomes and a mixed-up kill is the walk's
  classic confusion (the original "docker stop didn't fail over" was a wrong-kill artifact, now closed by L1).

## The two demo numbers

1. **Failover time** — primary killed → controller promotes the standby (site card flips).
2. **Re-home time** — promotion → device dials the new hub, traffic resumes (Leg 1 stopwatch).

Commit all artifacts (screenshots, `wg show` / `pfctl -sr` / `ip link` captures, the stopwatch) to
`walk-artifacts/` DURING the session (walk evidence is committed live, not after). Scratch WG configs carry
private keys — gitignore them at creation, never commit.
