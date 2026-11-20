# SSI-12 — a dead hub is noticed in seconds, not minutes

Status: built on `story/site-to-site-improvements`. Local only.

## The problem, measured

Two walks on real gateways (`docs/SSI-10-boxwalk.md`): stopping the primary hub cost about **4 min 55 s
of downtime** for devices and for the other network. Nearly all of it is detection. The controller
judges a hub by the AGE of its WireGuard handshake, and a healthy link's handshake age legitimately
reaches about 200 s between rekeys, so the stale window is 240 s (`failoverStaleWindow`), followed by
three 30 s ticks.

## What a living hub does that a dead one cannot

Every site-link peer carries a persistent keepalive. So on an idle, healthy link the OBSERVING
gateway's receive counter for the hub still advances every keepalive interval; for a dead hub it
never advances again. Measured on the Google Cloud gateway with nothing but keepalives flowing: the
counter for the acting hub and for the warm standby both moved every 25 to 30 s.

The agent already reports that counter on every status report. The control plane stored only the
latest value, so it could not tell "advancing" from "frozen".

## Decisions

**D1. Remember receive progress.** `node_peer_status` gains `rx_advanced_at` (control-plane time of
the last report whose `rx_bytes` differed) and `stalled_reports` (consecutive reports since with the
same value). Written by the existing upsert. No new agent field, no new report.

**D2. A hub is stale when its witnesses' counters have frozen.** In the one liveness derivation
(`deriveMemberLiveness`), a witness row gives receive evidence when it is CURRENT (the witness itself
reported within `witnessCurrentWindow`) and the link has handshaked at least once. That evidence says
*stalled* when the counter has not moved for `rxStallReports` consecutive reports AND for at least
`rxStallWindow`. Then:

- any current witness sees progress → the hub is fresh;
- every current witness with evidence says stalled → the hub is stale;
- no current witness has evidence → the handshake rule decides, exactly as before.

"Any witness sees it alive" keeps the costly error (a false demotion) rare: one observer with a
broken path cannot demote a hub others still reach. Requiring a count of reports as well as a
duration makes the rule adapt to the agent's report cadence by itself: a gateway reporting every 30 s
needs two reports (about a minute); one reporting every 10 s needs about 35 s.

A witness that has stopped reporting says nothing (`witnessCurrentWindow`). Before this, a dead
witness's last row kept ageing and could testify against a healthy hub.

**D3. Keepalive 25 s → 10 s on site links**, so the counter moves often enough for a short window. A
32-byte packet every 10 s per link. `rxStallWindow` is 35 s: three keepalives and slack.

**D4. Tick 30 s → 10 s; demote after 2 ticks; restore after 15 ticks.** Fail-over fast, fail-back
slow (150 s, unchanged in duration). The frozen-handshake path keeps its 240 s window and now
confirms in 20 s instead of 90 s: a frozen handshake cannot flap.

**D5. The dashboard shows the controller's verdict, not a recomputation.** `GET /hub-set` members
gain `liveness` (`fresh` / `stale` / `unobserved`) and `silent_seconds`. The Failover tab's badge and
pending notice read those. `failover.stale_after_seconds` now states the fast window.

**D6. Report cadence stays an operator setting.** `TUNNEX_AGENT_STATUS_INTERVAL` (default 30 s)
already exists on the gateway. At the default, detection is roughly 70 to 100 s; at 10 s on the
observing gateways it is roughly 40 to 60 s. The default is not changed here: every report writes one
row per connected device, and tripling that for every fleet is a capacity decision of its own.

## What this does not do

- It does not detect a hub that still answers keepalives but no longer forwards. Neither did the
  handshake rule. That needs an end-to-end probe.
- It does not give a single-network organisation failover: still no witness.
- Devices follow on their next routed-ranges poll, as before.

## Tests

- `TestDeriveMemberLivenessRxProgress` — frozen counter demotes fast; one fresh witness outvotes a
  stalled one; a silent witness says nothing; a never-handshaked link gives no verdict; no receive
  evidence falls back to the handshake rule.
- `TestFailoverTimingDerivesFromControllerConstants` (updated).
- Postgres: the upsert moves `rx_advanced_at` only on change and counts stalls.
