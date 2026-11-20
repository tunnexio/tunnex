# SSI-11 — the Failover tab says what the controller will do, and when

Status: built on `story/site-to-site-improvements`. Local only.

## What the failover walk found

Recorded in `docs/SSI-10-boxwalk.md` (2026-11-20). Stopping the primary hub cost about five minutes
before the standby took over. During that time the Failover tab:

1. marked a hub **Stale** after 90 s (`HUB_STALE_MS`), a window the controller abandoned for 240 s
   because a healthy WireGuard link's handshake age legitimately reaches about 200 s
   (`failoverStaleWindow`, `apps/api/internal/nodes/failover.go`). So the tab showed healthy hubs as
   stale on every rekey cycle, and a truly dead hub as stale for two and a half minutes during which
   the controller, correctly, did nothing;
2. showed no pending state at all. An operator watching a dead primary could not tell whether a
   failover was coming, was stuck, or was not configured;
3. did not refresh. The verdict on screen was whatever was true when the page loaded.

## Decisions

**D1. One window, served.** The dashboard stops owning a staleness constant. `GET /hub-set` gains a
required `failover` object with the controller's own timings in seconds: `stale_after_seconds`,
`demote_after_seconds` (demote ticks × tick interval) and `restore_after_seconds` (restore ticks ×
tick interval). They are computed from the constants in `failover.go`, so a change there reaches the
dashboard without a second edit. The dashboard's Recent/Stale badge uses `stale_after_seconds`.

Rejected: copying 240 s into the web bundle. That is the same two-clocks defect one constant later.

Rejected: serving the controller's live tick counters. They are in memory on whichever control-plane
process runs the ticker, are not persisted by design, and a read served by another process would
report zeros. Timings are static and true everywhere.

**D2. The tab states the pending ruling, as an estimate.** From the served timings and the handshake
age it already shows, the tab says, for a hub that is acting (not demoted) and stale:

- another acting hub is fresh: "*name* has not answered for *age*. If it stays unreachable, a standby
  takes over in about *remaining*." `remaining = stale_after + demote_after − age`, never below
  "within a minute".
- no other hub is fresh: "…No standby is answering either, so there is nothing to promote."

and for a demoted hub whose handshake is fresh again: "*name* is answering again. It returns to its
configured place after about *restore_after* of steady handshakes."

These are estimates and are worded as such ("about"). The counters restart if the control plane
restarts and hold when no observer reports, so an exact countdown would be a claim the dashboard
cannot keep. Nothing is shown for a hub nobody can observe: the SSI-9 notice already covers it and a
countdown there would be false.

**D3. The Failover tab refreshes itself.** Every 15 s while the tab is open and the page is visible.
Other tabs are unchanged.

**D4. "How failover works" gives the numbers.** The help text states the detection time and the
return time from the served timings instead of "can change when a candidate becomes unavailable".

## Not in this story

- Shortening the five minutes. The 240 s window is derived from the WireGuard rekey cycle; going
  below it needs an active probe from the observing gateway. Separate story, own paper.
- Failover for an organisation with one network (no observer).
- The Gateways list "Offline after 90 s" badge. That is a different signal (the gateway's own status
  report to the control plane, 30 s cadence) and 90 s is right for it.

## Tests

- api: `TestFailoverTimingDerivesFromControllerConstants`.
- web: `hubsetview.test.ts` — window comes from the served timing; pending/recovering/no-standby
  notices; nothing for an unobservable hub.
