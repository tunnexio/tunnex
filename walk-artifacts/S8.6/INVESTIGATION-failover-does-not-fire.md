# S8.6 failover-does-not-fire — Phase 1 investigation (cited, decision-first)

Branch story/S8.6-hub-ha @ 4506772. Read end-to-end: failover.go (whole),
service.go ReportStatus/latestByPubKey/GetHubSetView/DesiredState/electSiteHub/
electSiteHubSet/ReconcileHubSet/SetHubPriority, nodes.sql + sites.sql queries,
main.go tick wiring. NO code written, NO decision taken — decide-items HELD.

## The liveness substrate (who writes a hub's freshness, does it move when it dies)

- `ReportStatus` (service.go:942) writes `node_peer_status(node_id = REPORTER,
  public_key = PEER, last_handshake_at = hs)` as the sibling of device_status.
  The upsert's EXISTS guard (nodes.sql UpsertNodePeerStatus) admits a row ONLY
  when `public_key` is ANOTHER gateway node in the same org — a device pubkey
  no-ops here. So a hub's rows are written BY its peers ABOUT the hub.
- A hub's freshness = `latestByPubKey` (service.go:651) = MAX(last_handshake_at)
  across all reporters keyed by the hub's pubkey. `failoverOrg` (failover.go:196):
  `freshness[id] = !t.IsZero() && now.Sub(t) < failoverStaleWindow(90s)`.
- **Does it move when the subject dies?** YES — correctly. A dead hub's handshake
  FREEZES at every living peer (no peer can complete a NEW handshake with a dead
  node), so `now.Sub(frozen)` grows monotonically, crosses 90s, and STAYS stale.
  There is NO wire mechanism that refreshes it — **the "freshness flickers back
  fresh → Step's consecutive-stale counter resets → never reaches N" hypothesis
  has no substrate.** No living node can produce a <90s handshake for a dead peer.
  This is the founder's "observed-from-the-living-side" signal, and it is
  architecturally the RIGHT signal: observed by the living about the dead, and it
  ages when the subject dies.

## Derivation census on liveness (one truth?)

CLEAN. `deriveActive(configured, demoted)` (service.go:466) is the ONE derivation:
- policy compile ← `electSiteHub(topo)` (service.go:328) → `activeHubMembers` →
  `topo.hubMembers` (= deriveActive order, set in loadSiteTopology). electSiteHub[0]
  is the persisted active HEAD — it does NOT re-elect independently.
- data-plane graph ← `siteLinkGraphFrom` → `activeHubMembers` (same source).
- `GetHubSetView` ← `hs.Active()` = deriveActive, per-member handshake from the
  SAME `latestByPubKey`. So the view's "handshake 4m" IS the controller's freshness
  input — same number. A view showing 4m ⇒ controller freshness = STALE (240s > 90s).
- failover controller reads `configured`, writes `demoted` only (writer partition).

## The logic, traced, DEMOTES a persistently-stale primary

Dead hub stays `status='active'` (ListSiteGatewaysForOrg has NO liveness filter,
only status='active') with its last endpoint+wgkey → stays capable+pinned in
electSiteHubSet → `len(configured) >= 2` holds → freshness false for ≥90s and
STAYS false → Step accrues 3 consecutive stale (fresh branch never taken, no
counter reset) → `demoted=[hub]` → deriveActive reorders → demotedChanged →
persist demoted + audit `hub_set.promotion` + next ordinary compile re-homes
site-links + transit policy to the standby.

**So the ALGORITHM predicts demotion within ~90s of staleness onset. This
CONTRADICTS the walk (5 min, zero demotion, no promotion audit).** The gap is
NOT in failover.go's algorithm. It is one of the roots below — each needs ONE
datum from the iron the founder controls.

## Candidate roots (ranked) — each with its one decisive datum

1. **[ARCHITECTURAL — resolve first] What did Deck B's ping traverse?**
   Hub-set failover re-elects the SITE-TO-SITE TRANSIT HUB. It changes which
   gateway carries inter-site traffic and where spoke gateways point their
   site-link. It does NOT re-home a client DEVICE's tunnel — a device's peers come
   from `ListActivePeersForNode` (service.go:266), hub-set-INDEPENDENT. If Deck B
   killed a device's terminating gateway and pinged expecting the standby to serve
   the DEVICE, "failover does not fire" is BY DESIGN — the tested capability
   (device gateway HA) does not exist in S8.6; that's a new story, not a bug.
   Decisive datum: the ping's actual src → dst (device→internet? or host-in-siteB
   → host-in-siteA via the hub?).

2. **Was the CP binary actually S8.6+?** Mid-session the CP was source-built from
   `story/S8.4-dns` (PRE-S8.6 — no RunFailoverTick in that binary at all).
   Counter-evidence: the founder saw role="standby" + per-member handshake age,
   both GetHubSetView/S8.6 features → argues the binary WAS S8.6. Decisive datum:
   the CP's built git sha / a startup log / proof the tick ever wrote a row.

3. **Persisted `org_hub_set.configured` length at kill time.** ListFailoverOrgs
   gates the tick on `array_length(configured,1) > 1`. Weakened by role="standby"
   (implies configured=2), but confirm. Decisive datum:
   `SELECT configured, demoted, generation FROM org_hub_set WHERE org_id=…`.

4. **Silent per-tick error.** failoverOrg errors are swallowed to a single generic
   `slog.Warn("failover_tick_failed")`. Decisive datum: grep the CP logs for it.

## Two REAL code defects found regardless of which root bit Deck B (HELD)

A. **Near-zero failover observability.** A stale primary that never demotes emits
   NOTHING — no "tick ran for org X", no freshness/counter trace, no "considering
   demotion". Only signal is a generic swallowed slog.Warn. For a merge-gating
   fail-closed HA path this is the actual gap: **the wire re-run the founder wants
   as the fix's only accepted proof is UNDIAGNOSABLE without it.** The fake-clock
   red tests the algorithm; observability makes the iron re-run readable.

B. **The pinned-before-capable ADDITION gap.** `configured` is recomputed ONLY on
   discrete membership events (pin/bind/unbind/revoke — grep-confirmed ReportWGInfo
   does NOT trigger ReconcileHubSet). A standby PINNED BEFORE it reported its
   WG key/endpoint is excluded from configured at pin time (capability gate) and
   NEVER re-added. The tick's own live "configured corrector" cannot rescue it:
   ListFailoverOrgs gates on the stale single-length configured → the org is
   invisible to the tick. The corrector's comment claims it covers "every removal
   path by construction" — TRUE for removals (a departed-but-still-configured
   gateway keeps length>1, org stays visible, corrector shrinks it) — but it
   STRUCTURALLY CANNOT cover ADDITIONS (a should-be-added gateway keeps length≤1 →
   org invisible → corrector never runs). Removal self-heals; addition does not.
   This PREDICTS the exact walk outcome IF persisted configured was single (root 3).

## ROOT RATIFIED = the window (iron datum, D2 writer REFUTED)

Iron query returned distinct observer rows (azure observed by both AWS nodes;
azure→aws-gw-2 at 1:29 warm keepalive), healthy steady-state ages 1:29–3:22
against a 90s window. Writer clobber refuted. `failoverStaleWindow=90s`
(failover.go:29) is TIGHTER than WG's ~120–180s rekey cadence; the agent's own
`siteLinkStaleWindow=180s` (reconcile.go:162) is deliberately "comfortably above
WireGuard's ~2-min rehandshake" — the CP window contradicts that floor.

## Point-3 trace: failoverOrg against the live rows — reconciling flicker vs non-firing

freshness[id] = latestByPubKey(rows)[pubkey[id]] within 90s, per configured id.
- `pubkey[id]` = nodes.wg_public_key (electSiteHubSet). `latest` keyed by
  nps.public_key (agent-reported peer key). SAME base64 → NO keying miss (the
  iron rows are read; the view rendered their ages). Confirmed: no filter/keying
  second defect.
- NULL handshake rows: latestByPubKey guards `r.LastHandshakeAt.Valid` → a NULL
  row is SKIPPED, never sets latest, never poisons MAX. Current code already
  correct; a red LOCKS it (founder point 2). The same-site hub pair (aws-gw ↔
  aws-gw-2) does NOT peer (service.go:50 same-site exclusion) so their mutual
  entry is absent/NULL — must read as stale, never fresh.

WINDOW predicts the FLICKER + steady-state NON-spurious-demotion:
  Healthy link rehandshakes ~every 120s → observed age sawtooths 0→~120s. With a
  90s window, age>90s ~1 tick per 120s cycle, then a rekey resets age<90s → fresh
  tick resets Step's consecutive-stale counter → NEVER 3 consecutive → no spurious
  demotion, yet a snapshot catches age in 90–120s = the stale BADGE (#4). ✓

WINDOW does NOT explain the kill-time NON-FIRING:
  On a CLEAN kill, rehandshakes CEASE → azure's observed handshake FREEZES →
  age grows monotonically past 90s and STAYS → 3 consecutive stale within ≤~180s
  → demote. The corrected model (180s window) fires even sooner-relative. So a
  clean kill ALWAYS demotes in bounded time. The observed 5-min zero-demotion is
  therefore EXOGENOUS, not a freshness/keying defect:
    (a) mixed/stale CP build during Deck B (ticker absent or pre-fold), or
    (b) silent tick error (swallowed slog.Warn — defect A, observability), or
    (c) incomplete kill (wg0 survived in-container → aws-gw kept handshaking →
        azure kept observing fresh → never stale). docker stop + host `ip link del
        wg0` can miss a container-netns wg0.
  NO code fix in the freshness path addresses (a)/(b)/(c). They are settled ONLY
  by a clean-build rematch with the kill verified complete.

## Build plan (window fix) — RULED

1. failoverStaleWindow: 90s → a protocol-derived constant ≥ 180s rekey floor +
   slack. Cite the derivation in-code (why NOT 90 — the narrowing-was-incidental
   lesson: reader must know it tracks WG's REKEY/REJECT cadence, not a guess).
2. NULL-handshake explicit in the aggregation + a red (never fresh, never poison).
3. Red family re-derived vs the corrected window: clean-kill fires (freeze → N
   ticks → demote); INVERSE steady-state red — healthy links at 2–3min ages
   produce ZERO demotions (the flicker fixture inverted); no-spokes edge = no
   verdict.
4. #2 bind-UI fix (Sites.tsx:491 list-of-one in the action path).

## FORK surfaced before code (founder point-3 obligation)

The trace found NO filter/keying second defect. It found the OPPOSITE: the
corrected model FIRES on a clean kill, so the non-firing is exogenous (a/b/c).
Consequence: the window fix ALONE cannot make the Deck B rematch conclusive — if
it non-fires again, we're blind for another 5 minutes (defect A). DECIDE: does
this fold ALSO land minimal failover observability (one log line per tick: org,
per-member observed age + stale/fresh + counter + demote/restore decision), so a
repeat non-fire is diagnosed in one tick instead of a blind wait? Recommend YES —
cheap, and it is what turns the rematch into proof.

## Phase 2 decide-items — HELD for founder ruling (no code until ruled)

- The ONE liveness truth: node_peer_status peer-observed handshake is confirmed
  correct (moves when the subject dies). Confirm as the authoritative signal.
- Step's consumption of it: algorithm is correct; the fix is OBSERVABILITY (defect
  A) + resolving which root actually bit (datums 1–4), NOT a Step rewrite.
- #4 stale-flicker sibling: SAME root as the freshness source — the badge shows
  the true (stale) freshness; "flicker" is UI, not a controller counter reset.
- #2 bind-2nd-gateway-UI scope (Sites.tsx:491 single-bind assumption).
- Defect B (pinned-before-capable): fold now, or register as its own finding?
