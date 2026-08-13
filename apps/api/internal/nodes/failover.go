package nodes

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// S8.6 Slice 4 — the failover trigger. ONE CP-side ticker → ONE method → read freshness → update counts →
// derive the ACTIVE order → if it differs from the persisted set, that is a PROMOTION EVENT (persist, bump
// the generation, audit) which the ORDINARY compile+push carries. No failover-special messages, no new
// push path, no measuring (the tick READS node_peer_status freshness, the substrate stores). Fail-back is
// the SAME event in the other direction (a membership-order change back toward the configured intent).

const (
	// FailoverTickInterval is the CP tick cadence (rides the accesslog-sweep goroutine pattern).
	FailoverTickInterval = 30 * time.Second
	// failoverDemoteTicks (N) — consecutive stale ticks before a member is PROMOTED-PAST (fail-over FAST).
	failoverDemoteTicks = 3
	// failoverRestoreTicks (M > N) — consecutive fresh ticks (the hold window) before a demoted member is
	// RESTORED (fail-back SLOW). The asymmetry lives entirely in N vs M.
	failoverRestoreTicks = 5
	// failoverStaleWindow — an OBSERVED handshake older than this marks a member STALE for THIS tick (N such
	// ticks demote it). DERIVED FROM THE WIREGUARD PROTOCOL CADENCE, deliberately NOT a round guess (the
	// narrowing-was-incidental lesson — the next reader must know why it is NOT 90s):
	//
	//   WireGuard renews a peer's handshake on the REKEY_AFTER_TIME (120s) / REJECT_AFTER_TIME (180s) cycle, so
	//   a LIVING but idle-ish link's last-handshake age legitimately sawtooths up to ~180s before a rekey
	//   resets it. The box-walk observed HEALTHY steady-state ages of 1:29–3:22 (up to 202s) against the OLD
	//   90s window — which marked living hubs dead every cycle (the #4 false-stale badge; the consecutive-stale
	//   counter kept resetting on the rekey, so a real death fired erratically / not at all). The window MUST
	//   clear WG's rekey ceiling plus report+tick slack: 180s (REJECT_AFTER_TIME) + one ~30s agent report
	//   interval + tick jitter, rounded up ABOVE the observed 202s healthy ceiling → 240s. N=3 ticks of
	//   hysteresis (90s) confirm on top, so a DEAD member (frozen handshake, no rekey possible) still demotes
	//   in bounded time while a living sawtooth never does.
	//
	// RELATIONSHIP TO apps/node reconcile.siteLinkStaleWindow (180s): NOT one shared constant — deliberately
	// distinct, across the api↔node module boundary, tracking the SAME protocol cadence but tuned in OPPOSITE
	// error directions. The agent's 180s drives an over-report-safe HEALTH BADGE (a false site_link_down is a
	// mere annoyance). This 240s drives an under-report-safe DEMOTION (a false demotion CHURNS the org's
	// transit hub — the costlier error), so it sits ABOVE the agent's badge window by design. If WG's cadence
	// ever changes, BOTH move; these paired comments are the cross-reference so neither drifts silently.
	failoverStaleWindow = 240 * time.Second
)

// The hub-set audit actions (S8.6 REDUCE #2, landing a — NAMED constants via the standard audit() path, the
// closest to "typed" available since the product has no audit-action registry; a real typed registry + lint
// is deferred to its own story). The promotion/failback kinds are the record of ACTIVE-ORDER transitions
// specifically (condition 1b); the membership kind is a CONFIGURED change (bind/unbind/pin), DISTINCT from a
// failover so an operator reading the log never confuses "I rebound a gateway" with "my primary went stale".
const (
	auditHubPromotion  = "hub_set.promotion"  // the controller DEMOTED a member (active-order transition, a loss)
	auditHubFailback   = "hub_set.failback"   // the controller RESTORED a member (active-order transition, recovery)
	auditHubMembership = "hub_set.membership" // ReconcileHubSet changed the CONFIGURED membership (not a failover)
)

// FailoverController holds ONE org's in-memory hysteresis state: per-member consecutive stale/fresh tick
// counts + the demoted set. RESTART CONTRACT (S8.6 #1 — both halves): the COUNTERS are not persisted — a
// mid-window restart restarts them (delays a failover by ≤N ticks, NEVER causes a spurious one — the
// conservative stance). But the DEMOTION SET is REHYDRATED from the persisted `demoted` field on the
// controller's first post-restart use (seedDemoted), so an in-flight demotion SURVIVES restart — a
// still-stale primary is never spuriously restored. Counters conservative, demotion state durable.
type FailoverController struct {
	n, m    int
	stale   map[uuid.UUID]int
	fresh   map[uuid.UUID]int
	demoted map[uuid.UUID]bool
	seeded  bool // rehydrated from the persisted demoted set yet? (first-tick-post-restart guard)
}

// NewFailoverController builds a controller with the ruled thresholds (N=3 demote, M=5 restore).
func NewFailoverController() *FailoverController {
	return &FailoverController{
		n: failoverDemoteTicks, m: failoverRestoreTicks,
		stale: map[uuid.UUID]int{}, fresh: map[uuid.UUID]int{}, demoted: map[uuid.UUID]bool{},
	}
}

// seedDemoted rehydrates the demotion SET from the persisted `demoted` field on the controller's FIRST use
// after a CP restart (S8.6 #1) — the demotion survives restart, so a still-stale primary is NOT spuriously
// restored on the first tick. The hysteresis COUNTERS stay zero (conservative — a fresh member still needs M
// ticks to restore, a stale one N to (re-)demote); only the demotion STATE is rehydrated.
func (fc *FailoverController) seedDemoted(persisted []uuid.UUID) {
	if fc.seeded {
		return
	}
	fc.seeded = true
	for _, id := range persisted {
		fc.demoted[id] = true
	}
}

// Step advances ONE tick and returns the DEMOTED set (in configured order) — the members currently
// promoted-past for staleness. It updates the hysteresis counts from `freshness` (N consecutive stale →
// demote; M consecutive fresh → restore), then collects the demoted members. The ACTIVE order is NOT
// computed here: deriveActive(configured, demoted) is the ONE shared derivation every consumer applies (the
// REDUCE). Returning the demoted SET — not the active order — is what makes the controller a single-field
// writer: it persists ONLY `demoted`. Convergence: when NOTHING is demoted, deriveActive returns the
// configured order unchanged — fail-back IS that convergence.
func (fc *FailoverController) Step(configured []uuid.UUID, freshness map[uuid.UUID]bool) []uuid.UUID {
	for _, id := range configured {
		v, observed := freshness[id]
		if !observed {
			// NO VERDICT this tick — no living observer reported a VALID handshake for this member (no spoke
			// peers it, or only NULL/never-handshaked entries exist). D1: liveness is testimony from the living;
			// with no witness there is no ruling, so HOLD the hysteresis counters (neither demote nor restore on
			// absence). A member is demoted ONLY on a PRESENT-but-STALE observation, never on silence — this is
			// the no-spokes edge + the NULL-handshake row, both handled here by construction.
			continue
		}
		if v {
			fc.fresh[id]++
			fc.stale[id] = 0
			if fc.demoted[id] && fc.fresh[id] >= fc.m {
				fc.demoted[id] = false // fail-back: M consecutive fresh (the hold window) restores it
			}
		} else {
			fc.stale[id]++
			fc.fresh[id] = 0
			if fc.stale[id] >= fc.n {
				fc.demoted[id] = true // promote-past: N consecutive stale
			}
		}
	}
	demoted := make([]uuid.UUID, 0)
	for _, id := range configured {
		if fc.demoted[id] {
			demoted = append(demoted, id)
		}
	}
	return demoted
}

func (s *Service) failoverFor(orgID uuid.UUID) *FailoverController {
	s.failoverMu.Lock()
	defer s.failoverMu.Unlock()
	fc := s.failovers[orgID]
	if fc == nil {
		fc = NewFailoverController()
		s.failovers[orgID] = fc
	}
	return fc
}

// sameOrder reports whether two member lists are element-wise identical (order matters — a reorder IS a
// promotion event).
func sameOrder(a, b []uuid.UUID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// RunFailoverTick is the ticker's method: for every org with a multi-member hub set, advance one failover
// tick. One org's error is logged and skipped — a single org must not stall the fleet.
func (s *Service) RunFailoverTick(ctx context.Context) error {
	orgs, err := s.q.ListFailoverOrgs(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	var errs []error
	for _, orgID := range orgs {
		if err := s.failoverOrg(ctx, orgID, now); err != nil {
			// Defect A: a per-org failure is logged at ERROR (a silently-failing failover controller is the
			// box-walk's finding-(b) made permanent) AND surfaced up the return — the fleet still completes
			// EVERY org (one org must not stall the others), but the caller SEES the failures instead of a
			// swallowed nil.
			slog.ErrorContext(ctx, "failover_org_failed", "org_id", orgID.String(), "error", err.Error())
			errs = append(errs, fmt.Errorf("org %s: %w", orgID, err))
		}
	}
	return errors.Join(errs...)
}

// failoverOrg advances one org's tick — the ONE loop that owns the whole hub-set reconciliation (S8.6 #4/#5
// REDUCE — the tick re-derives configured, carries demoted, derives active):
//   - CONFIGURED CORRECTOR: re-derive the configured membership from the LIVE election (electSiteHubSet)
//     every pass. This closes the four shadows of the deleted self-heal: every removal path (unbind, revoke,
//     DeleteSite) is covered here BY CONSTRUCTION — a departed gateway drops from the live election, so the
//     tick rewrites configured + audits the membership change within one tick; the event-triggers become
//     belt-and-suspenders latency optimizations. The tick is configured's SECOND writer alongside
//     ReconcileHubSet; legal under the writer-ownership law because BOTH write electSiteHubSet's output — one
//     pure function, convergent by construction (a racing stale write self-heals the next tick).
//   - DEMOTED (hysteresis): rehydrate the demotion set on the first post-restart tick (#1), advance the
//     counts, collect the demoted set.
//
// Both fields persist via their own per-field atomic upsert (writer partition preserved) IN ONE TX with their
// audits (#5 — an audit failure rolls the whole tick back; the next tick retries). Idempotent: a stable world
// changes neither field → zero writes, no generation churn.
func (s *Service) failoverOrg(ctx context.Context, orgID uuid.UUID, now time.Time) error {
	current, err := s.GetHubSet(ctx, orgID)
	if err != nil {
		return err
	}
	// ONE gateway read (no double GetOrgHubSet, no wasted subnet/dns load — #8). The live election needs only
	// the gateways; a minimal topology carries them into electSiteHubSet.
	gws, err := s.q.ListSiteGatewaysForOrg(ctx, orgID)
	if err != nil {
		return err
	}
	liveRows := electSiteHubSet(siteTopology{gws: gws}, now)
	configured := make([]uuid.UUID, len(liveRows))
	pubkey := make(map[uuid.UUID]string, len(liveRows))
	for i := range liveRows {
		configured[i] = liveRows[i].ID
		pubkey[liveRows[i].ID] = liveRows[i].WgPublicKey
	}

	fc := s.failoverFor(orgID)
	fc.seedDemoted(current.Demoted) // rehydrate the demotion set (#1) BEFORE the first Step
	// ⛔ EMPTY, NOT NIL — AND THIS IS A PERMANENT-WEDGE FIX, NOT A STYLE CHOICE.
	//
	// `org_hub_set.demoted` is NOT NULL. A nil slice reaches pgx as SQL NULL, so the write below fails with
	// 23502. The branch that assigns this variable is guarded by `len(configured) >= 2`, which means:
	//
	//   AN ORG THAT HAS A DEMOTED MEMBER AND THEN DROPS BELOW TWO CONFIGURED HUBS CAN NEVER CLEAR IT.
	//   `demotedChanged` is true (nil != {member}), the UPDATE sends NULL, the tick fails, and it fails
	//   again on EVERY subsequent tick — the failover controller is wedged until a human edits the row.
	//
	// Dropping below two hubs is exactly when a fleet is already degraded, so the controller stops working
	// at the moment it is most needed, and says so only in a log nobody is tailing.
	//
	// Found on 2026-08-02 by seeding a demotion and watching the CP log: 42 consecutive failed ticks.
	demoted := []uuid.UUID{}
	var freshness map[uuid.UUID]bool
	var ages map[uuid.UUID]time.Duration
	if len(configured) >= 2 { // a single/zero-hub set has nothing to demote (configured still heals below)
		rows, err := s.q.ListNodePeerStatusForOrg(ctx, orgID)
		if err != nil {
			return err
		}
		// WF-B D-WFB-1: THE ONE liveness derivation (shared pure function). The controller reads .Fresh
		// for its Step; the site-link health surface reads the SAME function's output for the badge — no
		// second freshness computation exists (the grep-red). A member with no living witness (!Observed)
		// is absent from `freshness` → Step HOLDS (no verdict on silence).
		liveness := deriveMemberLiveness(configured, pubkey, rows, current.Demoted, now)
		freshness = make(map[uuid.UUID]bool, len(configured))
		ages = make(map[uuid.UUID]time.Duration, len(configured))
		for _, id := range configured {
			if ml := liveness[id]; ml.Observed {
				freshness[id] = ml.Fresh
				ages[id] = ml.Age
			}
		}
		demoted = fc.Step(configured, freshness)
	}

	configuredChanged := !sameOrder(configured, current.Configured)
	demotedChanged := !sameOrder(demoted, current.Demoted)
	// #7: the transition KIND is derived per-member (added = newly demoted, restored = came out of demotion
	// AND still configured), not a len() heuristic — a simultaneous demote+restore audits BOTH.
	added, removed := diffSets(current.Demoted, demoted)
	inConfigured := make(map[uuid.UUID]bool, len(configured))
	for _, id := range configured {
		inConfigured[id] = true
	}
	var restored []uuid.UUID
	for _, id := range removed {
		if inConfigured[id] { // a removed-from-demoted member that LEFT configured is a membership event, not a failback
			restored = append(restored, id)
		}
	}
	// Observability (defect A): emit ONE structured line per multi-member org per tick — BEFORE any early
	// return — so the failover loop's rulings are ALWAYS visible in CP logs (the box-walk paid five blind
	// minutes for an invisible controller). A single/zero-hub org has no failover to narrate.
	if len(configured) >= 2 {
		logFailoverTick(ctx, orgID, configured, freshness, ages, fc, added, restored)
	}
	if !configuredChanged && !demotedChanged {
		return nil // stable world → zero writes, no generation churn
	}
	oldActive := deriveActive(current.Configured, current.Demoted)
	newActive := deriveActive(configured, demoted)
	return s.withTx(ctx, func(q *sqlc.Queries) error {
		if configuredChanged {
			row, err := q.UpsertOrgHubSetConfigured(ctx, sqlc.UpsertOrgHubSetConfiguredParams{OrgID: orgID, Configured: configured})
			if err != nil {
				return err
			}
			if err := audit(ctx, q, orgID, nil, auditHubMembership, "org", orgID.String(), map[string]any{
				"configured": idsToStrings(configured), "generation": row.Generation, "cause": "failover_corrector",
			}); err != nil {
				return err
			}
		}
		if demotedChanged {
			row, err := q.UpsertOrgHubSetDemoted(ctx, sqlc.UpsertOrgHubSetDemotedParams{OrgID: orgID, Demoted: demoted})
			if err != nil {
				return err
			}
			if len(added) > 0 {
				if err := audit(ctx, q, orgID, nil, auditHubPromotion, "org", orgID.String(), map[string]any{
					"demoted": idsToStrings(added), "old_primary": primaryOf(oldActive), "new_primary": primaryOf(newActive),
					"generation": row.Generation, "condition": "primary_stale",
				}); err != nil {
					return err
				}
			}
			if len(restored) > 0 {
				if err := audit(ctx, q, orgID, nil, auditHubFailback, "org", orgID.String(), map[string]any{
					"restored": idsToStrings(restored), "old_primary": primaryOf(oldActive), "new_primary": primaryOf(newActive),
					"generation": row.Generation, "condition": "recovered",
				}); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// diffSets returns (added, removed): members in b but not a (added, in b order), and in a but not b (removed,
// in a order).
func diffSets(a, b []uuid.UUID) (added, removed []uuid.UUID) {
	inA := make(map[uuid.UUID]bool, len(a))
	for _, id := range a {
		inA[id] = true
	}
	inB := make(map[uuid.UUID]bool, len(b))
	for _, id := range b {
		inB[id] = true
	}
	for _, id := range b {
		if !inA[id] {
			added = append(added, id)
		}
	}
	for _, id := range a {
		if !inB[id] {
			removed = append(removed, id)
		}
	}
	return
}

// primaryOf is the head node-id of an ordered hub set as a string ("" when empty) — the audit's old/new
// primary field.
func primaryOf(order []uuid.UUID) string {
	if len(order) == 0 {
		return ""
	}
	return order[0].String()
}

// logFailoverTick emits ONE structured line per multi-member org per tick — the failover loop's decisions made
// VISIBLE. A controller whose rulings are invisible is unfalsifiable; the Deck-B box-walk paid five blind
// minutes for exactly that. Chosen at Info as ONE compact line per HA org (multi-member sets are rare, so it
// will not drown ops) OVER per-member Debug, precisely so the rematch can confirm the ticker is live and read
// WHY it fired-or-not from CP logs at the DEFAULT level, BEFORE the kill. Diagnosis machinery for a live
// decision loop — NOT dormant lifecycle code, so the dormant-machinery law does not bite. Per member: the
// observed handshake age (or "none" = no living witness), the fresh/stale/no-observation verdict, the
// consecutive counters, and the demoted flag; plus the tick's decision (none / demote+restore ids).
func logFailoverTick(ctx context.Context, orgID uuid.UUID, configured []uuid.UUID, freshness map[uuid.UUID]bool, ages map[uuid.UUID]time.Duration, fc *FailoverController, added, restored []uuid.UUID) {
	detail := make([]string, 0, len(configured))
	for _, id := range configured {
		verdict, age := "no-observation", "none"
		if a, ok := ages[id]; ok {
			age = a.Round(time.Second).String()
			if freshness[id] {
				verdict = "fresh"
			} else {
				verdict = "stale"
			}
		}
		detail = append(detail, fmt.Sprintf("%s age=%s %s stale_n=%d fresh_n=%d demoted=%t",
			id.String(), age, verdict, fc.stale[id], fc.fresh[id], fc.demoted[id]))
	}
	decision := "none"
	if len(added) > 0 || len(restored) > 0 {
		decision = fmt.Sprintf("demote=%v restore=%v", idsToStrings(added), idsToStrings(restored))
	}
	slog.InfoContext(ctx, "failover_tick",
		slog.String("org_id", orgID.String()),
		slog.Int("members", len(configured)),
		slog.String("decision", decision),
		slog.Any("detail", detail),
	)
}
