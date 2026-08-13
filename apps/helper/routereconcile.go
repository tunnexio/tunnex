package helper

import (
	"strings"
)

// The ONE OS-route reconciler (S8.5 story-end REDUCE — findings #1/#3/#4/#8/#9/#10). Both backends' route
// convergence — Up's baked routes AND SetAllowedIPs' pushed ranges — flow through this single function with
// the per-target route call INJECTED (the NRPT cmdRunner-seam pattern applied to routes), so the reconcile
// LOGIC is red-able on any platform and the platform binding (darwin `route` CLI / windows winipcfg) is a
// thin adapter. This kills the drift that produced three defects: `Up` already delete-before-added its
// endpoint route ("so the re-add can't fail File exists") but the reconcile path forgot the same lesson.
//
// The `applied` map is a per-session BELIEF CACHE (never persisted) of the route-targets we believe are in
// the kernel. It is NOT kernel truth — the kernel can lose a route the map believes applied (sleep/wake,
// interface events, a manual `route delete`). The drift is bounded by a healing triad, all structural (no
// kernel-query, no periodic resync): (a) session lifecycle heals it — Up re-applies baked routes and the
// per-session monitor recreation re-applies pushed ranges on reconnect, and the interface events likeliest
// to strip routes are the ones that bounce the session; (b) a failed op INVALIDATES that route's belief
// (below), so the next reconcile re-attempts from delete-before-add; (c) Down clears the map entirely. The
// residual drift window is "mid-session, kernel-only route loss with no interface event" — rare and
// self-healing on the next change/reconnect (accepted residue, S8.5 decisions).

// routeCmd is the per-target route seam: add==true installs the route, add==false deletes it. Targets are
// canonical route-target strings (the same form routeSet produces + the compare uses — the /32-print class
// pre-killed), so a map key and a cmd argument are the same string.
type routeCmd func(add bool, target string) error

// reconcileRoutes drives `applied` to `want` via cmd. Semantics (each kills a review finding):
//   - delete-STALE-FIRST: the crypto layer (replace_allowed_ips) already dropped a de-advertised range, so
//     the OS layer must not lag it — remove applied-not-wanted before adding, best-effort, belief cleared
//     regardless (#4).
//   - DELETE-BEFORE-ADD per route: a pre-existing/stale route (a home-LAN collision, or a belief the kernel
//     lost) never fails "File exists" because we delete first (#3) — this is the Up:endpoint discipline,
//     now shared.
//   - PER-ROUTE ADVANCE, NO EARLY RETURN: each add that succeeds marks its belief; an add that FAILS clears
//     (never sets) its belief and is collected, but the sweep CONTINUES — so a transient failure on one
//     route never re-wedges another, and the next reconcile re-attempts only the failed ones (#1).
//   - PARTIAL FAILURE REPORTED with the failing targets NAMED (the health surface already carries
//     allowed_ips_apply_failed — it gains specificity, not spam).
func reconcileRoutes(applied map[string]bool, want map[string]bool, cmd routeCmd) error {
	// Delete stale FIRST (best-effort — the route may already be gone; belief cleared regardless).
	for _, t := range sortedKeys(applied) {
		if want[t] {
			continue
		}
		_ = cmd(false, t)
		delete(applied, t)
	}
	// Add missing with delete-before-add per route; per-route advance; sweep continues past a failed add.
	var failed []string
	for _, t := range sortedKeys(want) {
		if applied[t] {
			continue
		}
		_ = cmd(false, t) // delete-before-add: clear any pre-existing/stale route so the add can't fail "exists"
		if err := cmd(true, t); err != nil {
			delete(applied, t) // belief NOT set → the next reconcile re-attempts this route
			failed = append(failed, t)
			continue
		}
		applied[t] = true // per-route advance
	}
	if len(failed) > 0 {
		return &ProtocolError{Code: "allowed_ips_apply_failed", Msg: "route add failed for: " + strings.Join(failed, ", ")}
	}
	return nil
}
