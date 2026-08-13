package devices

import (
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// RangesStale reports whether a STATIC profile's baked ranges snapshot differs from the org's CURRENT
// routed ranges — i.e. the exported profile is out of date and needs re-export (S9.1 Part-2 stale
// surface). Set comparison (order-independent): a subnet added or removed since export makes it stale.
// A nil/empty snapshot against non-empty current ranges is stale (the profile predates any route).
func RangesStale(snapshotJSON []byte, current []string) bool {
	var snap []string
	if len(snapshotJSON) > 0 {
		_ = json.Unmarshal(snapshotJSON, &snap)
	}
	if len(snap) != len(current) {
		return true
	}
	set := make(map[string]bool, len(snap))
	for _, s := range snap {
		set[s] = true
	}
	for _, c := range current {
		if !set[c] {
			return true
		}
	}
	return false
}

// ProfileStale reports whether a device's ISSUED CONFIG no longer matches reality — the one question
// `needs_reexport` answers, now with two causes rather than one (S13.1 Slice 6).
//
// TWO CAUSES, AND A FUTURE THIRD SHOULD ARRIVE HERE DELIBERATELY:
//
//  1. ROUTES — the baked site ranges no longer match the org's current routed ranges. STATIC ONLY: a managed
//     (desktop-client) device polls routes, so nothing baked can go stale.
//  2. ADDRESS — the tunnel address in the issued config is not the device's current address. EVERY MODE: every
//     config embeds an interface address, so a managed device is just as broken by a change, and recording the
//     snapshot only for static exports is what left those users to discover it by failing to connect.
//
// The operator-facing meaning is unchanged and cause-neutral — "your config is out of date, re-import it" — which
// is why one field with a widened cause set beats a second boolean on a mirror surface. That choice, and this
// sentence, exist because two findings this epic (WF-S11-7, WF-S11-10c) were surfaces added without censusing
// their consumers.
//
// UNKNOWN IS NOT STALE. An absent snapshot (a row predating its column) reports false: claiming staleness on absent
// evidence is the mirror of missing it, and a permanent false positive on a healthy fleet is what the 0055 ruling
// spent a condition avoiding.
func ProfileStale(mode string, snapshotJSON []byte, currentRanges []string, provisionedIP, assignedIP *string,
	provisionedNode pgtype.UUID, currentNode uuid.UUID, currentNodeSelfHoming bool) bool {
	// ⛔ CAUSE 3, MANAGED HALF (S12.12 D7) — THE RESIDUAL THE COMMENT BELOW REGISTERED, NOW REACHABLE.
	//
	// The static-only boundary was drawn on the claim that "a MANAGED device polls the dial channel and
	// re-homes itself". That is true ONLY when its node is a hub-set member: activeHubDialFrom returns
	// derived=false otherwise and the client KEEPS ITS BAKED ENDPOINT, so a managed device on a non-member
	// gateway it was not provisioned against dials a gateway that will not serve it.
	//
	// It was registered rather than fixed because the only way to re-home a managed device was the operator
	// restore of a revoked gateway's devices — rare, deliberate, already a re-issue event. S12.12 adds
	// TRANSFER, which makes re-homing a routine act an operator performs before retiring any gateway. A
	// residual is acceptable while the path that reaches it is rare; it stops being acceptable the moment a
	// button creates it.
	//
	// ⚠ AND IT IS STILL NOT UNCONDITIONAL, because that is what the original comment warned against: a
	// managed device on a self-homing gateway reports FRESH, since it genuinely heals on the next poll.
	// Reporting every re-homed managed device stale would be the permanent false positive the
	// unknown-is-not-stale rule exists to avoid, in the other direction.
	if mode != "static" && provisionedNode.Valid && uuid.UUID(provisionedNode.Bytes) != currentNode &&
		!currentNodeSelfHoming {
		return true
	}
	if mode == "static" {
		if RangesStale(snapshotJSON, currentRanges) {
			return true
		}
		// CAUSE 3 — THE GATEWAY (F3, review fold). Every issued config bakes a specific gateway's `Endpoint` and
		// `PublicKey` (devices/config.go), so a device re-homed onto a different gateway — which is exactly what
		// the operator restore does, because a revoked gateway never returns — holds a config naming something
		// that will never serve it. Before this, needs_reexport compared the address and the routes and NOT the
		// gateway, so such a device rendered perfectly fresh while being unusable.
		//
		// STATIC ONLY, and the boundary is a real one rather than caution: a static export is a file that never
		// polls, so nothing can re-point it. A MANAGED device polls the dial channel and re-homes itself on the
		// next poll — but ONLY when its node is a hub-set member (nodes.NodeDial returns derived=false otherwise,
		// and the client keeps its baked endpoint). So managed devices on a non-hub-set target are NOT covered
		// here, and that residual is registered rather than papered over: reporting them stale unconditionally
		// would be a PERMANENT false positive for every managed device that self-heals, which is the failure mode
		// the unknown-is-not-stale rule exists to avoid.
		if provisionedNode.Valid && uuid.UUID(provisionedNode.Bytes) != currentNode {
			return true
		}
	}
	if provisionedIP == nil || assignedIP == nil {
		return false // nothing recorded, or no address assigned — unknown, not stale
	}
	return *provisionedIP != *assignedIP
}
