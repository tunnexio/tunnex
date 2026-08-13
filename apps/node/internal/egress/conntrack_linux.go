//go:build linux

package egress

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	conntrack "github.com/florianl/go-conntrack"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// S8.7 Slice 2 — the expired/revoked-grant conntrack flush. Removing a grant's ACCEPT rule denies
// RE-establishment but does NOT kill an already-established flow: `ct established,related accept` honors an
// open flow indefinitely (a chatty sender refreshes its own conntrack entry). So when the applied Allow set
// LOSES an entry, the agent flushes the conntrack entries for that entry's EXACT tuple — via CT NETLINK, not
// a shelled `conntrack -D` (the gateway image has no conntrack-tools; a shelled flush would silently no-op —
// D4 ratified). THE SECURITY INVARIANT: the flush is scoped to the removed tuple and ONLY it. One predicate
// too wide tears down innocent neighbors — a self-inflicted outage on the busiest gateway. "Scoped" is
// proven by the neighbor's SURVIVAL, not the filter's appearance (the innocent-neighbor red).

// NOTE (S8.7b): the BOOT-TIME restart reconcile sweep (governedSpace / shouldReconcileFlush / reconcileFlush)
// was REMOVED after four defect rounds concentrated in it (the mode-boundary taxonomy — genuine-mesh vs
// cold-nil vs enforcing — is where every round tripped). Deferred to S8.7b as a decision-first story, its own
// state-model paper before any code. NAMED LIMITATION until then: a grant revoked/expired while a gateway's
// agent is DOWN leaves its already-established flows alive after agent restart, until the flow ends naturally.
// NEW connections are denied immediately; device revocation is unaffected (peer removal is crypto-death). The
// LIVE flush below (removedTuples → flushTuples, on a grant leaving the applied set while the agent is UP) is
// proven + founder-walked and stays.

// flowTuple is a removed grant's EXACT conntrack match spec. A conntrack entry is flushed iff its ORIGIN
// tuple falls inside src AND dst AND (proto unset or equal) AND (ports unset or in range) — never wider.
type flowTuple struct {
	src, dst netip.Prefix
	proto    uint8  // 0 = any L4 (the grant is protocol-agnostic — a site subnet)
	portLow  uint16 // 0 = any port (proto-any or an L3 grant)
	portHigh uint16
	ruleID   string // the revoked grant identity, stamped on the VerdictTerminated event
}

// tupleFromAllow builds the flush spec for a removed AllowEntry. ok=false for a malformed src/dst — NEVER
// flush on a tuple we can't parse (a wide/wrong match is worse than a missed flow).
func tupleFromAllow(e nodepolicy.AllowEntry) (flowTuple, bool) {
	src, ok := loosePrefix(e.SrcIP)
	if !ok {
		return flowTuple{}, false
	}
	dst, ok := loosePrefix(e.DstCIDR)
	if !ok {
		return flowTuple{}, false
	}
	t := flowTuple{src: src, dst: dst, ruleID: e.RuleID}
	switch e.Protocol {
	case "tcp":
		t.proto = 6
	case "udp":
		t.proto = 17
	} // "any" / "" → 0 (match every L4 for this src/dst)
	if e.PortLow > 0 {
		t.portLow, t.portHigh = uint16(e.PortLow), uint16(e.PortHigh)
	}
	return t, true
}

// loosePrefix parses a CIDR ("10.0.0.0/24") or a bare address ("10.99.0.10" → /32, v6 → /128). ok=false on
// garbage.
func loosePrefix(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// matchesTuple reports whether a conntrack entry's ORIGIN tuple falls inside the removed grant's spec — the
// scoped predicate. Every clause must hold; a nil field on the entry fails the match (never flush on missing
// data). This is THE innocent-neighbor guard: a flow with a different src, dst, proto, or dst-port survives.
func matchesTuple(c conntrack.Con, t flowTuple) bool {
	if c.Origin == nil || c.Origin.Src == nil || c.Origin.Dst == nil {
		return false
	}
	src, ok := netip.AddrFromSlice(*c.Origin.Src)
	if !ok {
		return false
	}
	dst, ok := netip.AddrFromSlice(*c.Origin.Dst)
	if !ok {
		return false
	}
	if !t.src.Contains(src.Unmap()) || !t.dst.Contains(dst.Unmap()) {
		return false
	}
	if t.proto != 0 {
		if c.Origin.Proto == nil || c.Origin.Proto.Number == nil || *c.Origin.Proto.Number != t.proto {
			return false
		}
	}
	if t.portHigh != 0 {
		if c.Origin.Proto == nil || c.Origin.Proto.DstPort == nil {
			return false
		}
		if dp := *c.Origin.Proto.DstPort; dp < t.portLow || dp > t.portHigh {
			return false
		}
	}
	return true
}

// sweepConntrack is THE ONE flush primitive: open a CT socket, dump each of `families`, and delete every flow
// `selector` picks — counting kills, SURFACING per-flow delete + per-family dump errors via errors.Join (never
// a silent skip that reports healthy, [7]), and a dump failure for ONE family never discards ANOTHER family's
// kills ([11]). flushTuples (the live removed-grant flush) is the sole caller after the boot restart-sweep was
// deferred to S8.7b; the primitive stays a single family-scoping/error surface. The selector returns
// (label, match): on a match the label (the revoked grant's rule id) is carried into the delete error so a
// failed teardown NAMES which grant's flow leaked (F6 — the abstraction must not drop the grant identity).
func sweepConntrack(ctx context.Context, families []conntrack.Family, selector func(conntrack.Con) (string, bool)) (int, error) {
	if len(families) == 0 {
		return 0, nil
	}
	nfct, err := conntrack.Open(&conntrack.Config{})
	if err != nil {
		return 0, fmt.Errorf("conntrack open (CAP_NET_ADMIN?): %w", err)
	}
	defer nfct.Close()
	killed := 0
	var errs []error
	for _, fam := range families {
		flows, derr := nfct.Dump(conntrack.Conntrack, fam)
		if derr != nil {
			errs = append(errs, fmt.Errorf("conntrack dump %v: %w", fam, derr)) // surfaced; other family's kills stand
			continue
		}
		for i := range flows {
			c := flows[i]
			// [4] disposition (ACCEPT the alloc): the label is built on match though only used on a delete
			// ERROR. A match happens ONLY for a flow we are about to delete — i.e. a removed-grant flow, a small
			// bounded set (not every dumped flow) — so the "rule <id>" concat is per-killed-flow, negligible. A
			// lazy thunk would cost a comparable closure alloc per match.
			label, ok := selector(c)
			if !ok {
				continue
			}
			if delErr := nfct.Delete(conntrack.Conntrack, fam, c); delErr != nil {
				errs = append(errs, fmt.Errorf("conntrack delete (%s): %w", label, delErr)) // [7]/F6: surfaced + NAMED
			} else {
				killed++
			}
		}
	}
	return killed, errors.Join(errs...)
}

// flushTuples deletes the conntrack entries matching ANY removed-grant tuple, scoped exactly — a selector over
// the ONE primitive (S8.7 Slice 2). Dumps only the families the tuples span ([11]/[17]). The matched tuple's
// rule id labels the delete error (F6).
func flushTuples(ctx context.Context, tuples []flowTuple) (int, error) {
	if len(tuples) == 0 {
		return 0, nil
	}
	return sweepConntrack(ctx, familiesOf(tuples), func(c conntrack.Con) (string, bool) {
		for _, t := range tuples {
			if matchesTuple(c, t) {
				return "rule " + t.ruleID, true
			}
		}
		return "", false
	})
}

// familiesOf returns the conntrack address families the removed tuples span (IPv4 and/or IPv6). The flush
// dumps ONLY these — never a family with no matching tuple ([17]), so a v6-less kernel is never touched for
// an all-v4 removal ([11]).
func familiesOf(tuples []flowTuple) []conntrack.Family {
	ps := make([]netip.Prefix, len(tuples))
	for i, t := range tuples {
		ps[i] = t.src
	}
	return familiesOfPrefixes(ps)
}

// familiesOfPrefixes returns the conntrack families a set of prefixes spans — the family-scoping helper
// familiesOf uses so the removed-tuple flush dumps ONLY the families its tuples span ([11]/[17]).
func familiesOfPrefixes(ps []netip.Prefix) []conntrack.Family {
	var v4, v6 bool
	for _, p := range ps {
		if a := p.Addr(); a.Is4() || a.Is4In6() {
			v4 = true
		} else {
			v6 = true
		}
	}
	out := make([]conntrack.Family, 0, 2)
	if v4 {
		out = append(out, conntrack.IPv4)
	}
	if v6 {
		out = append(out, conntrack.IPv6)
	}
	return out
}
