package ipsec

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// guardTunnelMTUs binds current MTU only to independently observed healthy
// permit/reply indices. A known-down peer needs no MTU or new authority.
func (c *RuntimeController) guardTunnelMTUs(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment, indices ...[]int) ([]GuardTunnelMTU, error) {
	if c.kernel == nil {
		return nil, ErrRuntimeController
	}
	var routes []RuntimeBGPRouteTuple
	if e.ContractVersion == 3 {
		routes = bgpRouteUnion(e.BGPRoutes)
	}
	snap, err := c.kernel.snapshotSelectionRoutes(ctx, e.Allocation, true, routes)
	if err != nil {
		return nil, ErrRuntimeController
	}
	wanted := map[int]bool{}
	for _, list := range indices {
		for _, index := range list {
			if index <= 0 {
				return nil, ErrRuntimeController
			}
			wanted[index] = true
		}
	}
	var result []GuardTunnelMTU
	for i, owned := range snap.ownership {
		if !wanted[owned.InterfaceIndex] {
			continue
		}
		ceiling, qualified := runtimeProfileInnerMTU(e.Allocation.ProfileID, env.Underlays[i].OuterMTU)
		if !qualified || owned != e.Observed[i] || !snap.up[i] || snap.mtu[i] < 68 || snap.mtu[i] > uint64(ceiling) {
			return nil, ErrRuntimeController
		}
		result = append(result, GuardTunnelMTU{InterfaceIndex: owned.InterfaceIndex, MTU: uint16(snap.mtu[i])})
		delete(wanted, owned.InterfaceIndex)
	}
	if len(wanted) > 0 {
		return nil, ErrRuntimeController
	}
	sort.Slice(result, func(i, j int) bool { return result[i].InterfaceIndex < result[j].InterfaceIndex })
	return result, nil
}

// Reuse the full permit predicate, but never its verdict. SYN and SYN/ACK
// options are reduced only when larger than the observed tunnel IPv4 ceiling.
// This is TCP-only; it grants no traffic and does not implement PMTUD.
func guardMSSRule(r guardRule, mtus []GuardTunnelMTU) (guardRule, bool) {
	if !r.tcp || len(r.expr) < 2 {
		return guardRule{}, false
	}
	ceiling := uint16(0)
	for _, m := range mtus {
		if m.InterfaceIndex == r.ingress || m.InterfaceIndex == r.egress {
			value := m.MTU - 40
			if ceiling == 0 || value < ceiling {
				ceiling = value
			}
		}
	}
	if ceiling == 0 {
		return guardRule{}, false
	}
	prefix := strings.TrimSuffix(r.text, "counter accept\n")
	if prefix == r.text {
		return guardRule{}, false
	}
	flags := guardPayload("tcp", "flags")
	option := map[string]any{"tcp option": map[string]any{"name": "maxseg", "field": "size"}}
	expr := append([]any(nil), r.expr[:len(r.expr)-2]...)
	expr = append(expr, guardMatch("==", map[string]any{"&": []any{flags, map[string]any{"|": []any{"syn", "rst"}}}}, "syn"), guardMatch(">", option, ceiling), map[string]any{"mangle": map[string]any{"key": option, "value": ceiling}}, guardCounter())
	return guardRule{text: prefix + fmt.Sprintf("tcp flags & (syn | rst) == syn tcp option maxseg size > %d tcp option maxseg size set %d counter\n", ceiling, ceiling), expr: expr}, true
}
