package helper

import "net/netip"

// physicalDefaultRoute is the platform-neutral information needed to select the
// physical egress path that must carry a WireGuard endpoint under full tunnel.
// Windows supplies EffectiveMetric as route metric plus interface metric.
type physicalDefaultRoute struct {
	EffectiveMetric uint64
	LUID            uint64
	NextHop         netip.Addr
	Up              bool
}

// selectPhysicalDefaultRoute chooses the lowest effective-metric operational
// route. Equal metrics keep the table's original order, matching OS tie-breaking
// as closely as possible without fabricating a secondary preference.
func selectPhysicalDefaultRoute(routes []physicalDefaultRoute) (physicalDefaultRoute, bool) {
	var selected physicalDefaultRoute
	found := false
	for _, route := range routes {
		if !route.Up {
			continue
		}
		if !found || route.EffectiveMetric < selected.EffectiveMetric {
			selected, found = route, true
		}
	}
	return selected, found
}
