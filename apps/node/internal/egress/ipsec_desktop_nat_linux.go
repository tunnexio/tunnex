//go:build linux

package egress

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
)

func (m *Manager) SetIPsecDesktopNATSource(source *ipsec.DesktopNATSource) {
	m.desktopNAT.Store(source)
}

// Returning from this NAT chain preserves identity without accepting a packet
// in any forwarding chain. IPsec independently proves these exact tuples before
// admitting desktop traffic, and removes their authority on grant withdrawal.
func (m *Manager) desktopNATRules(subnet string) string {
	pool, err := netip.ParsePrefix(subnet)
	if err != nil || !pool.Addr().Is4() {
		return ""
	}
	var rules strings.Builder
	for _, exemption := range m.desktopNAT.Load().Snapshot() {
		if !pool.Contains(exemption.Source.Addr()) {
			continue
		}
		fmt.Fprintf(&rules, "    ip saddr %s ip daddr %s counter return comment \"tunnex_ipsec_desktop_no_snat\"\n", exemption.Source, exemption.Destination)
	}
	return rules.String()
}
