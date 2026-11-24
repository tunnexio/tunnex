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
	if m.kubernetesMode.Load() {
		m.withholdDesktopNAT(rules.String())
		return ""
	}
	return rules.String()
}

// withholdDesktopNAT is K8N-5 item 4, (b). IPsec cannot run on an in-cluster gateway: its guard table
// (inet tunnex_ipsec) hooks postrouting, and the host-network proof refuses every postrouting hook it
// does not know. An exemption rendered there could never serve a working tunnel, and the same proof
// would refuse the exemption itself, which is fatal at startup. It is withheld: the IPsec runtime sees
// the exemption as pending, so its Apply fails closed and its maintenance pass keeps the desktop grant
// pending. The reason is logged once per change of the withheld set.
func (m *Manager) withholdDesktopNAT(withheld string) {
	if previous := m.desktopNATWithheld.Swap(&withheld); previous != nil && *previous == withheld {
		return
	}
	if withheld == "" || m.log == nil {
		return
	}
	m.log.Warn("k8s_ipsec_desktop_nat_withheld",
		"exemptions", strings.Count(withheld, "\n"),
		"reason", "IPsec is not supported on an in-cluster gateway: its guard hooks are refused by the host network proof")
}
