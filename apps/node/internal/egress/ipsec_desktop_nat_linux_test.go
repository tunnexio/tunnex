//go:build linux

package egress

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
)

func TestDesktopNoSNATIsExactBeforeMasqueradeAndWithdraws(t *testing.T) {
	m := New("wg0")
	baseline := m.rulesetWith("10.99.0.0/24", nil)
	source := &ipsec.DesktopNATSource{}
	m.SetIPsecDesktopNATSource(source)
	id := uuid.New()
	source.Set(id, []ipsec.DesktopNATExemption{
		{Source: netip.MustParsePrefix("10.99.0.2/32"), Destination: netip.MustParsePrefix("10.180.0.0/16")},
		{Source: netip.MustParsePrefix("192.168.1.35/32"), Destination: netip.MustParsePrefix("10.180.0.0/16")},
	})
	rules := m.rulesetWith("10.99.0.0/24", nil)
	exact := "ip saddr 10.99.0.2/32 ip daddr 10.180.0.0/16 counter return comment \"tunnex_ipsec_desktop_no_snat\""
	i, j := strings.Index(rules, exact), strings.Index(rules, "ip saddr 10.99.0.0/24 oifname != \"wg0\" masquerade")
	if i < 0 || j <= i || strings.Contains(rules, "192.168.1.35") {
		t.Fatalf("invalid scoped NAT order:\n%s", rules)
	}
	if strings.Count(rules, "tunnex_ipsec_desktop_no_snat") != 1 {
		t.Fatal("broader exemption rendered")
	}
	source.Set(id, nil)
	if got := m.rulesetWith("10.99.0.0/24", nil); got != baseline {
		t.Fatal("withdrawal did not restore unchanged baseline")
	}
}
