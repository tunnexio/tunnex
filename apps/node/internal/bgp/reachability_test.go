package bgp

import (
	"net/netip"
	"strings"
	"testing"
)

func TestPhysicalExportReachability(t *testing.T) {
	baseLinks := `[{"ifname":"eth0","link_type":"ether","flags":["UP"],"linkinfo":{"info_kind":"veth"}}]`
	baseAddr := `[{"ifname":"eth0","addr_info":[{"local":"10.10.0.1","prefixlen":24}]}]`
	baseRoutes := `[{"dst":"10.10.0.0/24","dev":"eth0","protocol":"kernel","flags":[]}]`
	baseSelected := `[{"dev":"eth0","flags":[]}]`
	for _, tt := range []struct {
		name, links, addr, routes, selected string
		good                                bool
	}{
		{"connected", baseLinks, baseAddr, baseRoutes, baseSelected, true},
		// The generic process boundary deliberately stays strict. A managed
		// gateway must supply its independently qualified export proof instead.
		{"disjoint down bridge requires explicit proof", baseLinks, baseAddr, strings.TrimSuffix(baseRoutes, "]") + `,{"dst":"172.17.0.0/16","dev":"docker0","protocol":"kernel","scope":"link","prefsrc":"172.17.0.1","flags":["linkdown"]}]`, baseSelected, false},
		{"routed", baseLinks, `[{"ifname":"eth0","addr_info":[{"local":"172.30.88.2","prefixlen":24}]}]`, `[{"dst":"10.10.0.0/24","dev":"eth0","gateway":"172.30.88.1","protocol":"static","flags":[]}]`, `[{"dev":"eth0","gateway":"172.30.88.1","flags":[]}]`, true},
		{"linkdown", strings.Replace(baseLinks, `["UP"]`, `[]`, 1), baseAddr, baseRoutes, baseSelected, false},
		{"XFRM", strings.Replace(baseLinks, `"veth"`, `"xfrm"`, 1), baseAddr, baseRoutes, baseSelected, false},
		{"manual larger route", baseLinks, strings.Replace(baseAddr, `"prefixlen":24`, `"prefixlen":32`, 1), baseRoutes, baseSelected, false},
		{"malformed flags", baseLinks, baseAddr, strings.Replace(baseRoutes, `"flags":[]`, `"flags":"bad"`, 1), baseSelected, false},
		{"selected multipath", baseLinks, baseAddr, baseRoutes, `[{"dev":"eth0","multipath":[]}]`, false},
		{"FRR exportloop", baseLinks, baseAddr, strings.Replace(baseRoutes, `"kernel"`, `242`, 1), baseSelected, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			read := func(args ...string) ([]byte, error) {
				joined := strings.Join(args, " ")
				switch {
				case strings.Contains(joined, "link"):
					return []byte(tt.links), nil
				case strings.Contains(joined, "addr"):
					return []byte(tt.addr), nil
				case strings.Contains(joined, "route get"):
					return []byte(tt.selected), nil
				default:
					return []byte(tt.routes), nil
				}
			}
			e := probeLocalReachability([]netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")}, read)
			if (e == nil) != tt.good {
				t.Fatal("wrong export qualification", e)
			}
		})
	}
}
