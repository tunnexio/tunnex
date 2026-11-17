package ipsec

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

// Models the independently captured fresh AWS gateway's down default bridge.
// The bridge cannot prove local-prefix coverage or supply the VPN underlay.
func TestAWSEnvironmentDisjointDockerBridge(t *testing.T) {
	e := journalFixture()
	for i := range e.Engines {
		e.Engines[i].LocalPrefixes = []netip.Prefix{netip.MustParsePrefix("10.181.10.0/24")}
	}
	baseLinks := `[{"ifindex":2,"ifname":"ens5","link_type":"ether","mtu":1500,"flags":["UP"]},{"ifindex":3,"ifname":"docker0","link_type":"ether","mtu":1500,"flags":["NO-CARRIER","UP"],"operstate":"DOWN","linkinfo":{"info_kind":"bridge"}}]`
	baseRoutes := `[{"dst":"default","gateway":"10.181.10.1","dev":"ens5"},{"dst":"10.181.10.0/24","dev":"ens5","scope":"link"},{"dst":"172.17.0.0/16","dev":"docker0","protocol":"kernel","scope":"link","prefsrc":"172.17.0.1","flags":["linkdown"]}]`
	baseAddresses := `[{"ifname":"ens5","addr_info":[{"local":"10.181.10.10"}]},{"ifname":"docker0","addr_info":[{"local":"172.17.0.1"}]}]`
	links, routes, addresses := baseLinks, baseRoutes, baseAddresses
	inspector := &runtimeEnvironmentInspector{
		namespace: func() (string, error) { return e.Allocation.Namespace, nil },
		nft:       func(context.Context, ...string) ([]byte, error) { return []byte(`{"nftables":[]}`), nil },
		ip: func(_ context.Context, args ...string) ([]byte, error) {
			switch q := strings.Join(args, " "); q {
			case "-j -d link show":
				return []byte(links), nil
			case "-j -4 rule show":
				return []byte(`[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`), nil
			case "-j -4 route show table main":
				return []byte(routes), nil
			case "-j -4 address show":
				return []byte(addresses), nil
			default:
				if strings.HasPrefix(q, "-j -4 route get ") {
					return []byte(`[{"dst":"` + args[len(args)-1] + `","dev":"ens5","prefsrc":"10.181.10.10"}]`), nil
				}
				t.Fatalf("unexpected command %s", q)
				return nil, nil
			}
		},
	}
	got, err := inspector.Observe(context.Background(), e.Allocation, e.Engines)
	if err != nil || len(got.LocalIngressIndices) != 1 || got.LocalIngressIndices[0] != 2 || got.Underlays[0].InterfaceIndex != 2 {
		t.Fatal("disjoint Docker bridge prevents AWS environment qualification", err)
	}
	for name, mutate := range map[string]func(){
		"unknown flag":      func() { routes = strings.Replace(routes, `"linkdown"`, `"unknown"`, 1) },
		"nonbridge":         func() { links = strings.Replace(links, `"bridge"`, `"veth"`, 1) },
		"live bridge":       func() { links = strings.Replace(links, `"DOWN"`, `"UP"`, 1) },
		"unassigned source": func() { addresses = strings.Replace(addresses, "172.17.0.1", "172.17.0.2", 1) },
		"indirect bridge": func() {
			routes = strings.Replace(routes, `"dev":"docker0"`, `"dev":"docker0","gateway":"172.17.0.2"`, 1)
		},
		"local overlap": func() { routes = strings.Replace(routes, "172.17.0.0/16", "10.181.10.0/24", 1) },
		"remote overlap": func() {
			p := e.Engines[0].RemotePrefixes[0]
			routes = strings.Replace(strings.Replace(routes, "172.17.0.0/16", p.String(), 1), "172.17.0.1", p.Addr().Next().String(), 1)
			addresses = strings.Replace(addresses, "172.17.0.1", p.Addr().Next().String(), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			links, routes, addresses = baseLinks, baseRoutes, baseAddresses
			mutate()
			if _, err := inspector.Observe(context.Background(), e.Allocation, e.Engines); err == nil {
				t.Fatal("unsafe bridge environment accepted")
			}
		})
	}
}
