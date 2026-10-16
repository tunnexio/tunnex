package ipsec

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

// The complete route list is the key-free 2026-10-16 AWS Ubuntu capture. Its
// DHCP gateway /32 supplements the connected /24; it does not replace it.
const awsConnectedGatewayRoutes = `[{"dst":"default","gateway":"10.181.10.1","dev":"ens5","protocol":"dhcp","prefsrc":"10.181.10.10","metric":100,"flags":[]},{"dst":"10.99.0.0/24","dev":"wg0","protocol":"kernel","scope":"link","prefsrc":"10.99.0.1","flags":[]},{"dst":"10.181.0.2","gateway":"10.181.10.1","dev":"ens5","protocol":"dhcp","prefsrc":"10.181.10.10","metric":100,"flags":[]},{"dst":"10.181.10.0/24","dev":"ens5","protocol":"kernel","scope":"link","prefsrc":"10.181.10.10","metric":100,"flags":[]},{"dst":"10.181.10.1","dev":"ens5","protocol":"dhcp","scope":"link","prefsrc":"10.181.10.10","metric":100,"flags":[]},{"dst":"169.254.169.123","gateway":"10.181.10.1","dev":"ens5","protocol":"dhcp","prefsrc":"10.181.10.10","metric":100,"flags":[]},{"dst":"172.17.0.0/16","dev":"docker0","protocol":"kernel","scope":"link","prefsrc":"172.17.0.1","flags":["linkdown"]}]`

func TestAWSEnvironmentConnectedDHCPGatewayHost(t *testing.T) {
	for _, bgp := range []bool{false, true} {
		t.Run(map[bool]string{false: "static", true: "BGP"}[bgp], func(t *testing.T) {
			e := journalFixture()
			if bgp {
				m := bgpMaterialFixture()
				var err error
				e, _, err = runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
				if err != nil {
					t.Fatal(err)
				}
			}
			for i := range e.Engines {
				e.Engines[i].LocalPrefixes = []netip.Prefix{netip.MustParsePrefix("10.181.10.0/24")}
				e.Engines[i].RemotePrefixes = []netip.Prefix{netip.MustParsePrefix("10.182.0.0/16")}
			}
			const links = `[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536,"link_type":"loopback"},{"ifindex":2,"ifname":"ens5","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":9001,"operstate":"UP","link_type":"ether"},{"ifindex":3,"ifname":"docker0","flags":["NO-CARRIER","BROADCAST","MULTICAST","UP"],"mtu":1500,"operstate":"DOWN","link_type":"ether","linkinfo":{"info_kind":"bridge"}},{"ifindex":4,"ifname":"wg0","flags":["POINTOPOINT","NOARP","UP","LOWER_UP"],"mtu":1420,"link_type":"none","linkinfo":{"info_kind":"wireguard"}}]`
			const baseAddresses = `[{"ifindex":1,"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host","valid_life_time":4294967295,"preferred_life_time":4294967295}]},{"ifindex":2,"ifname":"ens5","addr_info":[{"family":"inet","local":"10.181.10.10","prefixlen":24,"scope":"global","dynamic":true,"valid_life_time":1869,"preferred_life_time":1869}]},{"ifindex":3,"ifname":"docker0","addr_info":[{"family":"inet","local":"172.17.0.1","prefixlen":16,"scope":"global","valid_life_time":4294967295,"preferred_life_time":4294967295}]},{"ifindex":4,"ifname":"wg0","addr_info":[{"family":"inet","local":"10.99.0.1","prefixlen":24,"scope":"global","valid_life_time":4294967295,"preferred_life_time":4294967295}]}]`
			routes, addresses := awsConnectedGatewayRoutes, baseAddresses
			linkRows := links
			routeReads := 0
			secondRoutes := ""
			inspector := &runtimeEnvironmentInspector{
				namespace: func() (string, error) { return e.Allocation.Namespace, nil },
				nft:       func(context.Context, ...string) ([]byte, error) { return []byte(`{"nftables":[]}`), nil },
				ip: func(_ context.Context, args ...string) ([]byte, error) {
					switch q := strings.Join(args, " "); q {
					case "-j -d link show":
						return []byte(linkRows), nil
					case "-j -4 rule show":
						return []byte(`[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`), nil
					case "-j -4 route show table main":
						routeReads++
						if routeReads == 2 && secondRoutes != "" {
							return []byte(secondRoutes), nil
						}
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
			observe := inspector.Observe
			if bgp {
				observe = inspector.ObserveLocalExports
			}
			verify := func(t *testing.T) {
				t.Helper()
				routeReads = 0
				got, err := observe(context.Background(), e.Allocation, e.Engines)
				if err != nil || len(got.LocalIngressIndices) != 1 || got.LocalIngressIndices[0] != 2 || got.Underlays[0].InterfaceIndex != 2 || got.Underlays[0].LocalAddress.String() != "10.181.10.10" || got.Underlays[0].OuterMTU != 9001 {
					t.Fatal("captured AWS connected DHCP environment refused", err)
				}
			}
			verify(t)
			var original []map[string]json.RawMessage
			if err := json.Unmarshal([]byte(awsConnectedGatewayRoutes), &original); err != nil {
				t.Fatal(err)
			}
			encode := func(rows []map[string]json.RawMessage) string {
				t.Helper()
				raw, err := json.Marshal(rows)
				if err != nil {
					t.Fatal(err)
				}
				return string(raw)
			}
			for i, j := 0, len(original)-1; i < j; i, j = i+1, j-1 {
				original[i], original[j] = original[j], original[i]
			}
			routes = encode(original)
			verify(t)
			routes = strings.Replace(awsConnectedGatewayRoutes, `"dst":"10.181.10.1"`, `"dst":"10.181.10.1/32"`, 1)
			verify(t)
			for _, index := range []int{0, 3, 4} {
				for _, change := range []struct{ field, value string }{
					{"dev", `"ens6"`}, {"prefsrc", `"10.181.10.11"`}, {"prefsrc", `null`},
					{"protocol", `"static"`}, {"scope", `"host"`}, {"scope", `null`}, {"flags", `["linkdown"]`},
					{"encap", `{}`}, {"multipath", `[]`}, {"nhid", `10`},
				} {
					t.Run([]string{"default", "", "", "cover", "host"}[index]+"_"+change.field+"_"+change.value, func(t *testing.T) {
						var rows []map[string]json.RawMessage
						json.Unmarshal([]byte(awsConnectedGatewayRoutes), &rows)
						rows[index][change.field] = json.RawMessage(change.value)
						routes = encode(rows)
						// A second valid physical interface/source cannot substitute for the matched tuple.
						linkRows = strings.TrimSuffix(links, "]") + `,{"ifindex":5,"ifname":"ens6","flags":["UP"],"mtu":9001,"link_type":"ether"}]`
						addresses = strings.TrimSuffix(baseAddresses, "]") + `,{"ifname":"ens6","addr_info":[{"local":"10.181.10.10"},{"local":"10.181.10.11"}]}]`
						if _, err := observe(context.Background(), e.Allocation, e.Engines); err == nil {
							t.Fatal("changed DHCP gateway tuple accepted")
						}
						linkRows, addresses = links, baseAddresses
					})
				}
			}
			for name, mutate := range map[string]func([]map[string]json.RawMessage) []map[string]json.RawMessage{
				"missing cover":     func(r []map[string]json.RawMessage) []map[string]json.RawMessage { return append(r[:3], r[4:]...) },
				"missing default":   func(r []map[string]json.RawMessage) []map[string]json.RawMessage { return r[1:] },
				"duplicate cover":   func(r []map[string]json.RawMessage) []map[string]json.RawMessage { return append(r, r[3]) },
				"duplicate default": func(r []map[string]json.RawMessage) []map[string]json.RawMessage { return append(r, r[0]) },
				"duplicate host":    func(r []map[string]json.RawMessage) []map[string]json.RawMessage { return append(r, r[4]) },
				"arbitrary host": func(r []map[string]json.RawMessage) []map[string]json.RawMessage {
					r[4]["dst"] = json.RawMessage(`"10.181.10.12"`)
					return r
				},
				"split prefix": func(r []map[string]json.RawMessage) []map[string]json.RawMessage {
					r[4]["dst"] = json.RawMessage(`"10.181.10.0/25"`)
					return r
				},
				"gateway mismatch": func(r []map[string]json.RawMessage) []map[string]json.RawMessage {
					r[0]["gateway"] = json.RawMessage(`"10.181.10.2"`)
					return r
				},
				"cover via": func(r []map[string]json.RawMessage) []map[string]json.RawMessage {
					r[3]["gateway"] = json.RawMessage(`"10.181.10.1"`)
					return r
				},
				"host via": func(r []map[string]json.RawMessage) []map[string]json.RawMessage {
					r[4]["gateway"] = json.RawMessage(`"10.181.10.2"`)
					return r
				},
				"cover broad": func(r []map[string]json.RawMessage) []map[string]json.RawMessage {
					r[3]["dst"] = json.RawMessage(`"10.181.0.0/16"`)
					return r
				},
				"unassigned source": func(r []map[string]json.RawMessage) []map[string]json.RawMessage {
					for _, i := range []int{0, 3, 4} {
						r[i]["prefsrc"] = json.RawMessage(`"10.181.10.11"`)
					}
					return r
				},
				"gateway is own source": func(r []map[string]json.RawMessage) []map[string]json.RawMessage {
					r[0]["gateway"] = json.RawMessage(`"10.181.10.10"`)
					r[4]["dst"] = json.RawMessage(`"10.181.10.10"`)
					return r
				},
			} {
				t.Run(name, func(t *testing.T) {
					var rows []map[string]json.RawMessage
					json.Unmarshal([]byte(awsConnectedGatewayRoutes), &rows)
					routes = encode(mutate(rows))
					if _, err := observe(context.Background(), e.Allocation, e.Engines); err == nil {
						t.Fatal("unsafe gateway host or missing prefix coverage accepted")
					}
				})
			}
			routes = awsConnectedGatewayRoutes
			t.Run("route snapshot changes", func(t *testing.T) {
				routeReads = 0
				secondRoutes = strings.Replace(routes, `"metric":100`, `"metric":101`, 1)
				if _, err := observe(context.Background(), e.Allocation, e.Engines); err == nil {
					t.Fatal("changing DHCP route snapshot accepted")
				}
				secondRoutes = ""
			})
			t.Run("subnet cannot prove whole VPC", func(t *testing.T) {
				for i := range e.Engines {
					e.Engines[i].LocalPrefixes = []netip.Prefix{netip.MustParsePrefix("10.181.0.0/16")}
				}
				if _, err := observe(context.Background(), e.Allocation, e.Engines); err == nil {
					t.Fatal("connected /24 admitted as approved /16")
				}
			})
		})
	}
}
