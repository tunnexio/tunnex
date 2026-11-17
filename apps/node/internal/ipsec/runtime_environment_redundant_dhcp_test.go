package ipsec

import (
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// Captured 2026-10-21 gateway main IPv4 routes. No cloud or network mutation.
const capturedOfficeDNSRoutes = `[{"dst":"default","gateway":"10.181.10.1","dev":"ens5","protocol":"dhcp","prefsrc":"10.181.10.10","metric":100,"flags":[]},{"dst":"10.99.0.0/24","dev":"wg0","protocol":"kernel","scope":"link","prefsrc":"10.99.0.1","flags":[]},{"dst":"10.181.10.0/24","dev":"ens5","protocol":"kernel","scope":"link","prefsrc":"10.181.10.10","metric":100,"flags":[]},{"dst":"10.181.10.1","dev":"ens5","protocol":"dhcp","scope":"link","prefsrc":"10.181.10.10","metric":100,"flags":[]},{"dst":"10.181.10.20","dev":"ens5","protocol":"dhcp","scope":"link","prefsrc":"10.181.10.10","metric":100,"flags":[]},{"dst":"10.182.0.0/16","dev":"tx9c1effaca1e5","protocol":"242","scope":"link","metric":50001,"flags":[]},{"dst":"169.254.137.9","dev":"tx9c1effaca1e5","protocol":"242","scope":"link","metric":50001,"flags":[]},{"dst":"169.254.162.253","dev":"tx9d3b806c1286","protocol":"242","scope":"link","metric":50002,"flags":[]},{"dst":"172.17.0.0/16","dev":"docker0","protocol":"kernel","scope":"link","prefsrc":"172.17.0.1","flags":["linkdown"]}]`
const capturedOfficeDNSHostRemoved = `[{"dst":"default","gateway":"10.181.10.1","dev":"ens5","protocol":"dhcp","prefsrc":"10.181.10.10","metric":100,"flags":[]},{"dst":"10.99.0.0/24","dev":"wg0","protocol":"kernel","scope":"link","prefsrc":"10.99.0.1","flags":[]},{"dst":"10.181.10.0/24","dev":"ens5","protocol":"kernel","scope":"link","prefsrc":"10.181.10.10","metric":100,"flags":[]},{"dst":"10.181.10.1","dev":"ens5","protocol":"dhcp","scope":"link","prefsrc":"10.181.10.10","metric":100,"flags":[]},{"dst":"10.182.0.0/16","dev":"tx9c1effaca1e5","protocol":"242","scope":"link","metric":50001,"flags":[]},{"dst":"169.254.137.9","dev":"tx9c1effaca1e5","protocol":"242","scope":"link","metric":50001,"flags":[]},{"dst":"169.254.162.253","dev":"tx9d3b806c1286","protocol":"242","scope":"link","metric":50002,"flags":[]},{"dst":"172.17.0.0/16","dev":"docker0","protocol":"kernel","scope":"link","prefsrc":"172.17.0.1","flags":["linkdown"]}]`
const capturedOfficeDNSRollbackRoutes = `[{"dst":"default","gateway":"10.181.10.1","dev":"ens5","protocol":"dhcp","prefsrc":"10.181.10.10","metric":100,"flags":[]},{"dst":"10.99.0.0/24","dev":"wg0","protocol":"kernel","scope":"link","prefsrc":"10.99.0.1","flags":[]},{"dst":"10.181.0.2","gateway":"10.181.10.1","dev":"ens5","protocol":"dhcp","prefsrc":"10.181.10.10","metric":100,"flags":[]},{"dst":"10.181.10.0/24","dev":"ens5","protocol":"kernel","scope":"link","prefsrc":"10.181.10.10","metric":100,"flags":[]},{"dst":"10.181.10.1","dev":"ens5","protocol":"dhcp","scope":"link","prefsrc":"10.181.10.10","metric":100,"flags":[]},{"dst":"10.182.0.0/16","dev":"tx9c1effaca1e5","protocol":"242","scope":"link","metric":50001,"flags":[]},{"dst":"169.254.137.9","dev":"tx9c1effaca1e5","protocol":"242","scope":"link","metric":50001,"flags":[]},{"dst":"169.254.162.253","dev":"tx9d3b806c1286","protocol":"242","scope":"link","metric":50002,"flags":[]},{"dst":"172.17.0.0/16","dev":"docker0","protocol":"kernel","scope":"link","prefsrc":"172.17.0.1","flags":["linkdown"]}]`

func TestCapturedOfficeDNSHostRouteQualification(t *testing.T) {
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
			var expected RuntimeEnvironment
			verify := func(t *testing.T) {
				t.Helper()
				routeReads = 0
				got, err := observe(context.Background(), e.Allocation, e.Engines)
				if err != nil || len(got.LocalIngressIndices) != 1 || got.LocalIngressIndices[0] != 2 || got.Underlays[0].InterfaceIndex != 2 || got.Underlays[0].LocalAddress.String() != "10.181.10.10" || got.Underlays[0].OuterMTU != 9001 {
					t.Fatal("captured AWS connected DHCP environment refused", err)
				}
				if expected.Namespace == "" {
					expected = got
				} else if !reflect.DeepEqual(expected, got) {
					t.Fatal("redundant DHCP host changed qualified environment")
				}
			}
			for _, tc := range []struct{ name, rows string }{
				{"counterfactual_only_DNS_host_removed", capturedOfficeDNSHostRemoved},
				{"captured_during_DHCP_office_DNS", capturedOfficeDNSRoutes},
				{"captured_after_original_DHCP_restored", capturedOfficeDNSRollbackRoutes},
			} {
				t.Run(tc.name, func(t *testing.T) {
					routes = tc.rows
					verify(t)
				})
			}

			encode := func(rows []map[string]json.RawMessage) string {
				t.Helper()
				raw, err := json.Marshal(rows)
				if err != nil {
					t.Fatal(err)
				}
				return string(raw)
			}
			fresh := func() []map[string]json.RawMessage {
				t.Helper()
				var rows []map[string]json.RawMessage
				if err := json.Unmarshal([]byte(capturedOfficeDNSRoutes), &rows); err != nil {
					t.Fatal(err)
				}
				return rows
			}
			rows := fresh()
			for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
				rows[i], rows[j] = rows[j], rows[i]
			}
			routes = encode(rows)
			t.Run("route_order_does_not_change_coverage", verify)
			routes = strings.Replace(capturedOfficeDNSRoutes, `"dst":"10.181.10.20"`, `"dst":"10.181.10.20/32"`, 1)
			t.Run("explicit_host_prefix", verify)
			deny := func(t *testing.T) {
				t.Helper()
				routeReads = 0
				if _, err := observe(context.Background(), e.Allocation, e.Engines); err == nil {
					t.Fatal("unsafe redundant DHCP route qualified")
				}
			}
			for _, index := range []int{0, 2, 3, 4} {
				for _, change := range []struct{ field, value string }{
					{"dev", `"ens6"`}, {"prefsrc", `"10.181.10.11"`}, {"prefsrc", `null`},
					{"protocol", `"static"`}, {"scope", `"host"`}, {"scope", `null`},
					{"flags", `["onlink"]`}, {"flags", `["linkdown"]`}, {"type", `"blackhole"`},
					{"encap", `{}`}, {"encap_type", `"ip"`}, {"multipath", `[]`}, {"nexthops", `[]`}, {"nhid", `10`},
				} {
					t.Run([]string{"default", "", "cover", "gateway_anchor", "DNS_host"}[index]+"_"+change.field+"_"+change.value, func(t *testing.T) {
						rows := fresh()
						rows[index][change.field] = json.RawMessage(change.value)
						routes = encode(rows)
						// Even another valid assigned physical source cannot replace the anchor tuple.
						linkRows = strings.TrimSuffix(links, "]") + `,{"ifindex":5,"ifname":"ens6","flags":["UP"],"mtu":9001,"link_type":"ether"}]`
						addresses = strings.TrimSuffix(baseAddresses, "]") + `,{"ifname":"ens6","addr_info":[{"local":"10.181.10.10"},{"local":"10.181.10.11"}]}]`
						deny(t)
						linkRows, addresses = links, baseAddresses
					})
				}
			}
			for name, mutate := range map[string]func([]map[string]json.RawMessage) []map[string]json.RawMessage{
				"missing_default":          func(r []map[string]json.RawMessage) []map[string]json.RawMessage { return r[1:] },
				"missing_cover":            func(r []map[string]json.RawMessage) []map[string]json.RawMessage { return append(r[:2], r[3:]...) },
				"missing_gateway_anchor":   func(r []map[string]json.RawMessage) []map[string]json.RawMessage { return append(r[:3], r[4:]...) },
				"duplicate_default":        func(r []map[string]json.RawMessage) []map[string]json.RawMessage { return append(r, r[0]) },
				"duplicate_cover":          func(r []map[string]json.RawMessage) []map[string]json.RawMessage { return append(r, r[2]) },
				"duplicate_gateway_anchor": func(r []map[string]json.RawMessage) []map[string]json.RawMessage { return append(r, r[3]) },
				"duplicate_DNS_host":       func(r []map[string]json.RawMessage) []map[string]json.RawMessage { return append(r, r[4]) },
				"DNS_host_via": func(r []map[string]json.RawMessage) []map[string]json.RawMessage {
					r[4]["gateway"] = json.RawMessage(`"10.181.10.1"`)
					return r
				},
				"gateway_anchor_via": func(r []map[string]json.RawMessage) []map[string]json.RawMessage {
					r[3]["gateway"] = json.RawMessage(`"10.181.10.2"`)
					return r
				},
				"cover_via": func(r []map[string]json.RawMessage) []map[string]json.RawMessage {
					r[2]["gateway"] = json.RawMessage(`"10.181.10.1"`)
					return r
				},
				"default_gateway_mismatch": func(r []map[string]json.RawMessage) []map[string]json.RawMessage {
					r[0]["gateway"] = json.RawMessage(`"10.181.10.2"`)
					return r
				},
				"DNS_host_is_assigned_source": func(r []map[string]json.RawMessage) []map[string]json.RawMessage {
					r[4]["dst"] = json.RawMessage(`"10.181.10.10"`)
					return r
				},
				"DNS_host_is_subnet": func(r []map[string]json.RawMessage) []map[string]json.RawMessage {
					r[4]["dst"] = json.RawMessage(`"10.181.10.0/25"`)
					return r
				},
				"cover_too_broad": func(r []map[string]json.RawMessage) []map[string]json.RawMessage {
					r[2]["dst"] = json.RawMessage(`"10.181.0.0/16"`)
					return r
				},
				"cover_too_narrow": func(r []map[string]json.RawMessage) []map[string]json.RawMessage {
					r[2]["dst"] = json.RawMessage(`"10.181.10.0/25"`)
					return r
				},
			} {
				t.Run(name, func(t *testing.T) { routes = encode(mutate(fresh())); deny(t) })
			}
			routes = capturedOfficeDNSRoutes
			for _, field := range []string{"metric", "dev", "prefsrc", "dst"} {
				t.Run("snapshot_drift_"+field, func(t *testing.T) {
					rows := fresh()
					rows[4][field] = json.RawMessage(map[string]string{"metric": "101", "dev": `"ens6"`, "prefsrc": `"10.181.10.11"`, "dst": `"10.181.10.21"`}[field])
					secondRoutes = encode(rows)
					deny(t)
					secondRoutes = ""
				})
			}
			t.Run("no_coverage_invention", func(t *testing.T) {
				for i := range e.Engines {
					e.Engines[i].LocalPrefixes = []netip.Prefix{netip.MustParsePrefix("10.181.0.0/16")}
				}
				deny(t)
				for i := range e.Engines {
					e.Engines[i].LocalPrefixes = []netip.Prefix{netip.MustParsePrefix("10.181.10.0/24")}
				}
			})
			t.Run("remote_overlap_cannot_use_exception", func(t *testing.T) {
				for i := range e.Engines {
					e.Engines[i].RemotePrefixes = []netip.Prefix{netip.MustParsePrefix("10.181.10.20/32")}
				}
				deny(t)
			})
		})
	}
}
