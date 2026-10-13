package ipsec

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

// Key-free Google DHCP shape read from the owned cloud gateway; I/O modeled.
func TestGCPEnvironmentExplicitRoutedLocalPrefix(t *testing.T) {
	for _, classic := range []bool{false, true} {
		t.Run(map[bool]string{false: "HA", true: "Classic"}[classic], func(t *testing.T) {
			m := gcpMaterialFixture()
			if classic {
				m = classicMaterialFixture()
			}
			e, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
			if err != nil {
				t.Fatal(err)
			}
			for i := range e.Engines[:e.Allocation.activeTunnelCount()] {
				e.Engines[i].LocalPrefixes = []netip.Prefix{netip.MustParsePrefix("10.70.0.0/24")}
			}
			routes := `[{"dst":"default","gateway":"10.70.0.1","dev":"ens4","protocol":"dhcp","prefsrc":"10.70.0.2","metric":100,"flags":[]},{"dst":"10.70.0.1","dev":"ens4","protocol":"dhcp","scope":"link","prefsrc":"10.70.0.2","metric":100,"flags":[]},{"dst":"169.254.169.254","gateway":"10.70.0.1","dev":"ens4","protocol":"dhcp","prefsrc":"10.70.0.2","metric":100,"flags":[]},{"dst":"172.17.0.0/16","dev":"docker0","protocol":"kernel","scope":"link","prefsrc":"172.17.0.1","flags":["linkdown"]}]`
			covering := `{"dst":"10.70.0.0/24","gateway":"10.70.0.1","dev":"ens4","protocol":"242","prefsrc":"10.70.0.2","metric":50000,"flags":[]}`
			original := routes
			var rows []json.RawMessage
			json.Unmarshal([]byte(routes), &rows)
			rows = append(rows, json.RawMessage(covering))
			raw, _ := json.Marshal(rows)
			routes = string(raw)
			address := `[{"ifname":"ens4","addr_info":[{"local":"10.70.0.2","prefixlen":32}]},{"ifname":"docker0","addr_info":[{"local":"172.17.0.1","prefixlen":16}]}]`
			inspector := &runtimeEnvironmentInspector{namespace: func() (string, error) { return e.Allocation.Namespace, nil }, nft: func(context.Context, ...string) ([]byte, error) { return []byte(`{"nftables":[]}`), nil }, ip: func(_ context.Context, args ...string) ([]byte, error) {
				switch q := strings.Join(args, " "); q {
				case "-j -d link show":
					return []byte(`[{"ifindex":2,"ifname":"ens4","link_type":"ether","mtu":1460,"flags":["UP"]},{"ifindex":3,"ifname":"docker0","link_type":"ether","mtu":1500,"flags":["NO-CARRIER","BROADCAST","MULTICAST","UP"],"operstate":"DOWN","linkinfo":{"info_kind":"bridge"}}]`), nil
				case "-j -4 rule show":
					return []byte(`[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`), nil
				case "-j -4 route show table main":
					return []byte(routes), nil
				case "-j -4 address show":
					return []byte(address), nil
				default:
					if strings.HasPrefix(q, "-j -4 route get ") {
						return []byte(`[{"dst":"` + args[len(args)-1] + `","dev":"ens4","prefsrc":"10.70.0.2"}]`), nil
					}
					t.Fatalf("unexpected %s", q)
					return nil, nil
				}
			}}
			got, err := inspector.Observe(context.Background(), e.Allocation, e.Engines)
			if err != nil || len(got.LocalIngressIndices) != 1 || got.LocalIngressIndices[0] != 2 || got.Underlays[0].OuterMTU != 1460 || got.Underlays[0].LocalAddress.String() != "10.70.0.2" {
				t.Fatal("explicit Google routed LAN rejected", err)
			}
			valid := routes
			// Host routes may appear before or after the exact covering route.
			var reverse []json.RawMessage
			json.Unmarshal([]byte(valid), &reverse)
			for i, j := 0, len(reverse)-1; i < j; i, j = i+1, j-1 {
				reverse[i], reverse[j] = reverse[j], reverse[i]
			}
			reordered, _ := json.Marshal(reverse)
			routes = string(reordered)
			if _, err := inspector.Observe(context.Background(), e.Allocation, e.Engines); err != nil {
				t.Fatal("route order changed exact proof", err)
			}
			routes = valid
			for name, bad := range map[string]string{
				"cover alone":              `[` + covering + `]`,
				"gateway host duplicate":   strings.TrimSuffix(valid, "]") + `,` + string(rows[1]) + `]`,
				"cover duplicate":          strings.TrimSuffix(valid, "]") + `,` + covering + `]`,
				"default only":             original,
				"gateway mismatch":         strings.Replace(valid, `"gateway":"10.70.0.1","dev":"ens4","protocol":"242"`, `"gateway":"10.70.0.3","dev":"ens4","protocol":"242"`, 1),
				"host wrong source":        strings.Replace(valid, `"scope":"link","prefsrc":"10.70.0.2"`, `"scope":"link","prefsrc":"10.70.0.3"`, 1),
				"host indirect":            strings.Replace(valid, `"scope":"link"`, `"scope":"global"`, 1),
				"host wrong device":        strings.Replace(valid, `"dst":"10.70.0.1","dev":"ens4"`, `"dst":"10.70.0.1","dev":"docker0"`, 1),
				"cover wrong source":       strings.Replace(valid, `"protocol":"242","prefsrc":"10.70.0.2"`, `"protocol":"242","prefsrc":"10.70.0.3"`, 1),
				"cover broad":              strings.Replace(valid, `"dst":"10.70.0.0/24"`, `"dst":"10.70.0.0/16"`, 1),
				"protected linkdown":       strings.Replace(valid, `"metric":50000,"flags":[]`, `"metric":50000,"flags":["linkdown"]`, 1),
				"malformed destination":    strings.Replace(valid, `"dst":"10.70.0.1"`, `"dst":"10.70.0.bad"`, 1),
				"gateway host via":         strings.Replace(valid, `"dst":"10.70.0.1","dev":"ens4"`, `"dst":"10.70.0.1","gateway":"10.70.0.9","dev":"ens4"`, 1),
				"cover multipath":          strings.Replace(valid, `"protocol":"242"`, `"multipath":[],"protocol":"242"`, 1),
				"cover encap":              strings.Replace(valid, `"protocol":"242"`, `"encap":{},"protocol":"242"`, 1),
				"cover missing source":     strings.Replace(valid, `"protocol":"242","prefsrc":"10.70.0.2"`, `"protocol":"242"`, 1),
				"bridge unknown flag":      strings.Replace(valid, `"flags":["linkdown"]`, `"flags":["unknown"]`, 1),
				"bridge unassigned source": strings.Replace(valid, `"prefsrc":"172.17.0.1"`, `"prefsrc":"172.17.0.9"`, 1),
				"bridge protected overlap": strings.Replace(valid, `"dst":"172.17.0.0/16"`, `"dst":"10.70.0.0/24"`, 1),
				"malformed source":         strings.Replace(valid, `"prefsrc":"172.17.0.1"`, `"prefsrc":"not-an-address"`, 1),
				"split prefix":             strings.TrimSuffix(valid, "]") + `,{"dst":"10.70.0.128/25","dev":"ens4","scope":"link","prefsrc":"10.70.0.2","flags":[]}]`,
				"split host":               strings.TrimSuffix(valid, "]") + `,{"dst":"10.70.0.3","dev":"ens4","scope":"link","prefsrc":"10.70.0.2","flags":[]}]`,
			} {
				t.Run(name, func(t *testing.T) {
					routes = bad
					if _, err := inspector.Observe(context.Background(), e.Allocation, e.Engines); err == nil {
						t.Fatal("unsafe routed LAN accepted")
					}
				})
			}
			routes = valid
			baseIP := inspector.ip
			for _, q := range []string{"-j -d link show", "-j -4 address show", "-j -4 route show table main"} {
				t.Run("drift "+q, func(t *testing.T) {
					reads := 0
					inspector.ip = func(ctx context.Context, args ...string) ([]byte, error) {
						raw, err := baseIP(ctx, args...)
						if strings.Join(args, " ") == q {
							reads++
							if reads > 1 {
								return []byte(`[]`), nil
							}
						}
						return raw, err
					}
					if _, err := inspector.Observe(context.Background(), e.Allocation, e.Engines); err == nil {
						t.Fatal("changed observation accepted")
					}
				})
			}
			for name, kind := range map[string]string{"live bridge": "bridge", "down physical": "physical", "policy routing": "policy"} {
				t.Run(name, func(t *testing.T) {
					inspector.ip = func(ctx context.Context, args ...string) ([]byte, error) {
						raw, err := baseIP(ctx, args...)
						q := strings.Join(args, " ")
						v := string(raw)
						if kind == "bridge" && q == "-j -d link show" {
							v = strings.Replace(v, `"operstate":"DOWN"`, `"operstate":"UP"`, 1)
						}
						if kind == "physical" && q == "-j -d link show" {
							v = strings.Replace(v, `"mtu":1460,"flags":["UP"]`, `"mtu":1460,"flags":[]`, 1)
						}
						if kind == "policy" && q == "-j -4 rule show" {
							v = `[{"priority":100,"src":"all","table":"100"}]`
						}
						return []byte(v), err
					}
					if _, err := inspector.Observe(context.Background(), e.Allocation, e.Engines); err == nil {
						t.Fatal("unsafe independent environment accepted")
					}
				})
			}
			inspector.ip = baseIP
			originalAddress := address
			remote := e.Engines[0].RemotePrefixes[0]
			remoteSource := remote.Addr().Next().String()
			routes = strings.Replace(strings.Replace(valid, "172.17.0.0/16", remote.String(), 1), "172.17.0.1", remoteSource, 1)
			address = strings.Replace(originalAddress, "172.17.0.1", remoteSource, 1)
			if _, err := inspector.Observe(context.Background(), e.Allocation, e.Engines); err == nil {
				t.Fatal("DOWN bridge overlapping protected remote prefix accepted")
			}
			address = originalAddress
			routes = valid
			saved := e
			e = journalFixture()
			for i := range e.Engines {
				e.Engines[i].LocalPrefixes = []netip.Prefix{netip.MustParsePrefix("10.70.0.0/24")}
			}
			if _, err := inspector.Observe(context.Background(), e.Allocation, e.Engines); err == nil {
				t.Fatal("AWS acquired GCP gateway exception")
			}
			routes = `[{"dst":"10.70.0.0/24","dev":"ens4","scope":"link","flags":[]}]`
			if _, err := inspector.Observe(context.Background(), e.Allocation, e.Engines); err != nil {
				t.Fatal("AWS direct connected prefix changed", err)
			}
			e = saved
			routes = valid
			address = strings.Replace(address, "10.70.0.2", "10.70.0.9", 1)
			if _, err := inspector.Observe(context.Background(), e.Allocation, e.Engines); err == nil {
				t.Fatal("unassigned source accepted")
			}
		})
	}
}
