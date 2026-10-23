package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestEnvironmentSecondSnapshotDiagnosticLeaves(t *testing.T) {
	raw, err := os.ReadFile("testdata/runtime-environment-iproute2-6.9.0.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ NFT json.RawMessage }
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("fixture")
	}
	const rules = `[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`
	const links = `[{"ifindex":2,"ifname":"eth0","link_type":"ether","mtu":1500,"flags":["UP"]},{"ifindex":3,"ifname":"lan0","link_type":"ether","mtu":1500,"flags":["UP"]}]`
	const routes = `[{"dst":"10.10.0.0/16","dev":"lan0","protocol":"kernel","scope":"link","prefsrc":"10.10.0.1","metric":100}]`
	const addresses = `[{"ifname":"eth0","addr_info":[{"local":"172.18.0.2","prefixlen":24}]},{"ifname":"lan0","addr_info":[{"local":"10.10.0.1","prefixlen":16}]}]`
	for _, tc := range []struct {
		name, want string
		changes    []string
	}{
		{"success", "env_complete", nil},
		{"snapshot-read", "env_snapshot_after", []string{"read"}},
		{"snapshot-nft-read", "env_snapshot_after", []string{"nft-read"}},
		{"snapshot-census", "env_snapshot_after", []string{"nft-census"}},
		{"links", "env_links_after", []string{"links"}},
		{"rules", "env_rules_after", []string{"rules"}},
		{"routes", "env_routes_after", []string{"routes"}},
		{"addresses", "env_addresses_after", []string{"addresses"}},
		{"peer-one", "env_peer_routes_after", []string{"peer-one"}},
		{"peer-two", "env_peer_routes_after", []string{"peer-two"}},
		{"local-exports", "env_local_exports_after", []string{"exports"}},
		{"links-first", "env_links_after", []string{"links", "rules", "routes", "addresses", "peer-one", "exports"}},
		{"rules-before-routes", "env_rules_after", []string{"rules", "routes", "addresses", "peer-one", "exports"}},
		{"routes-before-addresses", "env_routes_after", []string{"routes", "addresses", "peer-one", "exports"}},
		{"addresses-before-peers", "env_addresses_after", []string{"addresses", "peer-one", "exports"}},
		{"peers-before-exports", "env_peer_routes_after", []string{"peer-one", "exports"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changes := map[string]bool{}
			for _, v := range tc.changes {
				changes[v] = true
			}
			var prior RuntimeEnvironment
			var priorErr error
			var priorReads map[string]int
			for _, enabled := range []bool{false, true} {
				e := journalFixture()
				for i := range e.Engines {
					e.Engines[i].LocalPrefixes = []netip.Prefix{netip.MustParsePrefix("10.10.0.0/16")}
					e.Engines[i].RemoteAddress = netip.MustParseAddr([]string{"192.0.2.2", "192.0.2.3"}[i])
				}
				var mu sync.Mutex
				reads := map[string]int{}
				count := func(k string) int { mu.Lock(); defer mu.Unlock(); reads[k]++; return reads[k] }
				events := []RuntimeDiagnostic{}
				r := &runtimeEnvironmentInspector{
					namespace: func() (string, error) { count("namespace"); return e.Allocation.Namespace, nil },
					nft: func(context.Context, ...string) ([]byte, error) {
						if count("nft") == 2 {
							if changes["nft-read"] {
								return nil, errors.New("synthetic-private-nft-error")
							}
							if changes["nft-census"] {
								return []byte(`{"nftables":[{"unknown":"synthetic-private-nft-body"}]}`), nil
							}
						}
						return fixture.NFT, nil
					},
					ip: func(_ context.Context, a ...string) ([]byte, error) {
						q := strings.Join(a, " ")
						second := count(q) == 2
						var value, kind, from, to string
						switch q {
						case "-j -4 rule show":
							if second && changes["read"] {
								return nil, errors.New("synthetic-private-ip-error")
							}
							value, kind, from, to = rules, "rules", `"priority":0`, `"priority":1`
						case "-j -d link show":
							value, kind, from, to = links, "links", `"mtu":1500`, `"mtu":1400`
						case "-j -4 route show table main":
							value, kind, from, to = routes, "routes", `"metric":100`, `"metric":200`
						case "-j -4 address show":
							value, kind, from, to = addresses, "addresses", `10.10.0.1`, `10.10.0.2`
						case "-j -4 route get 10.10.0.0":
							value, kind, from, to = `[{"dst":"10.10.0.0","dev":"lan0","prefsrc":"10.10.0.1"}]`, "exports", `lan0`, `lan1`
						case "-j -4 route get 192.0.2.2":
							value, kind, from, to = `[{"dst":"192.0.2.2","dev":"eth0","prefsrc":"172.18.0.2"}]`, "peer-one", `172.18.0.2`, `172.18.0.3`
						case "-j -4 route get 192.0.2.3":
							value, kind, from, to = `[{"dst":"192.0.2.3","dev":"eth0","prefsrc":"172.18.0.2"}]`, "peer-two", `172.18.0.2`, `172.18.0.3`
						default:
							return nil, errors.New("unexpected fixture command")
						}
						if second && changes[kind] {
							value = strings.Replace(value, from, to, 1)
						}
						return []byte(value), nil
					},
				}
				if enabled {
					r.diagnostic = func(d RuntimeDiagnostic) { events = append(events, d) }
				}
				got, gotErr := r.observeQualified(context.Background(), e.Allocation, e.Engines, nil, func(context.Context, string, ...string) ([]byte, error) {
					t.Fatal("unexpected hook command")
					return nil, nil
				}, true)
				if !enabled {
					prior, priorErr, priorReads = got, gotErr, reads
					continue
				}
				if !reflect.DeepEqual(got, prior) || gotErr != priorErr {
					t.Fatal("diagnostics changed result or refusal")
				}
				readFailure := changes["read"] || changes["nft-read"] || changes["nft-census"]
				if !readFailure && !reflect.DeepEqual(reads, priorReads) {
					t.Fatal("diagnostics changed reads", reads, priorReads)
				}
				for command, n := range reads {
					if n > 2 {
						t.Fatal("added native read", command, n)
					}
				}
				if len(events) != 1 || events[0].Operation != "environment_observe" || events[0].ConnectionID != e.Allocation.ConnectionID || events[0].Stage != tc.want {
					t.Fatal("wrong closed diagnostic", events)
				}
				if tc.name == "success" {
					if gotErr != nil || events[0].Refused {
						t.Fatal("success changed", gotErr)
					}
				} else if gotErr != ErrRuntimeEnvironment || !events[0].Refused || !reflect.DeepEqual(got, RuntimeEnvironment{}) {
					t.Fatal("refusal weakened", gotErr)
				}
				encoded, _ := json.Marshal(events)
				if strings.Contains(string(encoded), "synthetic-private") {
					t.Fatal("private diagnostic body")
				}
			}
		})
	}
}

func TestEnvironmentLocalExportDiagnosticIsClosed(t *testing.T) {
	if !validRuntimeDiagnostic("environment_observe", "env_local_exports_after") || validRuntimeDiagnostic("heartbeat", "env_local_exports_after") || validRuntimeDiagnostic("environment_observe", "env_local_exports_after_private") {
		t.Fatal("local export diagnostic vocabulary is not closed")
	}
}
