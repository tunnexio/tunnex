package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// Captured from the AWS gateway on 2026-10-23. Only lease countdown values
// below are synthetic: they force a complete observation across renewal.
func awsDHCPRenewalFixture(t *testing.T, lifetime int) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/actual_aws_dhcp_address.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if json.Unmarshal(raw, &rows) != nil || len(rows) != 1 {
		t.Fatal("address fixture")
	}
	addresses := rows[0]["addr_info"].([]any)
	if len(addresses) != 1 {
		t.Fatal("address fixture count")
	}
	a := addresses[0].(map[string]any)
	a["valid_life_time"], a["preferred_life_time"] = lifetime, lifetime
	out, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRuntimeAddressBracketQualifiedDHCPRenewal(t *testing.T) {
	before, after := awsDHCPRenewalFixture(t, 1800), awsDHCPRenewalFixture(t, 3600)
	if bytes.Equal(before, after) || !runtimeAddressBracket(before, after, 320*time.Millisecond) {
		t.Fatal("otherwise identical positive finite dynamic IPv4 renewal refused")
	}
}

func TestRuntimeEnvironmentCompleteQualifiedDHCPRenewal(t *testing.T) {
	before, after := awsDHCPRenewalFixture(t, 1800), awsDHCPRenewalFixture(t, 3600)
	var baseline RuntimeEnvironment
	for _, mode := range []string{"stable", "renewal", "assigned_source_drift"} {
		t.Run(mode, func(t *testing.T) {
			e := journalFixture()
			for i := range e.Engines {
				e.Engines[i].LocalPrefixes = []netip.Prefix{netip.MustParsePrefix("10.181.10.0/24")}
			}
			var mu sync.Mutex
			calls := 0
			var events []RuntimeDiagnostic
			r := &runtimeEnvironmentInspector{
				namespace:  func() (string, error) { return e.Allocation.Namespace, nil },
				diagnostic: func(d RuntimeDiagnostic) { events = append(events, d) },
				nft:        func(context.Context, ...string) ([]byte, error) { return []byte(`{"nftables":[]}`), nil },
				ip: func(_ context.Context, args ...string) ([]byte, error) {
					switch strings.Join(args, " ") {
					case "-j -d link show":
						return []byte(`[{"ifindex":2,"ifname":"enp39s0","link_type":"ether","mtu":9001,"flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"operstate":"UP"}]`), nil
					case "-j -4 rule show":
						return []byte(`[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`), nil
					case "-j -4 route show table main":
						return []byte(`[{"dst":"10.181.10.0/24","dev":"enp39s0","protocol":"kernel","scope":"link","prefsrc":"10.181.10.40","metric":100}]`), nil
					case "-j -4 address show":
						mu.Lock()
						defer mu.Unlock()
						calls++
						if calls == 1 || mode == "stable" {
							return before, nil
						}
						if mode == "assigned_source_drift" {
							return bytes.Replace(after, []byte("10.181.10.40"), []byte("10.181.10.41"), 1), nil
						}
						return after, nil
					default:
						if strings.HasPrefix(strings.Join(args, " "), "-j -4 route get ") {
							return []byte(`[{"dst":"` + args[len(args)-1] + `","dev":"enp39s0","prefsrc":"10.181.10.40"}]`), nil
						}
						t.Fatal("unexpected native read")
						return nil, nil
					}
				},
			}
			got, err := r.Observe(context.Background(), e.Allocation, e.Engines)
			if calls != 2 {
				t.Fatal("independent snapshot count changed", calls)
			}
			if mode == "assigned_source_drift" {
				if err != ErrRuntimeEnvironment || len(events) != 1 || events[0].Stage != "env_addresses_after" {
					t.Fatal("source drift admitted", err, events)
				}
				return
			}
			if err != nil {
				t.Fatal("qualified environment refused", err, events)
			}
			if mode == "stable" {
				baseline = got
			} else if !reflect.DeepEqual(got, baseline) {
				t.Fatal("renewal changed routing environment")
			}
		})
	}
}

func TestRuntimeAddressRenewalRefusesUnqualifiedOrChangedState(t *testing.T) {
	before, after := awsDHCPRenewalFixture(t, 1800), awsDHCPRenewalFixture(t, 3600)
	change := func(b []byte, old, next string) []byte { return bytes.Replace(b, []byte(old), []byte(next), 1) }
	for _, tc := range []struct{ name, old, next string }{
		{"not-dynamic", `"dynamic":true`, `"dynamic":false`},
		{"dynamic-string", `"dynamic":true`, `"dynamic":"true"`},
		{"missing-dynamic", `"dynamic":true,`, ``},
		{"not-ipv4", `"family":"inet"`, `"family":"inet6"`},
		{"missing-family", `"family":"inet",`, ``},
		{"not-global", `"scope":"global"`, `"scope":"link"`},
		{"unspecified", `10.181.10.40`, `0.0.0.0`},
		{"multicast", `10.181.10.40`, `224.0.0.1`},
		{"loopback", `10.181.10.40`, `127.0.0.1`},
		{"zero-prefix", `"prefixlen":24`, `"prefixlen":0`},
		{"oversize-prefix", `"prefixlen":24`, `"prefixlen":33`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, a := change(before, tc.old, tc.next), change(after, tc.old, tc.next)
			if bytes.Equal(b, before) || bytes.Equal(a, after) {
				t.Fatal("fixture replacement missing")
			}
			if runtimeAddressBracket(b, a, 320*time.Millisecond) {
				t.Fatal("unqualified renewal admitted")
			}
		})
	}
	for _, tc := range []struct {
		name          string
		before, after []byte
	}{
		{"unequal-before", change(before, `"preferred_life_time":1800`, `"preferred_life_time":1799`), after},
		{"unequal-after", before, change(after, `"preferred_life_time":3600`, `"preferred_life_time":3599`)},
		{"mixed-direction", before, change(after, `"preferred_life_time":3600`, `"preferred_life_time":1799`)},
		{"expired-before", awsDHCPRenewalFixture(t, 0), after},
		{"expired-after", before, awsDHCPRenewalFixture(t, 0)},
		{"forever-before", bytes.ReplaceAll(before, []byte("1800"), []byte(`"forever"`)), after},
		{"forever-after", before, bytes.ReplaceAll(after, []byte("3600"), []byte(`"forever"`))},
		{"numeric-forever", before, bytes.ReplaceAll(after, []byte("3600"), []byte("4294967295"))},
		{"malformed-lifetime", before, bytes.ReplaceAll(after, []byte("3600"), []byte(`"3600"`))},
		{"unknown-metadata-drift", before, change(after, `"metric":100`, `"metric":101`)},
		{"interface-index-drift", before, change(after, `"ifindex":2`, `"ifindex":3`)},
		{"flags-drift", before, change(after, `"LOWER_UP"`, `"NO-CARRIER"`)},
		{"source-drift", before, change(after, `10.181.10.40`, `10.181.10.41`)},
		{"prefix-drift", before, change(after, `"prefixlen":24`, `"prefixlen":25`)},
		{"missing-lifetime", before, change(after, `"preferred_life_time":3600,`, ``)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if runtimeAddressBracket(tc.before, tc.after, 320*time.Millisecond) {
				t.Fatal("changed or invalid state admitted")
			}
		})
	}
	for _, elapsed := range []time.Duration{0, -1, kernelReadTimeout + 1} {
		if runtimeAddressBracket(before, after, elapsed) {
			t.Fatal("read window ignored")
		}
	}
}
