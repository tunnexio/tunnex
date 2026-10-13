package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRuntimeAddressBracketActualCountdown(t *testing.T) {
	b, err := os.ReadFile("testdata/actual_gcp_address_countdown.json")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Before, After json.RawMessage
		ElapsedNS     int64 `json:"elapsed_ns"`
	}
	if json.Unmarshal(b, &c) != nil {
		t.Fatal("capture fixture")
	}
	if bytes.Equal(c.Before, c.After) {
		t.Fatal("old exact-byte guard must refuse actual countdown")
	}
	if !runtimeAddressBracket(c.Before, c.After, time.Duration(c.ElapsedNS)) {
		t.Fatal("bounded actual countdown refused")
	}
}
func TestRuntimeAddressBracketRefusesUnrelatedDrift(t *testing.T) {
	before := []byte(`[{"ifindex":2,"ifname":"ens4","flags":["UP"],"unknown":{"x":1},"addr_info":[{"family":"inet","local":"10.70.0.2","prefixlen":32,"scope":"global","label":"ens4","dynamic":true,"valid_life_time":2187,"preferred_life_time":2187}]}]`)
	after := bytes.ReplaceAll(before, []byte("2187"), []byte("2186"))
	if !runtimeAddressBracket(before, after, 44*time.Millisecond) {
		t.Fatal("countdown refused")
	}
	cases := map[string][]byte{
		"unknown":                 bytes.Replace(after, []byte(`"x":1`), []byte(`"x":2`), 1),
		"ifindex":                 bytes.Replace(after, []byte(`"ifindex":2`), []byte(`"ifindex":3`), 1),
		"flags":                   bytes.Replace(after, []byte(`"UP"`), []byte(`"DOWN"`), 1),
		"scope":                   bytes.Replace(after, []byte(`"global"`), []byte(`"link"`), 1),
		"label":                   bytes.Replace(after, []byte(`"label":"ens4"`), []byte(`"label":"ens5"`), 1),
		"local":                   bytes.Replace(after, []byte(`10.70.0.2`), []byte(`10.70.0.3`), 1),
		"prefix":                  bytes.Replace(after, []byte(`"prefixlen":32`), []byte(`"prefixlen":24`), 1),
		"expired":                 bytes.ReplaceAll(after, []byte("2186"), []byte("0")),
		"negative":                bytes.ReplaceAll(after, []byte("2186"), []byte("-1")),
		"malformed":               bytes.ReplaceAll(after, []byte("2186"), []byte(`"2186"`)),
		"excess":                  bytes.ReplaceAll(after, []byte("2186"), []byte("2185")),
		"renewal":                 bytes.ReplaceAll(after, []byte("2186"), []byte("2188")),
		"preferred_exceeds_valid": bytes.Replace(after, []byte(`"preferred_life_time":2186`), []byte(`"preferred_life_time":2187`), 1),
		"missing":                 bytes.Replace(after, []byte(`,"preferred_life_time":2186`), nil, 1),
		"row_count":               append(append([]byte(nil), after[:len(after)-1]...), []byte(`,{}]`)...),
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) {
			if runtimeAddressBracket(before, a, 44*time.Millisecond) {
				t.Fatal("changed input accepted")
			}
		})
	}
	for _, elapsed := range []time.Duration{0, -1, kernelReadTimeout + 1} {
		if runtimeAddressBracket(before, after, elapsed) {
			t.Fatal("elapsed bound ignored")
		}
	}
	forever := bytes.ReplaceAll(before, []byte("2187"), []byte(`"forever"`))
	if runtimeAddressBracket(forever, after, time.Second) {
		t.Fatal("forever changed")
	}
	if !runtimeAddressBracket(forever, forever, time.Second) {
		t.Fatal("stable forever refused")
	}
}

func TestRuntimeEnvironmentCompleteAddressCountdown(t *testing.T) {
	e := journalFixture()
	for i := range e.Engines {
		e.Engines[i].LocalPrefixes = []netip.Prefix{netip.MustParsePrefix("10.10.0.0/16")}
	}
	for _, drift := range []bool{false, true} {
		t.Run(map[bool]string{false: "countdown", true: "assigned_source_drift"}[drift], func(t *testing.T) {
			calls := 0
			r := &runtimeEnvironmentInspector{namespace: func() (string, error) { return e.Allocation.Namespace, nil }, nft: func(context.Context, ...string) ([]byte, error) { return []byte(`{"nftables":[]}`), nil }, ip: func(_ context.Context, args ...string) ([]byte, error) {
				switch strings.Join(args, " ") {
				case "-j -d link show":
					return []byte(`[{"ifindex":2,"ifname":"eth0","link_type":"ether","mtu":1500,"flags":["UP"]},{"ifindex":3,"ifname":"lan0","link_type":"ether","mtu":1500,"flags":["UP"]}]`), nil
				case "-j -4 rule show":
					return []byte(`[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`), nil
				case "-j -4 route show table main":
					return []byte(`[{"dst":"10.10.0.0/16","dev":"lan0"}]`), nil
				case "-j -4 address show":
					calls++
					raw := []byte(`[{"ifname":"eth0","addr_info":[{"local":"172.18.0.2","valid_life_time":100,"preferred_life_time":100}]}]`)
					if calls > 1 {
						raw = bytes.ReplaceAll(raw, []byte("100"), []byte("99"))
						if drift {
							raw = bytes.ReplaceAll(raw, []byte("172.18.0.2"), []byte("172.18.0.3"))
						}
					}
					return raw, nil
				default:
					if strings.HasPrefix(strings.Join(args, " "), "-j -4 route get ") {
						return []byte(`[{"dst":"` + args[len(args)-1] + `","dev":"eth0","prefsrc":"172.18.0.2"}]`), nil
					}
					t.Fatal("unexpected native read")
					return nil, nil
				}
			}}
			env, err := r.Observe(context.Background(), e.Allocation, e.Engines)
			if drift {
				if err == nil {
					t.Fatal("source drift accepted")
				}
			} else if err != nil || len(env.LocalIngressIndices) != 1 || env.Underlays[0].InterfaceIndex != 2 {
				t.Fatal("complete bounded countdown observation refused", err)
			}
		})
	}
	forever := []byte(`[{"addr_info":[{"valid_life_time":"forever","preferred_life_time":"forever"}]}]`)
	numeric := bytes.ReplaceAll(forever, []byte(`"forever"`), []byte(`4294967295`))
	if runtimeAddressBracket(forever, numeric, time.Millisecond) || runtimeAddressBracket(numeric, forever, time.Millisecond) {
		t.Fatal("forever representation drift accepted")
	}
}
