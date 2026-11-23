package k8snetprep

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// The status documents below are written from Cilium's API model
// (api/v1/openapi.yaml, definition Masquerading, v1.20.5), in which false and
// empty fields are omitted on the wire. They are not captured from a node; the
// live walk in docs/K8N-2-cilium.md replaces them with captured ones.

func ciliumStatusDoc(masquerading string) []byte {
	return []byte(`{"cilium":{"state":"Ok"},"kube-proxy-replacement":{"mode":"True","deviceList":[{"name":"eth0"}]},"masquerading":` + masquerading + `}`)
}

func TestParseCiliumStatusAccepted(t *testing.T) {
	cases := []struct {
		name string
		body string
		want ciliumMasquerade
	}{
		{"disabled", `{"enabledProtocols":{}}`, ciliumMasquerade{Mode: ciliumMasqOff}},
		{"disabled, written out", `{"enabled":false,"enabledProtocols":{"ipv4":false,"ipv6":false}}`, ciliumMasquerade{Mode: ciliumMasqOff}},
		{"IPv6 only", `{"enabled":true,"enabledProtocols":{"ipv6":true},"mode":"iptables","snat-exclusion-cidr":"10.0.0.0/8","snat-exclusion-cidr-v4":"10.0.0.0/8","snat-exclusion-cidr-v6":"fd00::/100"}`,
			ciliumMasquerade{Mode: ciliumMasqOff}},
		{"iptables", `{"enabled":true,"enabledProtocols":{"ipv4":true},"mode":"iptables","snat-exclusion-cidr":"10.244.1.0/24","snat-exclusion-cidr-v4":"10.244.1.0/24"}`,
			ciliumMasquerade{Mode: ciliumMasqIPTables, Exclusion: netip.MustParsePrefix("10.244.1.0/24")}},
		{"eBPF", `{"enabled":true,"enabledProtocols":{"ipv4":true},"mode":"BPF","snat-exclusion-cidr":"10.0.0.0/8","snat-exclusion-cidr-v4":"10.0.0.0/8"}`,
			ciliumMasquerade{Mode: ciliumMasqBPF, Exclusion: netip.MustParsePrefix("10.0.0.0/8")}},
		{"eBPF with ip-masq-agent, dual stack", `{"enabled":true,"enabledProtocols":{"ipv4":true,"ipv6":true},"mode":"BPF","ip-masq-agent":true,"snat-exclusion-cidr":"10.0.0.0/16","snat-exclusion-cidr-v4":"10.0.0.0/16","snat-exclusion-cidr-v6":"fd00::/100"}`,
			ciliumMasquerade{Mode: ciliumMasqBPF, Exclusion: netip.MustParsePrefix("10.0.0.0/16"), IPMasqAgent: true}},
		{"no legacy field", `{"enabled":true,"enabledProtocols":{"ipv4":true},"mode":"BPF","snat-exclusion-cidr-v4":"10.0.0.0/8"}`,
			ciliumMasquerade{Mode: ciliumMasqBPF, Exclusion: netip.MustParsePrefix("10.0.0.0/8")}},
		{"exclusion with host bits is masked", `{"enabled":true,"enabledProtocols":{"ipv4":true},"mode":"BPF","snat-exclusion-cidr-v4":"10.1.2.3/8"}`,
			ciliumMasquerade{Mode: ciliumMasqBPF, Exclusion: netip.MustParsePrefix("10.0.0.0/8")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseCiliumStatus(ciliumStatusDoc(tc.body))
			if err != nil {
				t.Fatalf("parseCiliumStatus: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestParseCiliumStatusIgnoresUnrelatedStaleProbes(t *testing.T) {
	doc := []byte(`{"stale":{"kvstore":"2026-11-23T10:00:00Z"},"masquerading":{"enabledProtocols":{}}}`)
	got, err := parseCiliumStatus(doc)
	if err != nil || got.Mode != ciliumMasqOff {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestParseCiliumStatusRefused(t *testing.T) {
	const bpf = `"enabled":true,"enabledProtocols":{"ipv4":true},"mode":"BPF","snat-exclusion-cidr-v4":"10.0.0.0/8"`
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{"empty", ``, "not a JSON object"},
		{"null", `null`, "not a JSON object"},
		{"array", `[]`, "not a JSON object"},
		{"text", `Masquerading: BPF [eth0] 10.0.0.0/8`, "not a JSON object"},
		{"trailing data", `{"masquerading":{"enabledProtocols":{}}} {}`, "not a JSON object"},
		{"no masquerading section", `{"cilium":{"state":"Ok"}}`, "no masquerading section"},
		{"masquerading null", `{"masquerading":null}`, "no per-protocol state"},
		{"masquerading empty", `{"masquerading":{}}`, "no per-protocol state"},
		{"masquerading is a string", `{"masquerading":"BPF"}`, "not understood"},
		{"masquerading stale", `{"stale":{"masquerading":"2026-11-23T10:00:00Z"},"masquerading":{` + bpf + `}}`, "stale"},
		{"stale list of another shape", `{"stale":["masquerading"],"masquerading":{` + bpf + `}}`, "stale list"},
		{"unknown field", `{"masquerading":{` + bpf + `,"snat-exclusion-cidrs-v4":["10.0.0.0/8"]}}`, "not understood"},
		{"enabled as string", `{"masquerading":{"enabled":"true","enabledProtocols":{"ipv4":true},"mode":"BPF","snat-exclusion-cidr-v4":"10.0.0.0/8"}}`, "not understood"},
		{"unknown protocol field", `{"masquerading":{"enabledProtocols":{"ipv4":true,"nat46":true}}}`, "not understood"},
		{"protocol on while disabled", `{"masquerading":{"enabledProtocols":{"ipv4":true}}}`, "inconsistent"},
		{"mode while disabled", `{"masquerading":{"enabledProtocols":{},"mode":"BPF"}}`, "inconsistent"},
		{"exclusion while disabled", `{"masquerading":{"enabledProtocols":{},"snat-exclusion-cidr-v4":"10.0.0.0/8"}}`, "inconsistent"},
		{"agent while disabled", `{"masquerading":{"enabledProtocols":{},"ip-masq-agent":true}}`, "inconsistent"},
		{"enabled with no protocol", `{"masquerading":{"enabled":true,"enabledProtocols":{},"mode":"BPF"}}`, "inconsistent"},
		{"mode missing", `{"masquerading":{"enabled":true,"enabledProtocols":{"ipv4":true},"snat-exclusion-cidr-v4":"10.0.0.0/8"}}`, "mode is not understood"},
		{"mode unknown", `{"masquerading":{"enabled":true,"enabledProtocols":{"ipv4":true},"mode":"nftables","snat-exclusion-cidr-v4":"10.0.0.0/8"}}`, "mode is not understood"},
		{"mode in another case", `{"masquerading":{"enabled":true,"enabledProtocols":{"ipv4":true},"mode":"bpf","snat-exclusion-cidr-v4":"10.0.0.0/8"}}`, "mode is not understood"},
		{"agent in iptables mode", `{"masquerading":{"enabled":true,"enabledProtocols":{"ipv4":true},"mode":"iptables","ip-masq-agent":true,"snat-exclusion-cidr-v4":"10.0.0.0/8"}}`, "inconsistent"},
		{"exclusion missing", `{"masquerading":{"enabled":true,"enabledProtocols":{"ipv4":true},"mode":"BPF"}}`, "no IPv4 exclusion range"},
		{"only the legacy exclusion", `{"masquerading":{"enabled":true,"enabledProtocols":{"ipv4":true},"mode":"BPF","snat-exclusion-cidr":"10.0.0.0/8"}}`, "no IPv4 exclusion range"},
		{"exclusion not a range", `{"masquerading":{"enabled":true,"enabledProtocols":{"ipv4":true},"mode":"BPF","snat-exclusion-cidr-v4":"10.0.0.0"}}`, "exclusion range is not understood"},
		{"exclusion empty", `{"masquerading":{"enabled":true,"enabledProtocols":{"ipv4":true},"mode":"BPF","snat-exclusion-cidr-v4":""}}`, "exclusion range is not understood"},
		{"exclusion IPv6", `{"masquerading":{"enabled":true,"enabledProtocols":{"ipv4":true},"mode":"BPF","snat-exclusion-cidr-v4":"fd00::/100"}}`, "exclusion range is not understood"},
		{"legacy disagrees", `{"masquerading":{"enabled":true,"enabledProtocols":{"ipv4":true},"mode":"BPF","snat-exclusion-cidr":"10.0.0.0/8","snat-exclusion-cidr-v4":"10.0.0.0/16"}}`, "inconsistent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseCiliumStatus([]byte(tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
			if got != (ciliumMasquerade{}) {
				t.Fatalf("a refused status still returned %+v", got)
			}
		})
	}
}

func TestParseCiliumStatusBound(t *testing.T) {
	doc := `{"masquerading":{"enabledProtocols":{}},"pad":"` + strings.Repeat("x", maxCiliumStatusBytes) + `"}`
	if _, err := parseCiliumStatus([]byte(doc)); err == nil || !strings.Contains(err.Error(), "exceeds bound") {
		t.Fatalf("err = %v", err)
	}
}

// ciliumIPMasqEntry renders one cilium_ipmasq_v4 entry the way bpftool prints a map
// without type information: struct { u32 prefixlen; u8 addr[4] } -> u8 pad.
func ciliumIPMasqEntry(cidr string) string {
	prefix := netip.MustParsePrefix(cidr)
	addr := prefix.Addr().As4()
	return fmt.Sprintf(`{"key":["0x%02x","0x00","0x00","0x00","0x%02x","0x%02x","0x%02x","0x%02x"],"value":["0x00"]}`,
		prefix.Bits(), addr[0], addr[1], addr[2], addr[3])
}

func ciliumIPMasqDump(cidrs ...string) []byte {
	entries := make([]string, len(cidrs))
	for i, cidr := range cidrs {
		entries[i] = ciliumIPMasqEntry(cidr)
	}
	return []byte("[" + strings.Join(entries, ",") + "]")
}

func ciliumPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(cidrs))
	for i, cidr := range cidrs {
		out[i] = netip.MustParsePrefix(cidr)
	}
	return out
}

func TestParseCiliumIPMasqDump(t *testing.T) {
	// The list the Cilium documentation shows after applying its rfc1918
	// example, plus the link-local range the agent appends by default.
	want := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}
	got, err := parseCiliumIPMasqDump(ciliumIPMasqDump(want...))
	if err != nil {
		t.Fatalf("parseCiliumIPMasqDump: %v", err)
	}
	if !reflect.DeepEqual(got, ciliumPrefixes(want...)) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseCiliumIPMasqDumpShapes(t *testing.T) {
	cases := []struct {
		name string
		dump string
		want []netip.Prefix
	}{
		{"empty map", `[]`, []netip.Prefix{}},
		{"pretty printed", "[{\n    \"key\": [\"0x08\",\"0x00\",\"0x00\",\"0x00\",\"0x0a\",\"0x00\",\"0x00\",\"0x00\"\n    ],\n    \"value\": [\"0x00\"\n    ]\n  }\n]\n", ciliumPrefixes("10.0.0.0/8")},
		{"with type information", `[{"key":["0x0a","0x00","0x00","0x00","0x64","0x40","0x00","0x00"],"value":["0x00"],"formatted":{"key":{"lpm":{"prefixlen":10},"addr":16484},"value":{"pad":0}}}]`, ciliumPrefixes("100.64.0.0/10")},
		{"default route and host entry", `[` + ciliumIPMasqEntry("0.0.0.0/0") + `,` + ciliumIPMasqEntry("192.0.2.7/32") + `]`, ciliumPrefixes("0.0.0.0/0", "192.0.2.7/32")},
		{"host bits beyond the prefix are ignored, as the kernel ignores them", `[{"key":["0x08","0x00","0x00","0x00","0x0a","0x01","0x02","0x03"],"value":["0x00"]}]`, ciliumPrefixes("10.0.0.0/8")},
		{"upper-case hex", `[{"key":["0x0C","0x00","0x00","0x00","0xAC","0x10","0x00","0x00"],"value":["0x00"]}]`, ciliumPrefixes("172.16.0.0/12")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseCiliumIPMasqDump([]byte(tc.dump))
			if err != nil {
				t.Fatalf("parseCiliumIPMasqDump: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseCiliumIPMasqDumpRefused(t *testing.T) {
	const value = `"value":["0x00"]`
	cases := []struct {
		name string
		dump string
		want string
	}{
		{"empty output", ``, "not a JSON array"},
		{"null", `null`, "not a JSON array"},
		{"object", `{"key":[],"value":[]}`, "not a JSON array"},
		{"error object", `{"error":"can't open pinned map"}`, "not a JSON array"},
		{"the documented text listing", "IP PREFIX/ADDRESS\n10.0.0.0/8\n", "not a JSON array"},
		{"truncated", `[{"key":["0x08","0x00"`, "not understood"},
		{"trailing data", `[] []`, "not understood"},
		{"null entry", `[null]`, "entry that is not understood"},
		{"entry is an array", `[["0x08"]]`, "not understood"},
		{"unknown member", `[{"key":["0x08","0x00","0x00","0x00","0x0a","0x00","0x00","0x00"],` + value + `,"flags":1}]`, "entry that is not understood"},
		{"no key", `[{` + value + `}]`, "key that is not understood"},
		{"no value", `[{"key":["0x08","0x00","0x00","0x00","0x0a","0x00","0x00","0x00"]}]`, "value that is not understood"},
		{"lookup error as value", `[{"key":["0x08","0x00","0x00","0x00","0x0a","0x00","0x00","0x00"],"value":{"error":"No such file or directory"}}]`, "value that is not understood"},
		{"IPv6 key (20 bytes)", `[{"key":["0x40","0x00","0x00","0x00","0xfd","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00","0x00"],` + value + `}]`, "key that is not understood"},
		{"short key", `[{"key":["0x08","0x00","0x00","0x00","0x0a","0x00","0x00"],` + value + `}]`, "key that is not understood"},
		{"wide value", `[{"key":["0x08","0x00","0x00","0x00","0x0a","0x00","0x00","0x00"],"value":["0x00","0x00"]}]`, "value that is not understood"},
		{"numeric bytes", `[{"key":[8,0,0,0,10,0,0,0],` + value + `}]`, "key that is not understood"},
		{"byte without prefix", `[{"key":["08","0x00","0x00","0x00","0x0a","0x00","0x00","0x00"],` + value + `}]`, "key that is not understood"},
		{"byte too wide", `[{"key":["0x008","0x00","0x00","0x00","0x0a","0x00","0x00","0x00"],` + value + `}]`, "key that is not understood"},
		{"byte not hex", `[{"key":["0xzz","0x00","0x00","0x00","0x0a","0x00","0x00","0x00"],` + value + `}]`, "key that is not understood"},
		{"byte with a sign", `[{"key":["0x+8","0x00","0x00","0x00","0x0a","0x00","0x00","0x00"],` + value + `}]`, "key that is not understood"},
		{"prefix length 33", `[{"key":["0x21","0x00","0x00","0x00","0x0a","0x00","0x00","0x00"],` + value + `}]`, "prefix length"},
		{"big-endian prefix length", `[{"key":["0x00","0x00","0x00","0x08","0x0a","0x00","0x00","0x00"],` + value + `}]`, "prefix length"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseCiliumIPMasqDump([]byte(tc.dump))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
			if got != nil {
				t.Fatalf("a refused dump still returned %v", got)
			}
		})
	}
}

func TestParseBPFToolMapDumpBounds(t *testing.T) {
	entry := ciliumIPMasqEntry("10.0.0.0/8")
	three := []byte("[" + entry + "," + entry + "," + entry + "]")
	if _, err := parseBPFToolMapDump(three, ciliumIPMasqKeyBytes, ciliumIPMasqValueBytes, 2); err == nil || !strings.Contains(err.Error(), "too many entries") {
		t.Fatalf("entry bound: err = %v", err)
	}
	if keys, err := parseBPFToolMapDump(three, ciliumIPMasqKeyBytes, ciliumIPMasqValueBytes, 3); err != nil || len(keys) != 3 {
		t.Fatalf("at the entry bound: %d keys, err = %v", len(keys), err)
	}
	huge := []byte("[" + strings.Repeat(" ", maxCiliumMapDumpBytes) + "]")
	if _, err := parseBPFToolMapDump(huge, ciliumIPMasqKeyBytes, ciliumIPMasqValueBytes, 2); err == nil || !strings.Contains(err.Error(), "exceeds bound") {
		t.Fatalf("size bound: err = %v", err)
	}
}

func TestDecodeCiliumIPMasqKeys(t *testing.T) {
	got, err := decodeCiliumIPMasqKeys([][]byte{{10, 0, 0, 0, 100, 64, 0, 0}, {32, 0, 0, 0, 192, 0, 2, 7}})
	if err != nil || !reflect.DeepEqual(got, ciliumPrefixes("100.64.0.0/10", "192.0.2.7/32")) {
		t.Fatalf("got %v, %v", got, err)
	}
	if got, err := decodeCiliumIPMasqKeys(nil); err != nil || len(got) != 0 {
		t.Fatalf("no keys: got %v, %v", got, err)
	}
	for name, keys := range map[string][][]byte{
		"short key":        {{8, 0, 0, 0, 10, 0, 0}},
		"long key":         {{8, 0, 0, 0, 10, 0, 0, 0, 0}},
		"empty key":        {{}},
		"prefix length 33": {{33, 0, 0, 0, 10, 0, 0, 0}},
		"high length byte": {{8, 0, 0, 1, 10, 0, 0, 0}},
		"too many":         make([][]byte, maxCiliumNonMasqueradeCIDRs+1),
	} {
		if got, err := decodeCiliumIPMasqKeys(keys); err == nil || got != nil {
			t.Fatalf("%s: got %v, err = %v", name, got, err)
		}
	}
}

func TestCiliumPresent(t *testing.T) {
	cases := []struct {
		name                  string
		links, chains, pinned []string
		want                  bool
	}{
		{"Flannel node", []string{"lo", "eth0", "flannel.1", "cni0", "wg0"}, []string{"POSTROUTING", "KUBE-POSTROUTING", "FLANNEL-POSTRTG"}, nil, false},
		{"nothing read", nil, nil, nil, false},
		{"Cilium host device", []string{"lo", "eth0", "cilium_net", "cilium_host", "lxc_health"}, nil, nil, true},
		{"Cilium tunnel device only", []string{"lo", "eth0", "cilium_vxlan"}, nil, nil, true},
		{"Cilium NAT chain only", []string{"lo", "eth0"}, []string{"POSTROUTING", "CILIUM_POST_nat"}, nil, true},
		{"Cilium pinned map only", []string{"lo", "eth0"}, []string{"POSTROUTING"}, []string{"cilium_lxc"}, true},
		{"a device that merely contains the word", []string{"mycilium_0", "ciliumhost"}, []string{"cilium_post"}, []string{"not_cilium_map"}, false},
	}
	for _, tc := range cases {
		if got := ciliumPresent(tc.links, tc.chains, tc.pinned); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCiliumEgressGatewayPinned(t *testing.T) {
	for name, tc := range map[string]struct {
		pinned []string
		want   bool
	}{
		"none":            {[]string{"cilium_lxc", "cilium_ipmasq_v4", "cilium_ipcache_v2"}, false},
		"empty":           {nil, false},
		"policy map":      {[]string{"cilium_lxc", "cilium_egress_gw_policy_v4"}, true},
		"policy map v2":   {[]string{"cilium_egress_gw_policy_v4_v2"}, true},
		"IPv6 policy map": {[]string{"cilium_egress_gw_policy_v6"}, false},
	} {
		if got := ciliumEgressGatewayPinned(tc.pinned); got != tc.want {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
}

func TestProveCiliumNoTunnelMasqueradeAccepted(t *testing.T) {
	bpf := func(exclusion string, agent bool) ciliumMasquerade {
		return ciliumMasquerade{Mode: ciliumMasqBPF, Exclusion: netip.MustParsePrefix(exclusion), IPMasqAgent: agent}
	}
	// Cilium's documented defaults for an empty ip-masq-agent configuration.
	defaults := ciliumPrefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
		"192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "169.254.0.0/16")
	cases := []struct {
		name   string
		obs    ciliumObservation
		tunnel string
		want   string
	}{
		{"masquerade off", ciliumObservation{Masquerade: ciliumMasquerade{Mode: ciliumMasqOff}}, "172.20.0.0/24", ReasonCiliumMasqueradeOff},
		{"masquerade off, egress map left pinned", ciliumObservation{Masquerade: ciliumMasquerade{Mode: ciliumMasqOff}, EgressGateway: true}, "172.20.0.0/24", ReasonCiliumMasqueradeOff},
		{"iptables mode defers to the walk", ciliumObservation{Masquerade: ciliumMasquerade{Mode: ciliumMasqIPTables, Exclusion: netip.MustParsePrefix("10.244.1.0/24")}}, "172.20.0.0/24", ReasonCiliumIPTablesMasquerade},
		{"inside the native-routing range", ciliumObservation{Masquerade: bpf("10.0.0.0/8", false)}, "10.99.0.0/16", "tunnel range is inside Cilium's native-routing range 10.0.0.0/8"},
		{"equal to the native-routing range", ciliumObservation{Masquerade: bpf("10.99.0.0/16", false)}, "10.99.0.0/16", "tunnel range is inside Cilium's native-routing range 10.99.0.0/16"},
		{"native-routing range covers everything", ciliumObservation{Masquerade: bpf("0.0.0.0/0", false)}, "172.20.0.0/24", "tunnel range is inside Cilium's native-routing range 0.0.0.0/0"},
		{"ip-masq-agent on, inside the reported range and inside an entry: the entry carries the proof", ciliumObservation{Masquerade: bpf("10.0.0.0/8", true), NonMasquerade: ciliumPrefixes("10.99.0.0/16"), NonMasqueradeRead: true}, "10.99.0.0/16", "tunnel range is inside Cilium ip-masq-agent range 10.99.0.0/16"},
		{"inside a default ip-masq-agent range", ciliumObservation{Masquerade: bpf("10.0.0.0/16", true), NonMasquerade: defaults, NonMasqueradeRead: true}, "100.96.0.0/16", "tunnel range is inside Cilium ip-masq-agent range 100.64.0.0/10"},
		{"equal to an ip-masq-agent entry", ciliumObservation{Masquerade: bpf("10.0.0.0/16", true), NonMasquerade: ciliumPrefixes("172.20.0.0/24"), NonMasqueradeRead: true}, "172.20.0.0/24", "tunnel range is inside Cilium ip-masq-agent range 172.20.0.0/24"},
		{"the widest containing entry is named, in any order", ciliumObservation{Masquerade: bpf("10.0.0.0/16", true), NonMasquerade: ciliumPrefixes("172.20.0.0/24", "172.16.0.0/12", "172.20.0.0/16"), NonMasqueradeRead: true}, "172.20.0.0/24", "tunnel range is inside Cilium ip-masq-agent range 172.16.0.0/12"},
		{"unmasked inputs", ciliumObservation{Masquerade: bpf("10.1.2.3/8", false)}, "10.99.0.7/16", "tunnel range is inside Cilium's native-routing range 10.0.0.0/8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := proveCiliumNoTunnelMasquerade(tc.obs, netip.MustParsePrefix(tc.tunnel))
			if err != nil {
				t.Fatalf("proveCiliumNoTunnelMasquerade: %v", err)
			}
			if got != tc.want {
				t.Fatalf("reason = %q, want %q", got, tc.want)
			}
			if len(got) > maxReasonBytes {
				t.Fatalf("reason is %d bytes", len(got))
			}
		})
	}
}

func TestProveCiliumNoTunnelMasqueradeRefused(t *testing.T) {
	bpf := func(exclusion string, agent bool) ciliumMasquerade {
		return ciliumMasquerade{Mode: ciliumMasqBPF, Exclusion: netip.MustParsePrefix(exclusion), IPMasqAgent: agent}
	}
	tunnel := netip.MustParsePrefix("172.20.0.0/24")
	cases := []struct {
		name   string
		obs    ciliumObservation
		tunnel netip.Prefix
		want   string
	}{
		{"nothing observed", ciliumObservation{}, tunnel, "mode is not understood"},
		{"unknown mode", ciliumObservation{Masquerade: ciliumMasquerade{Mode: "nftables"}}, tunnel, "mode is not understood"},
		{"invalid tunnel", ciliumObservation{Masquerade: ciliumMasquerade{Mode: ciliumMasqOff}}, netip.Prefix{}, "invalid IPv4 tunnel range"},
		{"IPv6 tunnel", ciliumObservation{Masquerade: ciliumMasquerade{Mode: ciliumMasqOff}}, netip.MustParsePrefix("fd00::/64"), "invalid IPv4 tunnel range"},
		{"off but with an agent", ciliumObservation{Masquerade: ciliumMasquerade{Mode: ciliumMasqOff, IPMasqAgent: true}}, tunnel, "inconsistent"},
		{"off but with an exclusion", ciliumObservation{Masquerade: ciliumMasquerade{Mode: ciliumMasqOff, Exclusion: netip.MustParsePrefix("10.0.0.0/8")}}, tunnel, "inconsistent"},
		{"iptables with an agent", ciliumObservation{Masquerade: ciliumMasquerade{Mode: ciliumMasqIPTables, IPMasqAgent: true}}, tunnel, "inconsistent"},
		{"eBPF without an exclusion", ciliumObservation{Masquerade: ciliumMasquerade{Mode: ciliumMasqBPF}}, tunnel, "exclusion range is not understood"},
		{"eBPF with an IPv6 exclusion", ciliumObservation{Masquerade: bpf("fd00::/100", false)}, tunnel, "exclusion range is not understood"},
		{"outside, agent off", ciliumObservation{Masquerade: bpf("10.0.0.0/8", false)}, tunnel, "ip-masq-agent is off"},
		{"outside, agent off, a map was read anyway", ciliumObservation{Masquerade: bpf("10.0.0.0/8", false), NonMasquerade: ciliumPrefixes("172.16.0.0/12"), NonMasqueradeRead: true}, tunnel, "ip-masq-agent is off"},
		{"tunnel wider than the native-routing range", ciliumObservation{Masquerade: bpf("172.20.0.0/25", false)}, tunnel, "ip-masq-agent is off"},
		// Review finding 1. With the ip-masq-agent on the datapath applies the
		// reported range only when ipv4-native-routing-cidr was set explicitly,
		// and the status does not say whether it was. Only a map entry proves.
		{"agent on, inside the reported range, map not read", ciliumObservation{Masquerade: bpf("10.0.0.0/8", true)}, netip.MustParsePrefix("10.99.0.0/16"), "map was not read"},
		{"agent on, inside the reported range, map empty", ciliumObservation{Masquerade: bpf("10.0.0.0/8", true), NonMasquerade: []netip.Prefix{}, NonMasqueradeRead: true}, netip.MustParsePrefix("10.99.0.0/16"), "is applied only when it is set explicitly"},
		{"agent on, inside the reported range, no entry contains it", ciliumObservation{Masquerade: bpf("172.16.0.0/12", true), NonMasquerade: ciliumPrefixes("10.0.0.0/8", "172.20.0.0/25"), NonMasqueradeRead: true}, tunnel, "is applied only when it is set explicitly"},
		{"agent on, equal to the reported range, no entry", ciliumObservation{Masquerade: bpf("172.20.0.0/24", true), NonMasquerade: ciliumPrefixes("100.64.0.0/10"), NonMasqueradeRead: true}, tunnel, "is applied only when it is set explicitly"},
		{"agent on, reported range covers everything, no entry", ciliumObservation{Masquerade: bpf("0.0.0.0/0", true), NonMasquerade: ciliumPrefixes("100.64.0.0/10"), NonMasqueradeRead: true}, tunnel, "is applied only when it is set explicitly"},
		{"agent on, map not read", ciliumObservation{Masquerade: bpf("10.0.0.0/8", true)}, tunnel, "map was not read"},
		{"agent on, map not read, stale members present", ciliumObservation{Masquerade: bpf("10.0.0.0/8", true), NonMasquerade: ciliumPrefixes("172.16.0.0/12")}, tunnel, "map was not read"},
		{"agent on, map empty", ciliumObservation{Masquerade: bpf("10.0.0.0/8", true), NonMasquerade: []netip.Prefix{}, NonMasqueradeRead: true}, tunnel, "no ip-masq-agent nonMasqueradeCIDRs entry contains it"},
		{"agent on, no entry contains it", ciliumObservation{Masquerade: bpf("10.0.0.0/8", true), NonMasquerade: ciliumPrefixes("10.0.0.0/8", "192.168.0.0/16"), NonMasqueradeRead: true}, tunnel, "no ip-masq-agent nonMasqueradeCIDRs entry contains it"},
		{"an entry only overlaps part of it", ciliumObservation{Masquerade: bpf("10.0.0.0/8", true), NonMasquerade: ciliumPrefixes("172.20.0.0/25"), NonMasqueradeRead: true}, tunnel, "no ip-masq-agent nonMasqueradeCIDRs entry contains it"},
		{"two entries cover it only together", ciliumObservation{Masquerade: bpf("10.0.0.0/8", true), NonMasquerade: ciliumPrefixes("172.20.0.0/25", "172.20.0.128/25"), NonMasqueradeRead: true}, tunnel, "no ip-masq-agent nonMasqueradeCIDRs entry contains it"},
		{"an invalid entry", ciliumObservation{Masquerade: bpf("10.0.0.0/8", true), NonMasquerade: []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12"), {}}, NonMasqueradeRead: true}, tunnel, "entry that is not understood"},
		{"an IPv6 entry", ciliumObservation{Masquerade: bpf("10.0.0.0/8", true), NonMasquerade: ciliumPrefixes("172.16.0.0/12", "fe80::/10"), NonMasqueradeRead: true}, tunnel, "entry that is not understood"},
		{"egress gateway, inside the native-routing range", ciliumObservation{Masquerade: bpf("172.16.0.0/12", false), EgressGateway: true}, tunnel, "egress gateway is enabled"},
		{"egress gateway, inside an ip-masq-agent range", ciliumObservation{Masquerade: bpf("10.0.0.0/8", true), NonMasquerade: ciliumPrefixes("172.16.0.0/12"), NonMasqueradeRead: true, EgressGateway: true}, tunnel, "egress gateway is enabled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := proveCiliumNoTunnelMasquerade(tc.obs, tc.tunnel)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
			if got != "" {
				t.Fatalf("a refusal still returned the reason %q", got)
			}
		})
	}
}

func TestProveCiliumRefusalNamesTheRangeToExclude(t *testing.T) {
	obs := ciliumObservation{Masquerade: ciliumMasquerade{Mode: ciliumMasqBPF, Exclusion: netip.MustParsePrefix("10.0.0.0/8")}}
	_, err := proveCiliumNoTunnelMasquerade(obs, netip.MustParsePrefix("172.20.0.9/24"))
	if err == nil || !strings.Contains(err.Error(), "172.20.0.0/24") || !strings.Contains(err.Error(), "10.0.0.0/8") {
		t.Fatalf("err = %v", err)
	}
	if len(err.Error()) > maxReasonBytes {
		t.Fatalf("refusal is %d bytes; a status reason would cut it", len(err.Error()))
	}
}

// Review finding 1, as one statement: the same report and the same tunnel
// range are accepted with the ip-masq-agent off and refused with it on, and
// with it on a map entry is the only thing that changes the answer.
func TestProveCiliumReportedRangeProvesOnlyWithTheIPMasqAgentOff(t *testing.T) {
	tunnel := netip.MustParsePrefix("10.99.0.0/16")
	report := func(agent bool) ciliumMasquerade {
		return ciliumMasquerade{Mode: ciliumMasqBPF, Exclusion: netip.MustParsePrefix("10.0.0.0/8"), IPMasqAgent: agent}
	}
	if reason, err := proveCiliumNoTunnelMasquerade(ciliumObservation{Masquerade: report(false)}, tunnel); err != nil || reason != "tunnel range is inside Cilium's native-routing range 10.0.0.0/8" {
		t.Fatalf("agent off: reason = %q, err = %v", reason, err)
	}
	on := ciliumObservation{Masquerade: report(true), NonMasquerade: ciliumPrefixes("192.168.0.0/16"), NonMasqueradeRead: true}
	reason, err := proveCiliumNoTunnelMasquerade(on, tunnel)
	var notExcluded *ciliumTunnelNotExcludedError
	if err == nil || reason != "" || !errors.As(err, &notExcluded) {
		t.Fatalf("agent on, range only in the report: reason = %q, err = %v", reason, err)
	}
	if !notExcluded.IPMasqAgent || !notExcluded.InsideReported || notExcluded.Tunnel != tunnel || notExcluded.Exclusion != netip.MustParsePrefix("10.0.0.0/8") {
		t.Fatalf("refusal = %+v", notExcluded)
	}
	if len(err.Error()) > maxReasonBytes {
		t.Fatalf("refusal is %d bytes", len(err.Error()))
	}
	// Outside the reported range too: the plain refusal, not this one.
	_, err = proveCiliumNoTunnelMasquerade(on, netip.MustParsePrefix("172.20.0.0/24"))
	if !errors.As(err, &notExcluded) || notExcluded.InsideReported {
		t.Fatalf("outside both: %v", err)
	}
	on.NonMasquerade = ciliumPrefixes("192.168.0.0/16", "10.99.0.0/16")
	if reason, err := proveCiliumNoTunnelMasquerade(on, tunnel); err != nil || reason != "tunnel range is inside Cilium ip-masq-agent range 10.99.0.0/16" {
		t.Fatalf("agent on, range listed: reason = %q, err = %v", reason, err)
	}
}

func TestProveCiliumTooManyMembers(t *testing.T) {
	obs := ciliumObservation{
		Masquerade:        ciliumMasquerade{Mode: ciliumMasqBPF, Exclusion: netip.MustParsePrefix("10.0.0.0/8"), IPMasqAgent: true},
		NonMasquerade:     make([]netip.Prefix, maxCiliumNonMasqueradeCIDRs+1),
		NonMasqueradeRead: true,
	}
	if _, err := proveCiliumNoTunnelMasquerade(obs, netip.MustParsePrefix("172.20.0.0/24")); err == nil || !strings.Contains(err.Error(), "too many entries") {
		t.Fatalf("err = %v", err)
	}
}

// The whole reading, end to end: an agent status and a map dump, as the
// wiring will hand them over, decide one node.
func TestCiliumProofFromStatusAndDump(t *testing.T) {
	status := ciliumStatusDoc(`{"enabled":true,"enabledProtocols":{"ipv4":true},"mode":"BPF","ip-masq-agent":true,"snat-exclusion-cidr":"10.0.0.0/16","snat-exclusion-cidr-v4":"10.0.0.0/16"}`)
	if !json.Valid(status) {
		t.Fatal("fixture is not JSON")
	}
	masq, err := parseCiliumStatus(status)
	if err != nil {
		t.Fatalf("parseCiliumStatus: %v", err)
	}
	members, err := parseCiliumIPMasqDump(ciliumIPMasqDump("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"))
	if err != nil {
		t.Fatalf("parseCiliumIPMasqDump: %v", err)
	}
	obs := ciliumObservation{Masquerade: masq, NonMasquerade: members, NonMasqueradeRead: true}
	reason, err := proveCiliumNoTunnelMasquerade(obs, netip.MustParsePrefix("172.20.0.0/24"))
	if err != nil || reason != "tunnel range is inside Cilium ip-masq-agent range 172.16.0.0/12" {
		t.Fatalf("inside: reason = %q, err = %v", reason, err)
	}
	if _, err := proveCiliumNoTunnelMasquerade(obs, netip.MustParsePrefix("100.96.0.0/16")); err == nil {
		t.Fatal("a tunnel range outside every listed range was accepted")
	}
}
