package ipsec

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestRuntimeEnvironmentHookCensus(t *testing.T) {
	p := []netip.Prefix{netip.MustParsePrefix("10.10.0.0/16")}
	if !runtimeHookCensus([]byte(`{"nftables":[{"table":{"family":"ip","name":"tunnex"}},{"chain":{"family":"ip","table":"tunnex","name":"forward","type":"filter","hook":"forward","prio":0,"policy":"drop"}},{"rule":{"family":"ip","table":"tunnex","chain":"forward","expr":[{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"]}},{"accept":null}]}}]}`), p) {
		t.Fatal("qualified filter rejected")
	}
	for _, s := range []string{`{"nftables":[{"chain":{"family":"ip","table":"kube","name":"f","type":"filter","hook":"forward","prio":0,"policy":"accept"}}]}`, `{"nftables":[{"chain":{"family":"ip","table":"tunnex","name":"postrouting","type":"nat","hook":"postrouting","prio":400,"policy":"accept"}}]}`, `{"nftables":[{"rule":{"family":"ip","table":"tunnex","chain":"postrouting","expr":[{"masquerade":null}]}}]}`, `{"nftables":[{"flowtable":{"family":"ip","table":"tunnex","name":"offload"}}]}`, `{"nftables":[{"rule":{"family":"ip","table":"tunnex","chain":"forward","expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":1}}]}}]}`, `{"nftables":[],"nftables":[]}`} {
		if runtimeHookCensus([]byte(s), p) {
			t.Fatal("unsafe composition accepted")
		}
	}
}
func TestRuntimeEnvironmentDefaultRules(t *testing.T) {
	if !runtimeDefaultRules([]byte(`[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`)) {
		t.Fatal("default rules rejected")
	}
	if runtimeDefaultRules([]byte(`[{"priority":0,"src":"all","table":"local"},{"priority":100,"src":"all","table":"100"}]`)) {
		t.Fatal("policy routes accepted")
	}
}

func TestRuntimeEnvironmentObservedUnderlayAndIngress(t *testing.T) {
	entry := journalFixture()
	for i := range entry.Engines {
		entry.Engines[i].LocalPrefixes = []netip.Prefix{netip.MustParsePrefix("10.10.0.0/16")}
	}
	missingAddress := false
	indirectRoute := false
	duplicateIndex := false
	driftRoute := false
	routeCalls := 0
	unknownRule := false
	changedNamespace := false
	calls := 0
	inspector := &runtimeEnvironmentInspector{namespace: func() (string, error) {
		calls++
		if changedNamespace && calls > 1 {
			return "net:[9999]", nil
		}
		return entry.Allocation.Namespace, nil
	}, nft: func(context.Context, ...string) ([]byte, error) { return []byte(`{"nftables":[]}`), nil }, ip: func(_ context.Context, args ...string) ([]byte, error) {
		command := strings.Join(args, " ")
		switch command {
		case "-j -d link show":
			if duplicateIndex {
				return []byte(`[{"ifindex":2,"ifname":"eth0","link_type":"ether","flags":["UP"]},{"ifindex":2,"ifname":"lan0","link_type":"ether","flags":["UP"]}]`), nil
			}
			return []byte(`[{"ifindex":2,"ifname":"eth0","link_type":"ether","flags":["UP"]},{"ifindex":3,"ifname":"lan0","link_type":"ether","flags":["UP"]}]`), nil
		case "-j -4 rule show":
			if unknownRule {
				return []byte(`[]`), nil
			}
			return []byte(`[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`), nil
		case "-j -4 route show table main":
			routeCalls++
			if indirectRoute {
				return []byte(`[{"dst":"10.10.0.0/16","dev":"lan0","nhid":7}]`), nil
			}
			if driftRoute && routeCalls > 1 {
				return []byte(`[]`), nil
			}
			return []byte(`[{"dst":"10.10.0.0/16","dev":"lan0"}]`), nil
		case "-j -4 address show":
			if missingAddress {
				return []byte(`[]`), nil
			}
			return []byte(`[{"ifname":"eth0","addr_info":[{"local":"172.18.0.2"}]}]`), nil
		default:
			if strings.HasPrefix(command, "-j -4 route get ") {
				return []byte(`[{"dst":"` + args[len(args)-1] + `","dev":"eth0","prefsrc":"172.18.0.2"}]`), nil
			}
			t.Fatalf("unexpected command %s", command)
			return nil, nil
		}
	}}
	out, e := inspector.Observe(context.Background(), entry.Allocation, entry.Engines)
	if e != nil || len(out.LocalIngressIndices) != 1 || out.LocalIngressIndices[0] != 3 || out.Underlays[0].InterfaceIndex != 2 || out.Underlays[0].LocalAddress.String() != "172.18.0.2" {
		t.Fatal("independent observation failed", e)
	}
	for i := range entry.Engines {
		entry.Engines[i].LocalPrefixes = append(entry.Engines[i].LocalPrefixes, netip.MustParsePrefix("172.18.0.0/16"))
	}
	oldIP := inspector.ip
	inspector.ip = func(c context.Context, args ...string) ([]byte, error) {
		if strings.Join(args, " ") == "-j -4 route show table main" {
			return []byte(`[{"dst":"10.10.0.0/16","dev":"lan0"},{"dst":"172.18.0.0/16","dev":"eth0"}]`), nil
		}
		return oldIP(c, args...)
	}
	if _, e = inspector.Observe(context.Background(), entry.Allocation, entry.Engines); e == nil {
		t.Fatal("multiple independent LAN identities accepted")
	}
	inspector.ip = oldIP
	for i := range entry.Engines {
		entry.Engines[i].LocalPrefixes = entry.Engines[i].LocalPrefixes[:1]
	}
	missingAddress = true
	if _, e = inspector.Observe(context.Background(), entry.Allocation, entry.Engines); e == nil {
		t.Fatal("unassigned source accepted")
	}
	missingAddress = false
	unknownRule = true
	if _, e = inspector.Observe(context.Background(), entry.Allocation, entry.Engines); e == nil {
		t.Fatal("missing rule census accepted")
	}
	unknownRule = false
	indirectRoute = true
	if _, e = inspector.Observe(context.Background(), entry.Allocation, entry.Engines); e == nil {
		t.Fatal("indirect local route accepted")
	}
	indirectRoute = false
	duplicateIndex = true
	if _, e = inspector.Observe(context.Background(), entry.Allocation, entry.Engines); e == nil {
		t.Fatal("duplicate physical index accepted")
	}
	duplicateIndex = false
	driftRoute = true
	routeCalls = 0
	if _, e = inspector.Observe(context.Background(), entry.Allocation, entry.Engines); e == nil {
		t.Fatal("changed local route accepted")
	}
	driftRoute = false
	changedNamespace = true
	calls = 0
	if _, e = inspector.Observe(context.Background(), entry.Allocation, entry.Engines); e == nil {
		t.Fatal("namespace change accepted")
	}
}

func TestRuntimeEnvironmentNATOrdering(t *testing.T) {
	match := `{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"10.99.0.0","len":24}}}}`
	wrap := func(expr string) []byte {
		return []byte(`{"nftables":[{"rule":{"family":"ip","table":"tunnex","chain":"postrouting","expr":[` + expr + `]}}]}`)
	}
	protected := []netip.Prefix{netip.MustParsePrefix("10.10.0.0/16")}
	if !runtimeHookCensus(wrap(match+`,{"masquerade":null}`), protected) {
		t.Fatal("properly scoped NAT refused")
	}
	if runtimeHookCensus(wrap(`{"masquerade":null},`+match), protected) {
		t.Fatal("late source match retroactively scopes NAT")
	}
	if runtimeHookCensus(wrap(match+`,{"masquerade":null},{"masquerade":null}`), protected) {
		t.Fatal("multiple NAT transformations accepted")
	}
}

func TestRuntimeEnvironmentCapturedNativeInventory(t *testing.T) {
	// Captured from a disposable synthetic native lab; no host configuration,
	// daemon keys or provider credentials are included in this fixture.
	raw, e := os.ReadFile("testdata/runtime-environment-iproute2-6.9.0.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		IP  map[string]json.RawMessage `json:"ip"`
		NFT json.RawMessage            `json:"nft"`
	}
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("fixture malformed")
	}
	entry := journalFixture()
	for i := range entry.Engines {
		entry.Engines[i].LocalPrefixes = []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")}
		entry.Engines[i].RemoteAddress = netip.MustParseAddr([]string{"198.19.240.20", "198.19.240.21"}[i])
	}
	inspector := &runtimeEnvironmentInspector{namespace: func() (string, error) { return entry.Allocation.Namespace, nil }, ip: func(_ context.Context, args ...string) ([]byte, error) {
		v, ok := fixture.IP[strings.Join(args, " ")]
		if !ok {
			t.Fatal("uncaptured command", args)
		}
		return v, nil
	}, nft: func(context.Context, ...string) ([]byte, error) { return fixture.NFT, nil }}
	observed, e := inspector.Observe(context.Background(), entry.Allocation, entry.Engines)
	if e != nil || len(observed.LocalIngressIndices) != 1 || observed.LocalIngressIndices[0] != 3 || observed.Underlays[0].InterfaceIndex != 2 || observed.Underlays[0].LocalAddress.String() != "198.19.240.10" {
		t.Fatal("native inventory rejected", e)
	}
}
