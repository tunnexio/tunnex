package ipsec

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func guardFixture() GuardIntent {
	return GuardIntent{Namespace: "net:[4026531992]", OwnerID: uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), Revision: 1, Connections: []GuardConnection{{ID: uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), Local: []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")}, Remote: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, Tunnels: [2]Ownership{{Namespace: "net:[4026531992]", InterfaceName: "tnxi-a", InterfaceIndex: 10, XFRMID: 20}, {Namespace: "net:[4026531992]", InterfaceName: "tnxi-b", InterfaceIndex: 11, XFRMID: 21}}, PermitFor: 30 * time.Second, PermittedInterfaceIndices: []int{10}, LocalIngressIndices: []int{2}, Grants: []GuardGrant{{Source: netip.MustParsePrefix("10.10.0.0/24"), Destination: netip.MustParsePrefix("10.20.0.0/24"), Protocol: GuardTCP, PortLow: 443, PortHigh: 443}}}}}
}
func TestGuardRenderActualHooksAndNoBlanketEstablished(t *testing.T) {
	got, err := RenderGuard(guardFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"hook forward priority -10", "hook output priority -10", "hook input priority -10", "hook postrouting priority 90", "ip daddr 10.20.0.0/24 counter drop", "ip saddr 10.20.0.0/24 counter drop", "meta iif 2 meta oif 10", "tcp dport 443", "tcp sport 443", "ct direction reply ct state established"} {
		if !strings.Contains(got.NFT, line) {
			t.Fatalf("required guard missing: %s", line)
		}
	}
	for _, bad := range []string{"ct state established,related accept", "ct state established accept", "flush ruleset", "ct mark set", "meta mark set"} {
		if strings.Contains(got.NFT, bad) {
			t.Fatalf("unsafe broad action %s", bad)
		}
	}
	if len(got.Digest) != 64 || got.Namespace != guardFixture().Namespace {
		t.Fatal("missing manifest identity")
	}
}
func TestGuardRenderRefusalSurvivesEmptyPermitList(t *testing.T) {
	intent := guardFixture()
	intent.Connections[0].PermittedInterfaceIndices = nil
	got, err := RenderGuard(intent)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got.NFT, "counter accept") {
		t.Fatal("disabled manifest permits payload")
	}
	if strings.Count(got.NFT, "ip daddr 10.20.0.0/24 counter drop") < 3 {
		t.Fatal("refusal does not cover forward/output/postrouting")
	}
}
func TestGuardRenderMalformedAuthority(t *testing.T) {
	cases := map[string]func(*GuardIntent){
		"namespace":                  func(i *GuardIntent) { i.Namespace = "caller-label" },
		"owner":                      func(i *GuardIntent) { i.OwnerID = uuid.Nil },
		"revision":                   func(i *GuardIntent) { i.Revision = 0 },
		"foreign namespace":          func(i *GuardIntent) { i.Connections[0].Tunnels[0].Namespace = "net:[2]" },
		"duplicate interface":        func(i *GuardIntent) { i.Connections[0].Tunnels[1].InterfaceIndex = 10 },
		"duplicate xfrm":             func(i *GuardIntent) { i.Connections[0].Tunnels[1].XFRMID = 20 },
		"foreign permit":             func(i *GuardIntent) { i.Connections[0].PermittedInterfaceIndices = []int{99} },
		"physical trusted as tunnel": func(i *GuardIntent) { i.Connections[0].LocalIngressIndices = []int{10} },
		"noncanonical":               func(i *GuardIntent) { i.Connections[0].Remote[0] = netip.MustParsePrefix("10.20.0.1/24") },
		"empty remote":               func(i *GuardIntent) { i.Connections[0].Remote = nil },
		"overlapping domains":        func(i *GuardIntent) { i.Connections[0].Remote = i.Connections[0].Local },
		"foreign source grant":       func(i *GuardIntent) { i.Connections[0].Grants[0].Source = netip.MustParsePrefix("10.99.0.0/24") },
		"broader destination grant":  func(i *GuardIntent) { i.Connections[0].Grants[0].Destination = netip.MustParsePrefix("10.0.0.0/8") },
		"unsupported protocol":       func(i *GuardIntent) { i.Connections[0].Grants[0].Protocol = "tcp; accept" },
		"invalid ports":              func(i *GuardIntent) { i.Connections[0].Grants[0].PortLow = 0 },
		"fqdn provenance":            func(i *GuardIntent) { i.Connections[0].Grants[0].FQDNManaged = true },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			i := guardFixture()
			change(&i)
			got, err := RenderGuard(i)
			if err == nil || got.NFT != "" {
				t.Fatal("invalid authority produced executable rules")
			}
		})
	}
}
func TestGuardRenderHostPermissionExplicit(t *testing.T) {
	i := guardFixture()
	base, _ := RenderGuard(i)
	i.Connections[0].Grants[0].HostOrigin = true
	host, err := RenderGuard(i)
	if err != nil {
		t.Fatal(err)
	}
	if host.Digest == base.Digest {
		t.Fatal("host authority omitted from manifest digest")
	}
	// Host-origin grants produce only output and matching input-reply accepts.
	for _, rule := range strings.Split(host.NFT, "\n") {
		if strings.Contains(rule, "counter accept") && strings.Contains(rule, "meta iif 2") {
			t.Fatal("host grant widened to forwarded traffic")
		}
	}
}
func TestGuardRenderDeterministicAndImmutable(t *testing.T) {
	i := guardFixture()
	i.Connections[0].PermittedInterfaceIndices = []int{11, 10}
	i.Connections[0].LocalIngressIndices = []int{3, 2}
	before := guardFixture()
	before.Connections[0].PermittedInterfaceIndices = []int{11, 10}
	before.Connections[0].LocalIngressIndices = []int{3, 2}
	a, err := RenderGuard(i)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(i, before) {
		t.Fatal("mutated caller input")
	}
	i.Connections[0].PermittedInterfaceIndices = []int{10, 11}
	i.Connections[0].LocalIngressIndices = []int{2, 3}
	b, err := RenderGuard(i)
	if err != nil || a != b {
		t.Fatal("unordered equivalent authority renders differently")
	}
}

func TestGuardRenderJSONContainsCompleteOrderedSemantics(t *testing.T) {
	m, err := RenderGuard(guardFixture())
	if err != nil {
		t.Fatal(err)
	}
	var expected struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	var transaction struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal([]byte(m.ExpectedJSON), &expected) != nil || json.Unmarshal([]byte(m.NFTJSON), &transaction) != nil {
		t.Fatal("invalid structured manifest")
	}
	if len(transaction.NFTables) < len(expected.NFTables)+1 {
		t.Fatal("transaction does not represent entire expected inventory")
	}
	hooks := map[string][]int{}
	rules := 0
	for _, object := range expected.NFTables {
		if raw, ok := object["chain"]; ok {
			var c struct {
				Hook     string `json:"hook"`
				Priority int    `json:"prio"`
			}
			if json.Unmarshal(raw, &c) != nil {
				t.Fatal("bad chain")
			}
			if c.Hook != "" {
				hooks[c.Hook] = append(hooks[c.Hook], c.Priority)
			}
		}
		if raw, ok := object["rule"]; ok {
			var r struct {
				Expr []json.RawMessage `json:"expr"`
			}
			if json.Unmarshal(raw, &r) != nil || len(r.Expr) < 3 {
				t.Fatal("missing match/counter/verdict semantics")
			}
			rules++
		}
	}
	if !reflect.DeepEqual(hooks, map[string][]int{"forward": {-10}, "input": {-10}, "output": {-10}, "postrouting": {90, 300}}) || rules < 10 {
		t.Fatal("structured manifest omitted enforcement boundary")
	}
	// Readback must contain expressions, not merely a digest/owner marker.
	if !strings.Contains(m.ExpectedJSON, `"payload"`) || !strings.Contains(m.ExpectedJSON, `"ct"`) || !strings.Contains(m.ExpectedJSON, `"drop":null`) {
		t.Fatal("expected semantics reduced to ownership marker")
	}
}

func TestGuardRenderEveryPermitRequiresKernelLease(t *testing.T) {
	i := encryptedGuardFixture()
	i.Connections[0].Grants = append(i.Connections[0].Grants, GuardGrant{Source: i.Connections[0].Local[0], Destination: i.Connections[0].Remote[0], Protocol: GuardAny, HostOrigin: true})
	m, err := RenderGuard(i)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(m.NFT, "\n") {
		if strings.Contains(line, "counter accept") && !strings.Contains(line, "@lease_") && !strings.Contains(line, "@sa_lease_") {
			t.Fatalf("permit bypasses expiry: %s", line)
		}
	}
	var doc struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal([]byte(m.ExpectedJSON), &doc) != nil {
		t.Fatal("bad expected JSON")
	}
	sets := 0
	for _, o := range doc.NFTables {
		if raw, ok := o["set"]; ok {
			sets++
			if !strings.Contains(string(raw), `"timeout":30`) {
				t.Fatal("lease timeout lost")
			}
		}
		if raw, ok := o["rule"]; ok && strings.Contains(string(raw), `"accept":null`) && !strings.Contains(string(raw), `@lease_`) && !strings.Contains(string(raw), `@sa_lease_`) {
			t.Fatal("JSON permit bypasses lease")
		}
	}
	if sets != 2 {
		t.Fatal("missing perconnection timeout set")
	}
}
func TestGuardRenderLeaseDurationBounds(t *testing.T) {
	for _, tt := range []struct {
		d           time.Duration
		bad, permit bool
	}{{0, false, false}, {time.Second - time.Nanosecond, false, false}, {time.Second, false, true}, {30*time.Second + 999*time.Millisecond, false, true}, {60 * time.Second, false, true}, {-1, true, false}, {60*time.Second + 1, true, false}} {
		t.Run(tt.d.String(), func(t *testing.T) {
			i := guardFixture()
			i.Connections[0].PermitFor = tt.d
			m, err := RenderGuard(i)
			if (err != nil) != tt.bad {
				t.Fatalf("wrong validation: %v", err)
			}
			if err != nil {
				return
			}
			if strings.Contains(m.NFT, "counter accept") != tt.permit {
				t.Fatal("wrong lease permission")
			}
			if tt.permit && !strings.Contains(m.NFT, fmt.Sprintf("timeout %ds", int64(tt.d/time.Second))) {
				t.Fatal("timeout rounded upward or lost")
			}
			if !strings.Contains(m.NFT, "ip daddr 10.20.0.0/24 counter drop") {
				t.Fatal("refusal expired with permits")
			}
		})
	}
}

func TestGuardRenderLeaseUsesNativeInterfaceIndexDatatype(t *testing.T) {
	m, err := RenderGuard(guardFixture())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.NFT, "type iface_index;") || !strings.Contains(m.NFTJSON, `"type":"iface_index"`) {
		t.Fatal("lease set uses a datatype rejected by native nft")
	}
}

func TestGuardRenderRefreshReplacesOwnerCommentAtomically(t *testing.T) {
	m, err := RenderGuard(guardFixture())
	if err != nil {
		t.Fatal(err)
	}
	sequence := "flush table inet tunnex_ipsec\nadd chain inet tunnex_ipsec owner\ndelete chain inet tunnex_ipsec owner\n"
	if !strings.Contains(m.NFT, sequence) {
		t.Fatal("existing owner comment would survive refresh")
	}
	var doc struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal([]byte(m.NFTJSON), &doc) != nil {
		t.Fatal("invalid transaction")
	}
	var ownerOps []string
	for _, command := range doc.NFTables {
		for op, raw := range command {
			var object map[string]json.RawMessage
			if json.Unmarshal(raw, &object) != nil {
				continue
			}
			if chain, ok := object["chain"]; ok {
				var c struct {
					Name    string `json:"name"`
					Comment string `json:"comment"`
				}
				if json.Unmarshal(chain, &c) == nil && c.Name == "owner" {
					ownerOps = append(ownerOps, op)
					if len(ownerOps) == 3 && c.Comment == "" {
						t.Fatal("replacement owner omitted current digest")
					}
				}
			}
		}
	}
	if !reflect.DeepEqual(ownerOps, []string{"add", "delete", "add"}) {
		t.Fatalf("unsafe owner refresh operations: %v", ownerOps)
	}
}

func TestGuardRenderNATCannotEscapeOriginalProtection(t *testing.T) {
	intent := guardFixture()
	manifest, err := RenderGuard(intent)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err = json.Unmarshal([]byte(manifest.ExpectedJSON), &envelope); err != nil {
		t.Fatal(err)
	}
	chains := map[string][]map[string]any{}
	for _, entry := range envelope.NFTables {
		if raw, ok := entry["rule"]; ok {
			var rule map[string]any
			if err = json.Unmarshal(raw, &rule); err != nil {
				t.Fatal(err)
			}
			chains[rule["chain"].(string)] = append(chains[rule["chain"].(string)], rule)
		}
	}
	for _, chain := range []string{"forward_guard", "input_guard", "output_guard", "postrouting_guard"} {
		for _, original := range []bool{true, false} {
			for _, field := range []string{"saddr", "daddr"} {
				for _, status := range []string{"dnat", "snat"} {
					selector := guardPayload("ip", field)
					if original {
						selector = map[string]any{"ct": map[string]any{"key": "ip " + field, "dir": "original"}}
					}
					prefix := guardPrefixJSON(netip.MustParsePrefix("10.20.0.0/24"))
					wanted := []any{guardMatch("==", selector, prefix), guardMatch("in", guardCT("status"), status), guardCounter(), guardVerdict("drop")}
					encoded, _ := json.Marshal(wanted)
					found := false
					for _, rule := range chains[chain] {
						expr, _ := json.Marshal(rule["expr"])
						if string(expr) == string(encoded) {
							found = true
							break
						}
						if strings.Contains(string(expr), `"accept":null`) {
							break
						}
					}
					if !found {
						t.Errorf("missing NAT refusal before permits: chain=%s original=%v field=%s status=%s", chain, original, field, status)
					}
				}
			}
		}
	}
	for _, text := range []string{"ct original ip daddr 10.20.0.0/24 ct status dnat counter drop", "ct original ip saddr 10.20.0.0/24 ct status snat counter drop"} {
		if !strings.Contains(manifest.NFT, text) {
			t.Errorf("text missing %s", text)
		}
	}
}

func encryptedGuardFixture() GuardIntent {
	i := guardFixture()
	i.Connections[0].EncryptedEgress = []GuardEncryptedEgress{{TunnelInterfaceIndex: 10, ReqID: 41, Peer: netip.MustParseAddr("198.19.240.2"), UnderlayInterfaceIndex: 3}}
	return i
}
func TestGuardRenderEncryptedEgressExactLease(t *testing.T) {
	i := encryptedGuardFixture()
	m, e := RenderGuard(i)
	if e != nil {
		t.Fatal(e)
	}
	for _, part := range []string{"typeof ipsec out reqid; flags timeout; timeout 60s;", "41 timeout 30s", "ip daddr 10.20.0.0/24 meta oif 3 ipsec out reqid 41 ipsec out ip daddr 198.19.240.2 ipsec out reqid @", "ct status dnat counter drop"} {
		if !strings.Contains(m.NFT, part) {
			t.Errorf("missing %s", part)
		}
	}
	if !strings.Contains(m.ExpectedJSON, `"ipsec":{"dir":"out","key":"reqid","spnum":0}`) || !strings.Contains(m.ExpectedJSON, `"ipsec":{"dir":"out","family":"ip","key":"daddr","spnum":0}`) {
		t.Fatal("exact XFRM JSON selectors absent")
	}
	i.Connections[0].PermitFor = 0
	m, e = RenderGuard(i)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(m.NFT, "ipsec out reqid 41") || strings.Contains(m.NFT, "41 timeout") {
		t.Fatal("unleased encrypted permit")
	}
}
func TestGuardRenderEncryptedEgressRefusals(t *testing.T) {
	for name, change := range map[string]func(*GuardIntent){
		"zero reqid":       func(i *GuardIntent) { i.Connections[0].EncryptedEgress[0].ReqID = 0 },
		"foreign tunnel":   func(i *GuardIntent) { i.Connections[0].EncryptedEgress[0].TunnelInterfaceIndex = 99 },
		"inactive tunnel":  func(i *GuardIntent) { i.Connections[0].EncryptedEgress[0].TunnelInterfaceIndex = 11 },
		"xfrm underlay":    func(i *GuardIntent) { i.Connections[0].EncryptedEgress[0].UnderlayInterfaceIndex = 11 },
		"missing underlay": func(i *GuardIntent) { i.Connections[0].EncryptedEgress[0].UnderlayInterfaceIndex = 0 },
		"zero peer":        func(i *GuardIntent) { i.Connections[0].EncryptedEgress[0].Peer = netip.MustParseAddr("0.0.0.0") },
		"multicast":        func(i *GuardIntent) { i.Connections[0].EncryptedEgress[0].Peer = netip.MustParseAddr("224.0.0.1") },
		"ipv6":             func(i *GuardIntent) { i.Connections[0].EncryptedEgress[0].Peer = netip.MustParseAddr("2001:db8::1") },
		"duplicate reqid": func(i *GuardIntent) {
			i.Connections[0].PermittedInterfaceIndices = []int{10, 11}
			b := i.Connections[0].EncryptedEgress[0]
			b.TunnelInterfaceIndex = 11
			i.Connections[0].EncryptedEgress = append(i.Connections[0].EncryptedEgress, b)
		},
	} {
		t.Run(name, func(t *testing.T) {
			i := encryptedGuardFixture()
			change(&i)
			if _, e := RenderGuard(i); e == nil {
				t.Fatal("invalid encrypted authority accepted")
			}
		})
	}
}

func TestGuardRenderEncryptedCrossConnectionCollision(t *testing.T) {
	i := encryptedGuardFixture()
	second := i.Connections[0]
	second.ID = uuid.New()
	second.Remote = []netip.Prefix{netip.MustParsePrefix("10.30.0.0/24")}
	second.Tunnels = [2]Ownership{{Namespace: i.Namespace, InterfaceName: "tnxi-c", InterfaceIndex: 12, XFRMID: 22}, {Namespace: i.Namespace, InterfaceName: "tnxi-d", InterfaceIndex: 13, XFRMID: 23}}
	second.PermittedInterfaceIndices = []int{12}
	second.EncryptedEgress = []GuardEncryptedEgress{{TunnelInterfaceIndex: 12, ReqID: 41, Peer: netip.MustParseAddr("198.19.240.3"), UnderlayInterfaceIndex: 3}}
	second.Grants = []GuardGrant{{Source: second.Local[0], Destination: second.Remote[0], Protocol: GuardAny}}
	i.Connections = append(i.Connections, second)
	if _, err := RenderGuard(i); err == nil {
		t.Fatal("cross connection reqid collision accepted")
	}
	i.Connections[1].EncryptedEgress[0].ReqID = 42
	if _, err := RenderGuard(i); err != nil {
		t.Fatal("independent connection rejected", err)
	}
	i.Connections[0].EncryptedEgress[0].UnderlayInterfaceIndex = 12
	if _, err := RenderGuard(i); err == nil {
		t.Fatal("other connection XFRM treated as physical")
	}
}

func TestGuardRenderEncryptedPeerCannotRouteIntoManagedPrefixes(t *testing.T) {
	for _, peer := range []string{"10.10.0.1", "10.20.0.1", "10.40.0.1", "10.50.0.1"} {
		t.Run(peer, func(t *testing.T) {
			i := encryptedGuardFixture()
			second := GuardConnection{ID: uuid.New(), Local: []netip.Prefix{netip.MustParsePrefix("10.40.0.0/24")}, Remote: []netip.Prefix{netip.MustParsePrefix("10.50.0.0/24")}, Tunnels: [2]Ownership{{Namespace: i.Namespace, InterfaceName: "tnxi-c", InterfaceIndex: 12, XFRMID: 22}, {Namespace: i.Namespace, InterfaceName: "tnxi-d", InterfaceIndex: 13, XFRMID: 23}}}
			i.Connections = append(i.Connections, second)
			if _, err := RenderGuard(i); err != nil {
				t.Fatal("nonoverlapping control rejected", err)
			}
			i.Connections[0].EncryptedEgress[0].Peer = netip.MustParseAddr(peer)
			if _, err := RenderGuard(i); err == nil {
				t.Fatal("recursive managed peer accepted")
			}
		})
	}
}

func TestGuardRenderCanonicalTransportPredicates(t *testing.T) {
	for _, protocol := range []GuardProtocol{GuardTCP, GuardUDP} {
		t.Run(string(protocol), func(t *testing.T) {
			i := guardFixture()
			i.Connections[0].Grants[0].Protocol = protocol
			m, err := RenderGuard(i)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(m.ExpectedJSON, `"key":"l4proto"`) || strings.Contains(m.NFT, "meta l4proto") {
				t.Fatal("redundant protocol predicate differs from native canonical output")
			}
			for _, field := range []string{"dport", "sport"} {
				needle := fmt.Sprintf(`"payload":{"field":%q,"protocol":%q}`, field, protocol)
				if !strings.Contains(m.ExpectedJSON, needle) {
					t.Fatalf("typed protocol predicate lost %s", needle)
				}
			}
		})
	}
}
