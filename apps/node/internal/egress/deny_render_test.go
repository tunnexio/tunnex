package egress

import (
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// AI-SEC-2: an explicit deny closes the direct path from an agent device to its MCP server. These run on
// every platform; the forward-chain placement is pinned in deny_linux_test.go.

func TestRenderDeniesExactTupleInItsOwnFamily(t *testing.T) {
	v4, v6, ok := renderDenies([]nodepolicy.DenyEntry{
		{SrcIP: "10.99.0.7", DstCIDR: "172.30.0.10/32", Protocol: "tcp", PortLow: 9000, PortHigh: 9000, Reason: "mcp_gateway_only"},
		{SrcIP: "fd42:99::7", DstCIDR: "2001:db8::10/128", Protocol: "tcp", PortLow: 9000, PortHigh: 9010},
	}, 0)
	if !ok {
		t.Fatal("well-formed denies were refused")
	}
	// The address the device dialed (survives a DNAT) and the address the packet is going to.
	want4 := "    ip saddr 10.99.0.7 ct original ip daddr 172.30.0.10/32 meta l4proto tcp ct original proto-dst 9000 counter drop comment \"tunnex_policy_deny\"\n" +
		"    ip saddr 10.99.0.7 ip daddr 172.30.0.10/32 tcp dport 9000 counter drop comment \"tunnex_policy_deny\"\n"
	if v4 != want4 {
		t.Fatalf("ip denies:\n%s\nwant:\n%s", v4, want4)
	}
	want6 := "    ip6 saddr fd42:99::7 ct original ip6 daddr 2001:db8::10/128 meta l4proto tcp ct original proto-dst 9000-9010 counter drop comment \"tunnex_policy_deny\"\n" +
		"    ip6 saddr fd42:99::7 ip6 daddr 2001:db8::10/128 tcp dport 9000-9010 counter drop comment \"tunnex_policy_deny\"\n"
	if v6 != want6 {
		t.Fatalf("ip6 denies:\n%s\nwant:\n%s", v6, want6)
	}
}

func TestRenderDeniesProtocolForms(t *testing.T) {
	for name, tc := range map[string]struct {
		entry nodepolicy.DenyEntry
		want  []string
	}{
		"any": {nodepolicy.DenyEntry{SrcIP: "10.99.0.7", DstCIDR: "172.30.0.0/24", Protocol: "any"},
			[]string{"ip saddr 10.99.0.7 ct original ip daddr 172.30.0.0/24 counter drop", "ip saddr 10.99.0.7 ip daddr 172.30.0.0/24 counter drop"}},
		"udp, every port": {nodepolicy.DenyEntry{SrcIP: "10.99.0.7", DstCIDR: "172.30.0.10/32", Protocol: "udp"},
			[]string{"ct original ip daddr 172.30.0.10/32 meta l4proto udp counter drop", "ip daddr 172.30.0.10/32 meta l4proto udp counter drop"}},
		"a source range": {nodepolicy.DenyEntry{SrcIP: "10.99.0.9/24", DstCIDR: "172.30.0.10/32", Protocol: "tcp", PortLow: 80, PortHigh: 80},
			[]string{"ip saddr 10.99.0.0/24 ct original ip daddr 172.30.0.10/32", "ip saddr 10.99.0.0/24 ip daddr 172.30.0.10/32 tcp dport 80"}},
	} {
		t.Run(name, func(t *testing.T) {
			v4, v6, ok := renderDenies([]nodepolicy.DenyEntry{tc.entry}, 0)
			if !ok || v6 != "" {
				t.Fatalf("ok=%v v6=%q", ok, v6)
			}
			for _, want := range tc.want {
				if !strings.Contains(v4, want) {
					t.Fatalf("missing %q in:\n%s", want, v4)
				}
			}
		})
	}
}

// A deny the gateway cannot render exactly must never be skipped: skipping an allow fails closed, skipping
// a deny leaves the path it names open. The whole render is refused and the caller denies everything.
func TestRenderDeniesRefusesWhatItCannotRenderExactly(t *testing.T) {
	good := nodepolicy.DenyEntry{SrcIP: "10.99.0.7", DstCIDR: "172.30.0.10/32", Protocol: "tcp", PortLow: 9000, PortHigh: 9000}
	for name, bad := range map[string]nodepolicy.DenyEntry{
		"no source":             {DstCIDR: "172.30.0.10/32", Protocol: "tcp", PortLow: 9000, PortHigh: 9000},
		"injected source":       {SrcIP: "10.99.0.7 accept", DstCIDR: "172.30.0.10/32", Protocol: "any"},
		"destination not CIDR":  {SrcIP: "10.99.0.7", DstCIDR: "172.30.0.10", Protocol: "any"},
		"mixed families":        {SrcIP: "10.99.0.7", DstCIDR: "2001:db8::10/128", Protocol: "any"},
		"mapped IPv6 source":    {SrcIP: "::ffff:10.99.0.7", DstCIDR: "172.30.0.10/32", Protocol: "any"},
		"unknown protocol":      {SrcIP: "10.99.0.7", DstCIDR: "172.30.0.10/32", Protocol: "sctp"},
		"empty protocol":        {SrcIP: "10.99.0.7", DstCIDR: "172.30.0.10/32"},
		"ports on any":          {SrcIP: "10.99.0.7", DstCIDR: "172.30.0.10/32", Protocol: "any", PortLow: 9000, PortHigh: 9000},
		"half-set range":        {SrcIP: "10.99.0.7", DstCIDR: "172.30.0.10/32", Protocol: "tcp", PortLow: 9000},
		"inverted range":        {SrcIP: "10.99.0.7", DstCIDR: "172.30.0.10/32", Protocol: "tcp", PortLow: 9001, PortHigh: 9000},
		"port beyond the range": {SrcIP: "10.99.0.7", DstCIDR: "172.30.0.10/32", Protocol: "tcp", PortLow: 9000, PortHigh: 70000},
		"negative port":         {SrcIP: "10.99.0.7", DstCIDR: "172.30.0.10/32", Protocol: "tcp", PortLow: -1, PortHigh: 9000},
	} {
		t.Run(name, func(t *testing.T) {
			v4, v6, ok := renderDenies([]nodepolicy.DenyEntry{good, bad}, 0)
			if ok || v4 != "" || v6 != "" {
				t.Fatalf("a deny that cannot be rendered was skipped: ok=%v\n%s%s", ok, v4, v6)
			}
		})
	}
}

func TestRenderDeniesWithoutEntriesIsEmpty(t *testing.T) {
	for _, group := range []int{0, 5} {
		if v4, v6, ok := renderDenies(nil, group); !ok || v4 != "" || v6 != "" {
			t.Fatalf("group %d: ok=%v v4=%q v6=%q", group, ok, v4, v6)
		}
	}
}

// With flow logging on, a denied packet is observed as a deny; the log statement never changes the verdict.
func TestRenderDeniesLogsWithoutChangingTheVerdict(t *testing.T) {
	entry := []nodepolicy.DenyEntry{{SrcIP: "10.99.0.7", DstCIDR: "172.30.0.10/32", Protocol: "tcp", PortLow: 9000, PortHigh: 9000}}
	plain, _, _ := renderDenies(entry, 0)
	logged, _, ok := renderDenies(entry, 5)
	if !ok || strings.Count(logged, " group 5 counter drop comment \"tunnex_policy_deny\"\n") != 2 {
		t.Fatalf("logged denies:\n%s", logged)
	}
	stripped := strings.ReplaceAll(logged, denyLogClause(5), "")
	if stripped != plain {
		t.Fatalf("the log clause must be the only difference:\n%s\nplain:\n%s", stripped, plain)
	}
}

func TestAddedDeniesAreOnlyTheNewOnes(t *testing.T) {
	a := nodepolicy.DenyEntry{SrcIP: "10.99.0.7", DstCIDR: "172.30.0.10/32", Protocol: "tcp", PortLow: 9000, PortHigh: 9000, Reason: "mcp_gateway_only"}
	b := nodepolicy.DenyEntry{SrcIP: "10.99.0.8", DstCIDR: "172.30.0.10/32", Protocol: "tcp", PortLow: 9000, PortHigh: 9000}
	if got := addedDenies(nil, []nodepolicy.DenyEntry{a, b}); len(got) != 2 {
		t.Fatalf("with no baseline every deny is new: %+v", got)
	}
	if got := addedDenies([]nodepolicy.DenyEntry{a}, []nodepolicy.DenyEntry{a, b}); len(got) != 1 || got[0].SrcIP != "10.99.0.8" {
		t.Fatalf("only the new deny: %+v", got)
	}
	// Metadata is not part of the tuple: a changed reason is not a new deny.
	renamed := a
	renamed.Reason, renamed.SrcDeviceID = "other", "device"
	if got := addedDenies([]nodepolicy.DenyEntry{a, b}, []nodepolicy.DenyEntry{renamed, b}); len(got) != 0 {
		t.Fatalf("an unchanged tuple was flushed again: %+v", got)
	}
	if got := addedDenies([]nodepolicy.DenyEntry{a, b}, nil); len(got) != 0 {
		t.Fatalf("a removed deny has nothing to cut: %+v", got)
	}
}
