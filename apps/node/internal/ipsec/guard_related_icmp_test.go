package ipsec

import (
	"encoding/json"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestGuardRemoteFragmentNeededExactParentGrant(t *testing.T) {
	i := guardFixture()
	i.Connections[0].ReplyIngressIndices = []int{10}
	i.Connections[0].Grants[0].Source = netip.MustParsePrefix("10.10.0.1/32")
	m, err := RenderGuard(i)
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{"meta iif 10 meta oif 2 ip saddr 10.20.0.0/24 ip daddr 10.10.0.1/32 icmp type 3 icmp code 4 ct state related ct direction reply", "ct protocol tcp", "ct original ip saddr 10.10.0.1/32 ct original ip daddr 10.20.0.0/24", "ct original proto-dst 443 meta iif @reply_lease"} {
		if !strings.Contains(m.NFT, wanted) {
			t.Fatal("missing parent authority", wanted)
		}
	}
	if strings.Contains(m.NFT, "ct state related accept") {
		t.Fatal("blanket related grant")
	}
}
func TestGuardRemoteFragmentNeededNoIndependentAuthority(t *testing.T) {
	for _, scenario := range []string{"UDP", "ANY", "no-grants", "no-lease", "no-reply", "no-permit", "remote-origin", "broad-source"} {
		i := guardFixture()
		c := &i.Connections[0]
		c.ReplyIngressIndices = []int{10}
		c.Grants[0].Source = netip.MustParsePrefix("10.10.0.1/32")
		switch scenario {
		case "broad-source":
			c.Grants[0].Source = netip.MustParsePrefix("10.10.0.0/24")
		case "UDP":
			c.Grants[0].Protocol = GuardUDP
		case "ANY":
			c.Grants[0].Protocol = GuardAny
			c.Grants[0].PortLow = 0
			c.Grants[0].PortHigh = 0
		case "no-grants":
			c.Grants = nil
		case "no-lease":
			c.PermitFor = 0
		case "no-reply":
			c.ReplyIngressIndices = nil
		case "no-permit":
			c.PermittedInterfaceIndices = nil
		case "remote-origin":
			g := &c.Grants[0]
			g.Source, g.Destination = g.Destination, g.Source
		}
		m, err := RenderGuard(i)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(m.NFT, "icmp type 3") {
			t.Fatal("unapproved related authority", scenario)
		}
	}
}

func TestGuardRemoteCapturedNativeParentExpression(t *testing.T) {
	raw, err := os.ReadFile("testdata/nft_related_icmp_native_expression.json")
	if err != nil {
		t.Fatal(err)
	}
	c := guardFixture().Connections[0]
	g := c.Grants[0]
	g.Source = netip.MustParsePrefix("10.10.0.1/32")
	g.Destination = netip.MustParsePrefix("10.20.0.1/32")
	g.PortLow, g.PortHigh = 8080, 8080
	r := guardRemoteFragmentNeeded(c, g, 10, 2, c.Remote[0])
	encoded, _ := json.Marshal(r.expr[4:12])
	var want, got any
	if json.Unmarshal(raw, &want) != nil || json.Unmarshal(encoded, &got) != nil || !reflect.DeepEqual(want, got) {
		t.Fatal("parent expression differs from captured native grammar")
	}
}
