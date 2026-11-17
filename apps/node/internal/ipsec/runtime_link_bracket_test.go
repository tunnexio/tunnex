package ipsec

import (
	"strings"
	"testing"
)

const runtimeBridgeLinkFixture = `[{"ifindex":4,"ifname":"docker0","mtu":1500,"flags":["NO-CARRIER","BROADCAST","MULTICAST","UP"],"operstate":"DOWN","link_type":"ether","linkinfo":{"info_kind":"bridge","info_data":{"stp_state":0,"forward_delay":1500,"gc_timer":295.54}}}]`

func TestRuntimeLinkBracketBridgeGarbageCollectionTimer(t *testing.T) {
	for _, timer := range []string{"295.51", "0", "299.99"} {
		after := strings.Replace(runtimeBridgeLinkFixture, "295.54", timer, 1)
		if !runtimeLinkBracket([]byte(runtimeBridgeLinkFixture), []byte(after)) {
			t.Fatalf("operational bridge timer %s refused", timer)
		}
	}
}

func TestRuntimeLinkBracketKeepsLinkIdentityAndConfiguration(t *testing.T) {
	for _, pair := range [][2]string{
		{`"ifindex":4`, `"ifindex":5`},
		{`"docker0"`, `"docker1"`},
		{`"mtu":1500`, `"mtu":1400`},
		{`"operstate":"DOWN"`, `"operstate":"UP"`},
		{`"NO-CARRIER",`, ``},
		{`"stp_state":0`, `"stp_state":1`},
		{`"forward_delay":1500`, `"forward_delay":1000`},
		{`"info_kind":"bridge"`, `"info_kind":"veth"`},
		{`"gc_timer":295.54`, `"gc_timer":"295.51"`},
		{`"gc_timer":295.54`, `"gc_timer":null`},
		{`"gc_timer":295.54`, `"gc_timer":-1`},
		{`"gc_timer":295.54`, `"gc_timer":1e999`},
		{`,"gc_timer":295.54`, ``},
	} {
		after := strings.Replace(runtimeBridgeLinkFixture, pair[0], pair[1], 1)
		after = strings.Replace(after, "295.54", "295.51", 1)
		if runtimeLinkBracket([]byte(runtimeBridgeLinkFixture), []byte(after)) {
			t.Fatalf("unexpectedly accepted %s", pair[1])
		}
	}
	for _, kind := range []string{"veth", "xfrm", "wireguard"} {
		before := strings.Replace(runtimeBridgeLinkFixture, `"bridge"`, `"`+kind+`"`, 1)
		after := strings.Replace(before, "295.54", "295.51", 1)
		if runtimeLinkBracket([]byte(before), []byte(after)) {
			t.Fatalf("ignored timer on non-bridge %s", kind)
		}
	}
}
