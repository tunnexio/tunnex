package ipsec

import (
	"encoding/json"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// A subnet-valued original CT address needs an IPv4 type during JSON input.
// The untyped form accepted by nft can silently install a different host match.
func TestGuardRelatedIPv4DestinationPrefixTyped(t *testing.T) {
	for _, destination := range []string{"10.20.0.0/24", "10.20.0.1/32"} {
		t.Run(destination, func(t *testing.T) {
			c := guardFixture().Connections[0]
			g := c.Grants[0]
			g.Source = netip.MustParsePrefix("10.10.0.1/32")
			g.Destination = netip.MustParsePrefix(destination)
			rule := guardRemoteFragmentNeeded(c, g, 10, 2, c.Remote[0])
			match := rule.expr[10].(map[string]any)["match"].(map[string]any)
			key := "ip daddr"
			var right any = guardPrefixJSON(g.Destination)
			if g.Destination.Bits() == 32 {
				key = "daddr"
				right = g.Destination.Addr().String()
			}
			if !reflect.DeepEqual(match["left"], guardOriginalCT(key, "")) || !reflect.DeepEqual(match["right"], right) {
				encoded, _ := json.Marshal(match)
				t.Fatalf("original destination lost its IPv4 address type: %s", encoded)
			}
		})
	}
}

func TestGuardRelatedIPv4SubnetCapturedNativeExpression(t *testing.T) {
	// Captured with nft 1.1.6 from the same immutable image as the gateway:
	// sha256:11bd0e4852749c609ed8d1896af65ea86cb1647e73be93b7bb0ed99f87873aea.
	// The isolated native roundtrip retained the exact /24 only with ip daddr.
	raw, err := os.ReadFile("testdata/nft_related_icmp_prefix_native_expression.json")
	if err != nil {
		t.Fatal(err)
	}
	c := guardFixture().Connections[0]
	g := c.Grants[0]
	g.Source = netip.MustParsePrefix("10.99.0.2/32")
	g.Destination = netip.MustParsePrefix("10.182.10.0/24")
	rule := guardRemoteFragmentNeeded(c, g, 10, 13, netip.MustParsePrefix("10.182.0.0/16"))
	encoded, _ := json.Marshal(rule.expr[4:12])
	var want, got any
	if json.Unmarshal(raw, &want) != nil || json.Unmarshal(encoded, &got) != nil || !reflect.DeepEqual(want, got) {
		t.Fatal("subnet parent expression differs from captured native grammar")
	}
}

func TestGuardDesktopSubnetParentReadbackRejectsChangedPredicate(t *testing.T) {
	in := guardFixture()
	c := &in.Connections[0]
	c.Remote = []netip.Prefix{netip.MustParsePrefix("10.182.0.0/16")}
	c.ReplyIngressIndices = []int{10}
	d := desktopGrantFixture()
	c.Grants = []GuardGrant{{Source: netip.MustParsePrefix("10.99.0.2/32"), Destination: netip.MustParsePrefix("10.182.10.0/24"), Protocol: GuardTCP, PortLow: 443, PortHigh: 443, DesktopDeviceID: uuid.MustParse(d.DeviceID), DesktopPublicKey: d.PublicKey, DesktopIngressIndex: 7}}
	m, err := RenderGuard(in)
	if err != nil {
		t.Fatal(err)
	}
	parent := `{"match":{"left":{"ct":{"dir":"original","key":"ip daddr"}},"op":"==","right":{"prefix":{"addr":"10.182.10.0","len":24}}}}`
	if strings.Count(m.ExpectedJSON, parent) != 1 || strings.Count(m.NFTJSON, parent) != 1 {
		t.Fatal("exact typed subnet parent was not emitted")
	}
	if VerifyGuardReadback([]byte(m.ExpectedJSON), []byte(m.ExpectedJSON)) != nil || VerifyGuardWithdrawal([]byte(m.ExpectedJSON), []byte(m.ExpectedJSON), nil) != nil {
		t.Fatal("correct typed subnet refused")
	}
	for name, changed := range map[string]string{
		"wrong-native-host":   strings.Replace(parent, `{"prefix":{"addr":"10.182.10.0","len":24}}`, `"0.10.182.10"`, 1),
		"legacy-wrong-native": strings.Replace(strings.Replace(parent, `{"prefix":{"addr":"10.182.10.0","len":24}}`, `"0.10.182.10"`, 1), `"ip daddr"`, `"daddr"`, 1),
		"untyped":             strings.Replace(parent, `"ip daddr"`, `"daddr"`, 1),
		"widened":             strings.Replace(parent, `"len":24`, `"len":16`, 1),
		"other-subnet":        strings.Replace(parent, `10.182.10.0`, `10.182.20.0`, 1),
		"ipv6":                strings.Replace(parent, `"ip daddr"`, `"ip6 daddr"`, 1),
		"reply":               strings.Replace(parent, `"original"`, `"reply"`, 1),
		"negated":             strings.Replace(parent, `"=="`, `"!="`, 1),
		"malformed":           strings.Replace(parent, `"len":24`, `"len":"24"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			observed := strings.Replace(m.ExpectedJSON, parent, changed, 1)
			if VerifyGuardReadback([]byte(m.ExpectedJSON), []byte(observed)) == nil || VerifyGuardWithdrawal([]byte(m.ExpectedJSON), []byte(observed), nil) == nil {
				t.Fatal("changed parent predicate accepted")
			}
		})
	}
}
