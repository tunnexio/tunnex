package originpolicy

import (
	"net/netip"
	"strings"
	"testing"
)

func TestDestinations(t *testing.T) {
	p, e := Normalize([]string{"10.1.2.3/16", "10.1.0.0/16"}, "")
	if e != nil || len(p.AllowedDestinationCIDRs) != 1 || p.AllowedDestinationCIDRs[0] != "10.1.0.0/16" {
		t.Fatal(p, e)
	}
	for _, ip := range []string{"10.1.2.3", "::ffff:10.1.2.3"} {
		if p.Validate(netip.MustParseAddr(ip), nil) != nil {
			t.Fatal(ip)
		}
	}
	for _, ip := range []string{"127.0.0.1", "::ffff:127.0.0.1", "169.254.169.254", "fd00:ec2::254", "168.63.129.16", "10.2.3.4", "8.8.8.8", "::1", "fe80::1", "100.64.0.1", "2002:7f00:1::", "3fff::1", "2001:2::1", "2001:10::1", "192.88.99.1"} {
		if p.Validate(netip.MustParseAddr(ip), nil) == nil {
			t.Fatal("allowed", ip)
		}
	}
	if p.Validate(netip.MustParseAddr("10.1.2.3"), []netip.Addr{netip.MustParseAddr("10.1.2.3")}) == nil {
		t.Fatal("control target")
	}
	public, _ := Normalize(nil, "")
	if public.Validate(netip.MustParseAddr("8.8.8.8"), nil) != nil || public.Validate(netip.MustParseAddr("10.1.2.3"), nil) == nil {
		t.Fatal("public default")
	}
}
func TestMalformedPolicies(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "::/0", "172.0.0.0/8", "127.0.0.0/8", "::ffff:10.1.0.0/112", "fd00:ec2::/32", "3fff::/20", "2001:2::/48", "192.88.99.0/24"} {
		if _, e := Normalize([]string{cidr}, ""); e == nil {
			t.Fatal(cidr)
		}
	}
	for _, ca := range []string{"garbage", "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----", strings.Repeat("a", 32769)} {
		if _, e := Normalize(nil, ca); e == nil {
			t.Fatal("bad CA accepted")
		}
	}
}
