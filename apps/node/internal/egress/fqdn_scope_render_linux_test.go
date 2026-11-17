//go:build linux

package egress

import (
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
	"testing"
)

func TestFQDNIdentityAndResolverScopeDoNotChangePacketTuple(t *testing.T) {
	base := nodepolicy.AllowEntry{SrcIP: "10.99.0.7", DstCIDR: "10.20.0.9/32", Protocol: "tcp", PortLow: 443, PortHigh: 443}
	tagged := base
	tagged.FQDNDeviceID = "11111111-1111-1111-1111-111111111111"
	tagged.DNSResolverProfileID = "22222222-2222-2222-2222-222222222222"
	ordinary, ok := renderAllow(base)
	scoped, scopedOK := renderAllow(tagged)
	if !ok || !scopedOK || ordinary != scoped {
		t.Fatal("scope identity leaked into L3/L4 accept semantics")
	}
	base.FQDNManaged = true
	tagged.FQDNManaged = true
	ordinary, ok = renderFQDNManagedAllow(base, 0, false)
	scoped, scopedOK = renderFQDNManagedAllow(tagged, 0, false)
	if !ok || !scopedOK || ordinary != scoped {
		t.Fatal("scope identity changed FQDN conntrack-mark enforcement")
	}
}
