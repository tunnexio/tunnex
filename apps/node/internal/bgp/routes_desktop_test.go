package bgp

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRIBDesktopExportsBeforeRemoteRoutesArrive(t *testing.T) {
	c := fixture()
	c.LocalPrefixes = []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	c.RemotePrefixes = []netip.Prefix{netip.MustParsePrefix("10.180.0.0/16")}
	c.DesktopPrefixes = []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32"), netip.MustParsePrefix("10.99.0.3/32")}
	status := Status{Peers: [2]PeerStatus{{Slot: 1, State: "active"}, {Slot: 2, State: "active"}}}
	// This is the local-only startup RIB observed on the affected gateway.
	// Refusing it restarts FRR before the AWS neighbors can advertise a route.
	raw := `{"routes":{
		"192.168.1.0/24":[{"valid":true,"network":"192.168.1.0/24","peerId":"(unspec)"}],
		"10.99.0.2/32":[{"valid":true,"network":"10.99.0.2/32","peerId":"(unspec)"}],
		"10.99.0.3/32":[{"valid":true,"network":"10.99.0.3/32","peerId":"(unspec)"}]
	}}`
	if routes, err := ParseRoutes([]byte(raw), c, status); err != nil || len(routes) != 0 {
		t.Fatalf("known local exports refused before remote convergence: routes=%v err=%v", routes, err)
	}
}

func TestRIBAcceptsOnlyCurrentLocalDesktopExports(t *testing.T) {
	c := fixture()
	c.DesktopPrefixes = []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32"), netip.MustParsePrefix("10.99.0.3/32")}
	status := Status{Peers: [2]PeerStatus{{Slot: 1, State: "established", AcceptedPrefixes: 1}, {Slot: 2, State: "active"}}}
	// FRR includes its locally originated desktop networks in the same RIB as
	// the office export and received AWS route. Only the received route is an
	// import candidate; the host exports must not count toward peer prefixes.
	raw := `{"routes":{
		"10.10.0.0/24":[{"valid":true,"bestpath":true,"network":"10.10.0.0/24","peerId":"(unspec)"}],
		"10.99.0.2/32":[{"valid":true,"bestpath":true,"network":"10.99.0.2/32","peerId":"(unspec)"}],
		"10.99.0.3/32":[{"valid":true,"bestpath":true,"network":"10.99.0.3/32","peerId":"(unspec)"}],
		"10.20.0.0/24":[{"valid":true,"bestpath":true,"network":"10.20.0.0/24","peerId":"169.254.20.2","nexthops":[{"ip":"169.254.20.2","afi":"ipv4","used":true}]}]
	}}`
	routes, err := ParseRoutes([]byte(raw), c, status)
	if err != nil || len(routes) != 1 || routes[0].Prefix != c.RemotePrefixes[0] || routes[0].Slot != 1 {
		t.Fatalf("authorized local desktop exports rejected or imported: routes=%v err=%v", routes, err)
	}
	for name, bad := range map[string]string{
		"unknown desktop":         strings.ReplaceAll(raw, "10.99.0.3/32", "10.99.0.4/32"),
		"broad desktop":           strings.ReplaceAll(raw, "10.99.0.3/32", "10.99.0.0/24"),
		"peer-originated desktop": strings.Replace(raw, `"network":"10.99.0.3/32","peerId":"(unspec)"`, `"network":"10.99.0.3/32","peerId":"169.254.20.2"`, 1),
		"default import":          strings.ReplaceAll(raw, "10.20.0.0/24", "0.0.0.0/0"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRoutes([]byte(bad), c, status); err == nil {
				t.Fatal("unapproved RIB accepted")
			}
		})
	}
	// Withdrawal must remove authority immediately even if FRR still reports
	// the old network while its process is being replaced.
	c.DesktopPrefixes = c.DesktopPrefixes[:1]
	if _, err := ParseRoutes([]byte(raw), c, status); err == nil {
		t.Fatal("withdrawn desktop export accepted")
	}
}
