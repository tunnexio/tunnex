package bgp

import (
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestSummaryCapturedMaximumPrefixShutdown(t *testing.T) {
	c := fixture()
	c.MaximumPrefixes = 1
	c.Peers[0].Local = netip.MustParseAddr("169.254.84.1")
	c.Peers[1].Local = netip.MustParseAddr("169.254.84.5")
	c.Peers[0].Remote = netip.MustParseAddr("169.254.84.2")
	c.Peers[1].Remote = netip.MustParseAddr("169.254.84.6")
	raw, e := os.ReadFile("testdata/summary_maximum_prefix_shutdown.json")
	if e != nil {
		t.Fatal(e)
	}
	status, e := ParseSummary(raw, c)
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range status.Peers {
		if p.State != "idle" || p.AcceptedPrefixes != 0 || p.InstalledPrefixes != 0 {
			t.Fatal("shutdown acquired authority")
		}
	}
	for _, bad := range []string{strings.Replace(string(raw), "Idle (PfxCt)", "Idle (Admin)", 1), strings.Replace(string(raw), `"peerState": "PfxCt"`, `"peerState": "Idle"`, 1), strings.Replace(string(raw), `"peerState": "PfxCt",`, "", 1), strings.Replace(string(raw), `"pfxRcd": 0`, `"pfxRcd": 1`, 1), strings.Replace(string(raw), `"pfxRcd": 0`, `"pfxRcd": 2`, 1), strings.Replace(string(raw), "Idle (PfxCt)", "Established", 1)} {
		if _, e := ParseSummary([]byte(bad), c); e == nil {
			t.Fatal("inconsistent shutdown accepted")
		}
	}
}
func TestMaximumPrefixShutdownRoutesPreserveSurvivor(t *testing.T) {
	c := fixture()
	c.MaximumPrefixes = 1
	status, e := ParseSummary([]byte(`{"peers":{"169.254.20.2":{"state":"Idle (PfxCt)","peerState":"PfxCt","pfxRcd":0},"169.254.20.6":{"state":"Established","pfxRcd":1}}}`), c)
	if e != nil {
		t.Fatal(e)
	}
	raw := []byte(`{"routes":{"10.20.0.0/24":[{"network":"10.20.0.0/24","peerId":"169.254.20.2","valid":true,"bestpath":true},{"network":"10.20.0.0/24","peerId":"169.254.20.6","valid":true,"bestpath":true,"nexthops":[{"ip":"169.254.20.6","afi":"ipv4","used":true}]}]}}`)
	routes, e := ParseRoutes(raw, c, status)
	if e != nil || len(routes) != 1 || routes[0].Slot != 2 {
		t.Fatal(routes, e)
	}
	status.Peers[1] = PeerStatus{Slot: 2, State: "idle"}
	routes, e = ParseRoutes(raw, c, status)
	if e != nil || len(routes) != 0 {
		t.Fatal(routes, e)
	}
}
