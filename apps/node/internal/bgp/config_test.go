package bgp

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func fixture() Config {
	return Config{LocalASN: 65000, RemoteASN: 7224, RouterID: netip.MustParseAddr("10.10.0.1"), MaximumPrefixes: 64, LocalPrefixes: []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")}, RemotePrefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, Peers: [2]Peer{{Slot: 1, Local: netip.MustParseAddr("169.254.20.1"), Remote: netip.MustParseAddr("169.254.20.2")}, {Slot: 2, Local: netip.MustParseAddr("169.254.20.5"), Remote: netip.MustParseAddr("169.254.20.6")}}}
}
func TestConfigBoundedDeterministic(t *testing.T) {
	c := fixture()
	first, e := RenderConfig(c)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 50; i++ {
		next, e := RenderConfig(c)
		if e != nil || next != first {
			t.Fatal("unstable config")
		}
	}
	for _, s := range []string{"neighbor 169.254.20.2 update-source 169.254.20.1", "ip prefix-list TNX-IN seq 10 permit 10.20.0.0/24", "network 10.10.0.0/24"} {
		if !strings.Contains(first, s) {
			t.Fatal("required bounded config missing", s)
		}
	}
	if strings.Contains(first, "redistribute") {
		t.Fatal("unapproved redistribution")
	}
	c.RemotePrefixes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	if _, e = RenderConfig(c); e == nil {
		t.Fatal("default import accepted")
	}
}
func TestSummaryHonestBoundedStates(t *testing.T) {
	c := fixture()
	raw := []byte(`{"ipv4Unicast":{"peers":{"169.254.20.2":{"state":"Established","pfxRcd":1},"169.254.20.6":{"state":"Active","pfxRcd":0}}}}`)
	out, e := ParseSummary(raw, c)
	if e != nil || out.Peers[0].State != "established" || out.Peers[1].State != "active" || out.Peers[0].InstalledPrefixes != 0 || out.Peers[0].RejectedPrefixes != nil {
		t.Fatal("invented route/status authority", e)
	}
	var doc map[string]any
	json.Unmarshal(raw, &doc)
	for _, bad := range []string{strings.Replace(string(raw), "Active", "Magic", 1), strings.Replace(string(raw), `"pfxRcd":1`, `"pfxRcd":null`, 1), strings.Replace(string(raw), `,"pfxRcd":1`, ``, 1), strings.Replace(string(raw), `"pfxRcd":1`, `"pfxRcd":65`, 1), strings.Replace(string(raw), "169.254.20.6", "169.254.99.2", 1)} {
		if _, e := ParseSummary([]byte(bad), c); e == nil {
			t.Fatal("unbounded/foreign observer accepted")
		}
	}
}
