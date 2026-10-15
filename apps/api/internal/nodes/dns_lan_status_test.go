package nodes

import "testing"

func TestDNSLANListenerStatusIsBoundedObservation(t *testing.T) {
	good := DNSLANListenerState{Address: "192.168.1.39", Interface: "eth0", Ready: true, ProfileIDs: []string{"11111111-1111-4111-8111-111111111111"}}
	if got := boundedDNSLANListenerStates([]DNSLANListenerState{good}); len(got) != 1 || !got[0].Ready {
		t.Fatal("valid local socket observation lost")
	}
	bad := good
	bad.Error = "port occupied\n"
	got := boundedDNSLANListenerStates([]DNSLANListenerState{bad})
	if len(got) != 1 || got[0].Ready || got[0].Error != "port occupied" {
		t.Fatal("contradictory status falsely ready", got)
	}
	for _, mutate := range []func(*DNSLANListenerState){func(p *DNSLANListenerState) { p.Address = "0.0.0.0" }, func(p *DNSLANListenerState) { p.Interface = "bad\ninterface" }, func(p *DNSLANListenerState) { p.ProfileIDs = []string{"untrusted"} }} {
		bad := good
		mutate(&bad)
		if len(boundedDNSLANListenerStates([]DNSLANListenerState{bad})) != 0 {
			t.Fatal("unbounded status persisted")
		}
	}
}
