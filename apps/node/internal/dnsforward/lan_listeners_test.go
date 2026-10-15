package dnsforward

import (
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func lanProfileFixture() ResolverProfile {
	p := staticProfileFixture()
	p.LANListener = &LANListener{Address: "192.168.1.39", Interface: "eth0", AllowedSources: []string{"192.168.1.0/24"}}
	return p
}
func TestLANProfileScopeSourceAndWGGrantSeparation(t *testing.T) {
	f := New(nil, func(netip.Addr, []byte) ([]byte, error) {
		t.Fatal("LAN leaked query to legacy forwarding")
		return nil, nil
	})
	p := lanProfileFixture()
	f.SetTable([]Entry{{Domain: "foreign.test", ResolverIP: "10.0.0.53"}})
	f.SetK8sAnswers([]K8sEntry{{FQDN: "app.k8s.test", VIP: "100.64.0.2"}}, []string{"k8s.test"})
	f.SetResolverProfiles([]ResolverProfile{p})
	key := compileLANListener(*p.LANListener).key
	source := netip.MustParseAddr("192.168.1.50")
	for _, transport := range []string{"udp", "tcp"} {
		if packetRCode(t, f.handleLAN(mkQuery("app.office.test."), source, transport, key)) != 0 {
			t.Fatal("approved LAN denied")
		}
		for _, name := range []string{"public.example.", "app.foreign.test.", "app.k8s.test."} {
			if packetRCode(t, f.handleLAN(mkQuery(name), source, transport, key)) != dnsmessage.RCodeRefused {
				t.Fatal("LAN escaped profile scope", name)
			}
		}
		if packetRCode(t, f.handleLAN(mkQuery("app.office.test."), netip.MustParseAddr("192.168.2.5"), transport, key)) != dnsmessage.RCodeRefused {
			t.Fatal("outside LAN source allowed")
		}
	}
	if packetRCode(t, f.handle(mkQuery("app.office.test."), source)) != dnsmessage.RCodeRefused {
		t.Fatal("LAN allowed_sources leaked to WG")
	}
	specific := p
	specific.ZoneSuffixes = []string{"app.office.test"}
	specific.Config.ProfileID = "99999999-9999-4999-8999-999999999999"
	specific.StaticRecords = p.StaticRecords[:2]
	specific.LANListener = nil
	f.SetResolverProfiles([]ResolverProfile{p, specific})
	if packetRCode(t, f.handleLAN(mkQuery("app.office.test."), source, "udp", key)) != dnsmessage.RCodeRefused {
		t.Fatal("less-specific LAN profile bypassed selected zone")
	}
	f.SetResolverProfiles(nil)
	if packetRCode(t, f.handleLAN(mkQuery("app.office.test."), source, "udp", key)) != dnsmessage.RCodeRefused {
		t.Fatal("withdrawn profile remained available")
	}
}
func TestLANBindingsCoalesceConflictOwnershipAndWithdrawal(t *testing.T) {
	f := New(nil, nil)
	defer f.closeOwnedBinds()
	p := lanProfileFixture()
	q := p
	q.Config.ProfileID = "99999999-9999-4999-8999-999999999999"
	q.ZoneSuffixes = []string{"second.test"}
	q.StaticRecords = []StaticRecord{{"app.second.test", "A", "10.0.0.2", 300}}
	f.SetResolverProfiles([]ResolverProfile{p, q})
	owned := true
	f.lanOwned = func(lanBindKey) error {
		if !owned {
			return errors.New("address withdrawn")
		}
		return nil
	}
	opens := 0
	var udp *fakeListener
	f.lanListenUDP = func(netip.Addr, string) (udpListener, error) { opens++; udp = newFakeListener(); return udp, nil }
	f.lanListenTCP = func(netip.Addr, string) (net.Listener, error) { return nil, errors.New("existing host DNS") }
	f.reconcileLANBinds("wg0")
	if len(f.lanListeners) != 0 || !udp.closed.Load() || len(f.AppliedLANListeners()) != 1 || !strings.Contains(f.AppliedLANListeners()[0].Error, "TCP") {
		t.Fatal("partial port bind reported ready")
	}
	f.lanListenTCP = func(netip.Addr, string) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }
	f.reconcileLANBinds("wg0")
	f.reconcileLANBinds("wg0")
	if len(f.lanListeners) != 1 || opens != 2 || !f.AppliedLANListeners()[0].Ready {
		t.Fatal("same scope was not coalesced")
	}
	if len(f.AppliedK8sState().Listeners) != 0 {
		t.Fatal("LAN bind falsely reported K8s/WG ownership")
	}
	owned = false
	f.reconcileLANBinds("wg0")
	if len(f.lanListeners) != 0 || !udp.closed.Load() {
		t.Fatal("lost LAN ownership retained listeners")
	}
	owned = true
	f.reconcileLANBinds("wg0")
	f.SetResolverProfiles(nil)
	f.reconcileLANBinds("wg0")
	if len(f.lanListeners) != 0 || !udp.closed.Load() || len(f.AppliedLANListeners()) != 0 {
		t.Fatal("profile deletion retained bind")
	}
}
func TestLANListenerValidationRejectsBroadOrUnownedScopes(t *testing.T) {
	good := *lanProfileFixture().LANListener
	for _, mutate := range []func(*LANListener){func(p *LANListener) { p.Address = "0.0.0.0" }, func(p *LANListener) { p.Address = "8.8.8.8" }, func(p *LANListener) { p.Interface = "" }, func(p *LANListener) { p.AllowedSources = nil }, func(p *LANListener) { p.AllowedSources = []string{"0.0.0.0/0"} }, func(p *LANListener) { p.AllowedSources = []string{"192.168.0.0/8"} }, func(p *LANListener) { p.AllowedSources = []string{"192.168.1.1/24"} }} {
		p := good
		mutate(&p)
		if compileLANListener(p) != nil {
			t.Fatal("unsafe listener accepted", p)
		}
	}
	if err := ownedLANAddress(lanBindKey{netip.MustParseAddr("192.168.1.39"), "tnx-missing"}); err == nil {
		t.Fatal("missing interface owned address")
	}
}

func TestLANSharedSocketKeepsSiblingProfileSourceScopes(t *testing.T) {
	f := New(nil, nil)
	a := lanProfileFixture()
	b := a
	b.Config.ProfileID = "99999999-9999-4999-8999-999999999999"
	b.ZoneSuffixes = []string{"finance.test"}
	b.StaticRecords = []StaticRecord{{"app.finance.test", "A", "10.50.0.1", 300}}
	listener := *a.LANListener
	listener.AllowedSources = []string{"192.168.2.0/24"}
	b.LANListener = &listener
	f.SetResolverProfiles([]ResolverProfile{a, b})
	key := compileLANListener(*a.LANListener).key
	for _, tc := range []struct {
		name, source string
		want         dnsmessage.RCode
	}{{"app.office.test.", "192.168.1.5", 0}, {"app.finance.test.", "192.168.1.5", dnsmessage.RCodeRefused}, {"app.finance.test.", "192.168.2.5", 0}, {"app.office.test.", "192.168.2.5", dnsmessage.RCodeRefused}} {
		if got := packetRCode(t, f.handleLAN(mkQuery(tc.name), netip.MustParseAddr(tc.source), "udp", key)); got != tc.want {
			t.Fatal("sibling profile permission escaped", tc, got)
		}
	}
}
