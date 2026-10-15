package dnsforward

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"golang.org/x/net/dns/dnsmessage"
)

func fullLANProfile() ResolverProfile {
	p := lanProfileFixture()
	p.LANListener.DefaultUpstreams = []string{"8.8.8.8", "1.1.1.1"}
	return p
}

func publicDNSAnswer(query []byte) []byte {
	var p dnsmessage.Parser
	h, _ := p.Start(query)
	q, _ := p.Question()
	return answerA(h.ID, query, q, netip.MustParseAddr("93.184.216.34"))
}

func TestLANDefaultPrivatePrecedenceAndSourceIsolation(t *testing.T) {
	f := New(nil, nil)
	p := fullLANProfile()
	privateOnly := lanProfileFixture()
	privateOnly.Config.ProfileID = "99999999-9999-4999-8999-999999999999"
	privateOnly.ZoneSuffixes = []string{"finance.test"}
	privateOnly.StaticRecords = []StaticRecord{{"app.finance.test", "A", "10.50.0.1", 300}}
	privateOnly.LANListener.AllowedSources = []string{"192.168.2.0/24"}
	cloud := privateProfile()
	cloud.LANListener = p.LANListener
	f.SetResolverProfiles([]ResolverProfile{p, privateOnly, cloud})
	f.SetTable([]Entry{{Domain: "legacy.test", ResolverIP: "10.0.0.53"}})
	f.SetK8sAnswers(nil, []string{"k8s.test"})
	if err := f.SetVPNHost("vpn.test", "10.99.0.1"); err != nil {
		t.Fatal(err)
	}
	var exchanges atomic.Int32
	f.lanDefaultTransport = privateProfileTransport(func(_ context.Context, c fqdnrpc.ResolverConfig, e fqdnrpc.ResolverEndpoint, q []byte) ([]byte, error) {
		exchanges.Add(1)
		if c.IPsecPath != nil || e.Port != 53 || e.Address != "1.1.1.1" {
			t.Error("unexpected default upstream", c, e)
		}
		return publicDNSAnswer(q), nil
	})
	key := compileLANListener(*p.LANListener).key
	for _, transport := range []string{"udp", "tcp"} {
		for _, tc := range []struct {
			name, source string
			want         dnsmessage.RCode
			public       bool
		}{
			{"www.example.com.", "192.168.1.50", 0, true},
			{"www.example.com.", "192.168.2.50", dnsmessage.RCodeRefused, false},
			{"www.example.com.", "192.168.3.50", dnsmessage.RCodeRefused, false},
			{"app.office.test.", "192.168.1.50", 0, false},
			{"missing.office.test.", "192.168.1.50", dnsmessage.RCodeNameError, false},
			{"external.office.test.", "192.168.1.50", 0, false},
			{"app.finance.test.", "192.168.1.50", dnsmessage.RCodeRefused, false},
			{"app.finance.test.", "192.168.2.50", 0, false},
			{"app.legacy.test.", "192.168.1.50", dnsmessage.RCodeRefused, false},
			{"app.k8s.test.", "192.168.1.50", dnsmessage.RCodeRefused, false},
			{"vpn.test.", "192.168.1.50", dnsmessage.RCodeRefused, false},
			{"db.aws.private.test.", "192.168.1.50", dnsmessage.RCodeServerFailure, false},
		} {
			before := exchanges.Load()
			got := packetRCode(t, f.handleLAN(mkQuery(tc.name), netip.MustParseAddr(tc.source), transport, key))
			if got != tc.want {
				t.Fatalf("%s %s got %v want %v", transport, tc.name, got, tc.want)
			}
			if (exchanges.Load() > before) != tc.public {
				t.Fatalf("unexpected WAN exchange for %s %s", tc.name, tc.source)
			}
		}
	}
	before := exchanges.Load()
	if got := packetRCode(t, f.handle(mkQuery("www.example.com."), netip.MustParseAddr("10.99.0.7"))); got != dnsmessage.RCodeRefused || exchanges.Load() != before {
		t.Fatal("LAN public grant escaped to WireGuard")
	}
}

func TestLANDefaultRejectsUnsafeAndSelfUpstreams(t *testing.T) {
	for _, raw := range []string{"0.1.2.3", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1", "172.16.0.1", "192.0.0.9", "192.0.2.5", "192.88.99.1", "192.168.1.39", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255", "::ffff:8.8.8.8", "2606:4700:4700::1111", "8.8.8.8:53", "dns.example", " 8.8.8.8"} {
		if _, err := compileLANDefaultUpstreams([]string{raw}); err == "" {
			t.Error("accepted unsafe upstream", raw)
		}
	}
	for _, raw := range [][]string{{"1.1.1.1", "1.1.1.1"}, {"1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4"}} {
		if _, err := compileLANDefaultUpstreams(raw); err == "" {
			t.Error("accepted invalid set", raw)
		}
	}
	if got, err := compileLANDefaultUpstreams([]string{"8.8.8.8", "1.1.1.1"}); err != "" || !slices.Equal(got, []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}) {
		t.Fatal("public set rejected", got, err)
	}
	f := New(nil, nil)
	p := fullLANProfile()
	f.SetResolverProfiles([]ResolverProfile{p})
	key := compileLANListener(*p.LANListener).key
	f.lanLocalAddresses = func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("8.8.8.8"), Mask: net.CIDRMask(24, 32)}}, nil
	}
	if _, _, _, failure := f.lanDefaults(f.profiles.Load(), key); !strings.Contains(failure, "local interface") {
		t.Fatal("local public upstream accepted", failure)
	}
	f.lanLocalAddresses = func() ([]net.Addr, error) { return nil, errors.New("interface enumeration failed") }
	if _, _, _, failure := f.lanDefaults(f.profiles.Load(), key); failure == "" {
		t.Fatal("unknown self state accepted")
	}
}

func TestLANDefaultConflictIsVisibleAndPreservesPrivateDNS(t *testing.T) {
	f := New(nil, nil)
	defer f.closeOwnedBinds()
	a := fullLANProfile()
	b := lanProfileFixture()
	b.Config.ProfileID = "99999999-9999-4999-8999-999999999999"
	b.ZoneSuffixes = []string{"second.test"}
	b.StaticRecords = []StaticRecord{{"app.second.test", "A", "10.0.0.2", 300}}
	b.LANListener.DefaultUpstreams = []string{"9.9.9.9"}
	f.SetResolverProfiles([]ResolverProfile{a, b})
	f.lanOwned = func(lanBindKey) error { return nil }
	f.lanListenUDP = func(netip.Addr, string) (udpListener, error) { return newFakeListener(), nil }
	f.lanListenTCP = func(netip.Addr, string) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }
	f.lanDefaultTransport = privateProfileTransport(func(context.Context, fqdnrpc.ResolverConfig, fqdnrpc.ResolverEndpoint, []byte) ([]byte, error) {
		t.Error("conflict sent WAN query")
		return nil, errors.New("must not exchange")
	})
	f.reconcileLANBinds("wg0")
	state := f.AppliedLANListeners()
	if len(state) != 1 || state[0].Ready || !strings.Contains(state[0].Error, "conflicting") || len(f.lanListeners) != 1 {
		t.Fatal("conflict readiness incorrect", state)
	}
	key := compileLANListener(*a.LANListener).key
	source := netip.MustParseAddr("192.168.1.50")
	if packetRCode(t, f.handleLAN(mkQuery("www.example.com."), source, "udp", key)) != dnsmessage.RCodeServerFailure {
		t.Fatal("conflict did not fail closed")
	}
	if packetRCode(t, f.handleLAN(mkQuery("app.office.test."), source, "udp", key)) != 0 {
		t.Fatal("conflict broke private DNS")
	}
	b.LANListener.DefaultUpstreams = []string{"1.1.1.1", "8.8.8.8"}
	f.SetResolverProfiles([]ResolverProfile{a, b})
	f.reconcileLANBinds("wg0")
	if state = f.AppliedLANListeners(); len(state) != 1 || !state[0].Ready {
		t.Fatal("resolved conflict stayed unavailable", state)
	}
	b.LANListener.DefaultUpstreams = nil
	f.SetResolverProfiles([]ResolverProfile{a, b})
	if _, _, _, failure := f.lanDefaults(f.profiles.Load(), key); failure != "" {
		t.Fatal("private-only sibling conflicts", failure)
	}
}

func TestLANDefaultInflightWithdrawalAndChangesSuppressResponse(t *testing.T) {
	for _, mutation := range []string{"remove", "sources", "upstreams", "new-private-zone", "legacy-zone", "self-address"} {
		t.Run(mutation, func(t *testing.T) {
			f := New(nil, nil)
			p := fullLANProfile()
			f.SetResolverProfiles([]ResolverProfile{p})
			key := compileLANListener(*p.LANListener).key
			entered, release := make(chan struct{}), make(chan struct{})
			var self atomic.Bool
			f.lanLocalAddresses = func() ([]net.Addr, error) {
				if self.Load() {
					return []net.Addr{&net.IPNet{IP: net.ParseIP("1.1.1.1"), Mask: net.CIDRMask(32, 32)}}, nil
				}
				return nil, nil
			}
			f.lanDefaultTransport = privateProfileTransport(func(_ context.Context, _ fqdnrpc.ResolverConfig, _ fqdnrpc.ResolverEndpoint, query []byte) ([]byte, error) {
				close(entered)
				<-release
				return publicDNSAnswer(query), nil
			})
			result := make(chan []byte)
			go func() {
				result <- f.handleLAN(mkQuery("www.example.com."), netip.MustParseAddr("192.168.1.50"), "udp", key)
			}()
			<-entered
			switch mutation {
			case "remove":
				f.SetResolverProfiles(nil)
			case "sources":
				p.LANListener.AllowedSources = []string{"192.168.2.0/24"}
				f.SetResolverProfiles([]ResolverProfile{p})
			case "upstreams":
				p.LANListener.DefaultUpstreams = []string{"9.9.9.9"}
				f.SetResolverProfiles([]ResolverProfile{p})
			case "new-private-zone":
				p.ZoneSuffixes = []string{"example.com"}
				p.StaticRecords = []StaticRecord{{"www.example.com", "A", "10.1.1.1", 300}}
				f.SetResolverProfiles([]ResolverProfile{p})
			case "legacy-zone":
				f.SetTable([]Entry{{Domain: "example.com", ResolverIP: "10.0.0.53"}})
			case "self-address":
				self.Store(true)
			}
			close(release)
			if packetRCode(t, <-result) != dnsmessage.RCodeServerFailure {
				t.Fatal("stale public answer relayed", mutation)
			}
		})
	}
}

func TestLANDefaultTimeoutAndRateLimit(t *testing.T) {
	f := New(nil, nil)
	p := fullLANProfile()
	p.LANListener.DefaultUpstreams = []string{"1.1.1.1"}
	f.SetResolverProfiles([]ResolverProfile{p})
	key := compileLANListener(*p.LANListener).key
	f.lanDefaultTransport = privateProfileTransport(func(ctx context.Context, _ fqdnrpc.ResolverConfig, _ fqdnrpc.ResolverEndpoint, _ []byte) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	start := time.Now()
	if packetRCode(t, f.handleLAN(mkQuery("www.example.com."), netip.MustParseAddr("192.168.1.50"), "udp", key)) != dnsmessage.RCodeServerFailure || time.Since(start) > 2*time.Second {
		t.Fatal("default lookup exceeded bounded timeout")
	}
	var calls atomic.Int32
	f.lanDefaultTransport = privateProfileTransport(func(_ context.Context, _ fqdnrpc.ResolverConfig, _ fqdnrpc.ResolverEndpoint, query []byte) ([]byte, error) {
		calls.Add(1)
		return publicDNSAnswer(query), nil
	})
	f.now = func() time.Time { return start }
	source := netip.MustParseAddr("192.168.1.51")
	for i := 0; i < dnsRateBurst; i++ {
		f.handleLAN(mkQuery("www.example.com."), source, "udp", key)
	}
	if f.handleLAN(mkQuery("www.example.com."), source, "udp", key) != nil || calls.Load() != dnsRateBurst {
		t.Fatal("default forwarding bypassed rate limiter")
	}
}
