package dnsforward

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"golang.org/x/net/dns/dnsmessage"
)

func externalProfileFixture() ResolverProfile {
	p := lanProfileFixture()
	p.Config.Endpoints = []fqdnrpc.ResolverEndpoint{{Address: "1.1.1.1", Port: 53, Transport: "udp"}}
	return p
}
func targetAnswer(query []byte, records ...dnsmessage.Resource) []byte {
	var m dnsmessage.Message
	if m.Unpack(query) != nil {
		panic("invalid test query")
	}
	m.Response = true
	m.RecursionAvailable = true
	m.Answers = records
	raw, err := m.Pack()
	if err != nil {
		panic(err)
	}
	return raw
}
func addressRecord(name string, kind dnsmessage.Type, ttl uint32) dnsmessage.Resource {
	h := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Class: dnsmessage.ClassINET, Type: kind, TTL: ttl}
	if kind == dnsmessage.TypeAAAA {
		return dnsmessage.Resource{Header: h, Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("fd00::229").As16()}}
	}
	return dnsmessage.Resource{Header: h, Body: &dnsmessage.AResource{A: [4]byte{10, 180, 10, 229}}}
}
func TestStaticExternalCNAMECompletesAuthorizedLANAndWG(t *testing.T) {
	for _, transport := range []string{"udp", "tcp"} {
		for _, lan := range []bool{false, true} {
			for _, kind := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
				f := New(nil, nil)
				p := externalProfileFixture()
				f.SetResolverProfiles([]ResolverProfile{p})
				calls := 0
				f.staticTargetTransport = privateProfileTransport(func(_ context.Context, c fqdnrpc.ResolverConfig, e fqdnrpc.ResolverEndpoint, wire []byte) ([]byte, error) {
					calls++
					q := decodeDNS(t, wire).Questions[0]
					if q.Name.String() != "internal.lb.example." || c.IPsecPath != nil || e.Address != "1.1.1.1" || e.Port != 53 {
						t.Fatal("wrong target authority", q, e)
					}
					return targetAnswer(wire, addressRecord(q.Name.String(), q.Type, 57)), nil
				})
				wire := queryType("external.office.test.", kind)
				var response []byte
				if lan {
					response = f.handleLAN(wire, netip.MustParseAddr("192.168.1.50"), transport, compileLANListener(*p.LANListener).key)
				} else {
					response = f.handleTransport(wire, netip.MustParseAddr("10.99.0.7"), transport)
				}
				m := decodeDNS(t, response)
				if m.RCode != 0 || len(m.Answers) != 2 || calls != 1 || m.Answers[1].Header.TTL != 57 || m.Answers[1].Header.Type != kind {
					t.Fatalf("completion failed lan%v transport%s kind%v: %+v calls%d", lan, transport, kind, m, calls)
				}
			}
		}
	}
}

func cnameRecord(name, target string, ttl uint32) dnsmessage.Resource {
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: ttl}, Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target)}}
}
func TestStaticExternalCNAMECloudNamesAndConnectedAnswers(t *testing.T) {
	for _, target := range []string{"internal-app-123.eu-north-1.elb.amazonaws.com.", "app.privatelink.azurewebsites.net.", "app.us-central1.run.app."} {
		f := New(nil, nil)
		p := externalProfileFixture()
		p.StaticRecords = []StaticRecord{{"cloud.office.test", "CNAME", target, 300}}
		f.SetResolverProfiles([]ResolverProfile{p})
		calls := 0
		f.staticTargetTransport = privateProfileTransport(func(_ context.Context, _ fqdnrpc.ResolverConfig, _ fqdnrpc.ResolverEndpoint, wire []byte) ([]byte, error) {
			calls++
			question := decodeDNS(t, wire).Questions[0]
			if calls == 1 {
				return targetAnswer(wire, cnameRecord(question.Name.String(), "terminal.public.example.", 70), addressRecord("unrelated.example.", question.Type, 10)), nil
			}
			return targetAnswer(wire, addressRecord("terminal.public.example.", question.Type, 41), addressRecord("unrelated.example.", question.Type, 10)), nil
		})
		m := decodeDNS(t, f.handle(mkQuery("cloud.office.test."), netip.MustParseAddr("10.99.0.7")))
		if m.RCode != 0 || len(m.Answers) != 3 || calls != 2 || m.Answers[0].Header.TTL != 300 || m.Answers[1].Header.TTL != 70 || m.Answers[2].Header.TTL != 41 || m.Authoritative {
			t.Fatalf("chain not connected/TTL lost: %+v calls%d", m, calls)
		}
	}
}
func TestStaticExternalCNAMEAuthorizationAndPrivateBarriers(t *testing.T) {
	for _, scenario := range []string{"no-endpoints", "cname-query", "local-A", "unauthorized-WG", "unauthorized-LAN", "arbitrary-name", "same-private-zone", "other-profile", "legacy-zone", "k8s-zone", "vpn-host"} {
		t.Run(scenario, func(t *testing.T) {
			f := New(nil, nil)
			p := externalProfileFixture()
			name := "external.office.test."
			kind := dnsmessage.TypeA
			source := netip.MustParseAddr("10.99.0.7")
			want := dnsmessage.RCodeSuccess
			switch scenario {
			case "no-endpoints":
				p.Config.Endpoints = nil
			case "cname-query":
				kind = dnsmessage.TypeCNAME
			case "local-A":
				name = "app.office.test."
			case "unauthorized-WG":
				source = netip.MustParseAddr("10.99.0.8")
				want = dnsmessage.RCodeRefused
			case "unauthorized-LAN":
				source = netip.MustParseAddr("192.168.2.50")
				want = dnsmessage.RCodeRefused
			case "arbitrary-name":
				name = "internal.lb.example."
				want = dnsmessage.RCodeRefused
			default:
				p.StaticRecords = []StaticRecord{{"external.office.test", "CNAME", "hidden.private.test", 300}}
				want = dnsmessage.RCodeServerFailure
				switch scenario {
				case "same-private-zone":
					p.StaticRecords[0].Value = "missing.office.test"
				case "legacy-zone":
					f.SetTable([]Entry{{Domain: "private.test", ResolverIP: "10.0.0.53"}})
				case "k8s-zone":
					f.SetK8sAnswers(nil, []string{"private.test"})
				case "vpn-host":
					if err := f.SetVPNHost("hidden.private.test", "10.99.0.1"); err != nil {
						t.Fatal(err)
					}
				}
			}
			profiles := []ResolverProfile{p}
			if scenario == "other-profile" {
				other := staticProfileFixture()
				other.Config.ProfileID = "99999999-9999-4999-8999-999999999999"
				other.ZoneSuffixes = []string{"private.test"}
				other.StaticRecords = []StaticRecord{{"hidden.private.test", "A", "10.0.0.9", 300}}
				profiles = append(profiles, other)
			}
			f.SetResolverProfiles(profiles)
			f.staticTargetTransport = privateProfileTransport(func(context.Context, fqdnrpc.ResolverConfig, fqdnrpc.ResolverEndpoint, []byte) ([]byte, error) {
				t.Fatal("unauthorized or private name escaped to public DNS")
				return nil, nil
			})
			var response []byte
			if scenario == "unauthorized-LAN" {
				response = f.handleLAN(queryType(name, kind), source, "udp", compileLANListener(*p.LANListener).key)
			} else {
				response = f.handle(queryType(name, kind), source)
			}
			if code := packetRCode(t, response); code != want {
				t.Fatalf("code%v want%v", code, want)
			}
		})
	}
}
func TestStaticExternalCNAMERefusesMalformedLoopAndPrivateHop(t *testing.T) {
	for _, scenario := range []string{"id", "question", "malformed", "tcp-truncated", "cycle", "duplicate-cname", "coexist", "private-hop", "private-terminal", "too-deep", "class", "too-many-addresses"} {
		t.Run(scenario, func(t *testing.T) {
			f := New(nil, nil)
			p := externalProfileFixture()
			f.SetResolverProfiles([]ResolverProfile{p})
			calls := 0
			f.staticTargetTransport = privateProfileTransport(func(_ context.Context, _ fqdnrpc.ResolverConfig, _ fqdnrpc.ResolverEndpoint, wire []byte) ([]byte, error) {
				calls++
				q := decodeDNS(t, wire).Questions[0]
				raw := targetAnswer(wire, addressRecord(q.Name.String(), q.Type, 50))
				m := decodeDNS(t, raw)
				switch scenario {
				case "id":
					m.ID++
				case "question":
					m.Questions[0].Name = dnsmessage.MustNewName("other.example.")
				case "malformed":
					return []byte{1, 2, 3}, nil
				case "tcp-truncated":
					m.Truncated = true
				case "cycle":
					m.Answers = []dnsmessage.Resource{cnameRecord(q.Name.String(), q.Name.String(), 50)}
				case "duplicate-cname":
					a := cnameRecord(q.Name.String(), "next.public.test.", 50)
					m.Answers = []dnsmessage.Resource{a, a}
				case "coexist":
					m.Answers = append(m.Answers, cnameRecord(q.Name.String(), "next.public.test.", 50))
				case "private-hop":
					m.Answers = []dnsmessage.Resource{cnameRecord(q.Name.String(), "hidden.office.test.", 50)}
				case "private-terminal":
					m.Answers = []dnsmessage.Resource{cnameRecord(q.Name.String(), "hidden.office.test.", 50), addressRecord("hidden.office.test.", q.Type, 50)}
				case "too-deep":
					m.Answers = []dnsmessage.Resource{cnameRecord(q.Name.String(), fmt.Sprintf("step%d.public.test.", calls), 50)}
				case "class":
					m.Answers[0].Header.Class = dnsmessage.ClassCHAOS
				case "too-many-addresses":
					for i := 0; i < 33; i++ {
						m.Answers = append(m.Answers, m.Answers[0])
					}
				}
				raw, err := m.Pack()
				return raw, err
			})
			if code := packetRCode(t, f.handle(mkQuery("external.office.test."), netip.MustParseAddr("10.99.0.7"))); code != dnsmessage.RCodeServerFailure {
				t.Fatalf("invalid response accepted: %v", code)
			}
			if calls > 8 {
				t.Fatal("chain unbounded", calls)
			}
		})
	}
}
func TestStaticExternalCNAMENegativeAnswersAndTimeout(t *testing.T) {
	for _, scenario := range []string{"nxdomain", "nodata", "timeout"} {
		t.Run(scenario, func(t *testing.T) {
			f := New(nil, nil)
			p := externalProfileFixture()
			f.SetResolverProfiles([]ResolverProfile{p})
			f.staticTargetTransport = privateProfileTransport(func(ctx context.Context, _ fqdnrpc.ResolverConfig, _ fqdnrpc.ResolverEndpoint, wire []byte) ([]byte, error) {
				if scenario == "timeout" {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				m := decodeDNS(t, targetAnswer(wire))
				if scenario == "nxdomain" {
					m.RCode = dnsmessage.RCodeNameError
				}
				m.Authorities = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("example."), Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: 63}, Body: &dnsmessage.SOAResource{NS: dnsmessage.MustNewName("ns.example."), MBox: dnsmessage.MustNewName("hostmaster.example."), MinTTL: 31}}}
				raw, err := m.Pack()
				return raw, err
			})
			start := time.Now()
			m := decodeDNS(t, f.handle(mkQuery("external.office.test."), netip.MustParseAddr("10.99.0.7")))
			if scenario == "timeout" {
				if m.RCode != dnsmessage.RCodeServerFailure || time.Since(start) > 2500*time.Millisecond {
					t.Fatal("timeout not bounded", m)
				}
				return
			}
			want := dnsmessage.RCodeSuccess
			if scenario == "nxdomain" {
				want = dnsmessage.RCodeNameError
			}
			if m.RCode != want || len(m.Answers) != 1 || len(m.Authorities) != 1 || m.Authorities[0].Header.TTL != 63 {
				t.Fatal("negative DNS semantics lost", m)
			}
		})
	}
}
func TestStaticExternalCNAMEWithdrawsInflightAuthority(t *testing.T) {
	for _, scenario := range []string{"remove", "WG-revoke", "LAN-revoke", "change-upstream", "new-private-zone", "legacy-private-zone", "local-upstream"} {
		t.Run(scenario, func(t *testing.T) {
			f := New(nil, nil)
			p := externalProfileFixture()
			f.SetResolverProfiles([]ResolverProfile{p})
			started, release := make(chan struct{}), make(chan struct{})
			result := make(chan []byte, 1)
			var local atomic.Bool
			f.lanLocalAddresses = func() ([]net.Addr, error) {
				if local.Load() {
					return []net.Addr{&net.IPNet{IP: net.ParseIP("1.1.1.1"), Mask: net.CIDRMask(32, 32)}}, nil
				}
				return nil, nil
			}
			f.staticTargetTransport = privateProfileTransport(func(_ context.Context, _ fqdnrpc.ResolverConfig, _ fqdnrpc.ResolverEndpoint, wire []byte) ([]byte, error) {
				close(started)
				<-release
				return targetAnswer(wire, addressRecord("internal.lb.example.", dnsmessage.TypeA, 50)), nil
			})
			go func() {
				if scenario == "LAN-revoke" {
					result <- f.handleLAN(mkQuery("external.office.test."), netip.MustParseAddr("192.168.1.50"), "udp", compileLANListener(*p.LANListener).key)
				} else {
					result <- f.handle(mkQuery("external.office.test."), netip.MustParseAddr("10.99.0.7"))
				}
			}()
			<-started
			switch scenario {
			case "remove":
				f.SetResolverProfiles(nil)
			case "WG-revoke":
				p.AllowedSources = nil
				f.SetResolverProfiles([]ResolverProfile{p})
			case "LAN-revoke":
				copy := *p.LANListener
				copy.AllowedSources = []string{"192.168.2.0/24"}
				p.LANListener = &copy
				f.SetResolverProfiles([]ResolverProfile{p})
			case "change-upstream":
				p.Config.Endpoints = []fqdnrpc.ResolverEndpoint{{Address: "8.8.8.8", Port: 53, Transport: "udp"}}
				f.SetResolverProfiles([]ResolverProfile{p})
			case "new-private-zone":
				other := staticProfileFixture()
				other.ZoneSuffixes = []string{"lb.example"}
				other.StaticRecords = []StaticRecord{{"internal.lb.example", "A", "10.0.0.9", 300}}
				f.SetResolverProfiles([]ResolverProfile{p, other})
			case "legacy-private-zone":
				f.SetTable([]Entry{{Domain: "lb.example", ResolverIP: "10.0.0.53"}})
			case "local-upstream":
				local.Store(true)
			}
			close(release)
			if code := packetRCode(t, <-result); code != dnsmessage.RCodeServerFailure {
				t.Fatal("stale result relayed", code)
			}
		})
	}
}
func TestStaticExternalCNAMEEndpointValidationAndSharedLANDefaults(t *testing.T) {
	for _, bad := range []fqdnrpc.ResolverEndpoint{{"10.0.0.53", 53, "udp"}, {"127.0.0.1", 53, "udp"}, {"192.0.2.1", 53, "udp"}, {"::ffff:1.1.1.1", 53, "udp"}, {"1.1.1.1", 5353, "udp"}, {"1.1.1.1", 53, "https"}} {
		if validStaticTargetEndpoints([]fqdnrpc.ResolverEndpoint{bad}) {
			t.Fatal("unsafe endpoint accepted", bad)
		}
	}
	if validStaticTargetEndpoints([]fqdnrpc.ResolverEndpoint{{"1.1.1.1", 53, "udp"}, {"1.1.1.1", 53, "tcp"}}) {
		t.Fatal("duplicate address accepted across transports")
	}
	if validStaticName("bad..example") != "" {
		t.Fatal("empty hostname label accepted")
	}
	f := New(nil, nil)
	p := externalProfileFixture()
	p.LANListener.DefaultUpstreams = []string{"1.1.1.1"}
	f.SetResolverProfiles([]ResolverProfile{p})
	if _, _, _, failure := f.lanDefaults(f.profiles.Load(), compileLANListener(*p.LANListener).key); failure != "" {
		t.Fatal("shared public resolver falsely treated private", failure)
	}
	f.staticTargetTransport = privateProfileTransport(func(_ context.Context, _ fqdnrpc.ResolverConfig, _ fqdnrpc.ResolverEndpoint, wire []byte) ([]byte, error) {
		return targetAnswer(wire, addressRecord("internal.lb.example.", dnsmessage.TypeA, 50)), nil
	})
	f.lanDefaultTransport = privateProfileTransport(func(context.Context, fqdnrpc.ResolverConfig, fqdnrpc.ResolverEndpoint, []byte) ([]byte, error) {
		t.Fatal("static target used LAN authority")
		return nil, nil
	})
	if code := packetRCode(t, f.handle(mkQuery("external.office.test."), netip.MustParseAddr("10.99.0.7"))); code != 0 {
		t.Fatal("shared explicit resolver refused", code)
	}
}

func TestStaticExternalCNAMEIPv6AuthorizationUnchanged(t *testing.T) {
	f := New(nil, nil)
	p := externalProfileFixture()
	p.AllowedSources = []string{"fd99::7/128"}
	f.SetResolverProfiles([]ResolverProfile{p})
	calls := 0
	f.staticTargetTransport = privateProfileTransport(func(_ context.Context, _ fqdnrpc.ResolverConfig, _ fqdnrpc.ResolverEndpoint, wire []byte) ([]byte, error) {
		calls++
		return targetAnswer(wire, addressRecord("internal.lb.example.", dnsmessage.TypeAAAA, 40)), nil
	})
	query := queryType("external.office.test.", dnsmessage.TypeAAAA)
	if m := decodeDNS(t, f.handle(query, netip.MustParseAddr("fd99::7"))); m.RCode != 0 || len(m.Answers) != 2 || m.Answers[1].Header.Type != dnsmessage.TypeAAAA {
		t.Fatal("existing explicitly entitled IPv6 source lost AAAA answer", m)
	}
	if packetRCode(t, f.handle(query, netip.MustParseAddr("fd99::8"))) != dnsmessage.RCodeRefused {
		t.Fatal("IPv6 entitlement broadened")
	}
	if packetRCode(t, f.handleLAN(query, netip.MustParseAddr("fd99::7"), "udp", compileLANListener(*p.LANListener).key)) != dnsmessage.RCodeRefused || calls != 1 {
		t.Fatal("WireGuard IPv6 authority leaked to LAN", calls)
	}
}

func TestStaticExternalCNAMEUsesOnlyExplicitFailover(t *testing.T) {
	f := New(nil, nil)
	p := externalProfileFixture()
	p.Config.Endpoints = append(p.Config.Endpoints, fqdnrpc.ResolverEndpoint{Address: "8.8.8.8", Port: 53, Transport: "tcp"})
	f.SetResolverProfiles([]ResolverProfile{p})
	var calls []string
	f.staticTargetTransport = privateProfileTransport(func(_ context.Context, _ fqdnrpc.ResolverConfig, e fqdnrpc.ResolverEndpoint, wire []byte) ([]byte, error) {
		calls = append(calls, e.Address)
		if e.Address == "1.1.1.1" {
			return nil, context.DeadlineExceeded
		}
		if e.Address != "8.8.8.8" || e.Transport != "tcp" {
			t.Fatal("escaped explicit failover set", e)
		}
		return targetAnswer(wire, addressRecord("internal.lb.example.", dnsmessage.TypeA, 41)), nil
	})
	if packetRCode(t, f.handle(mkQuery("external.office.test."), netip.MustParseAddr("10.99.0.7"))) != 0 || len(calls) != 2 || calls[0] != "1.1.1.1" || calls[1] != "8.8.8.8" {
		t.Fatal("explicit upstream failover failed", calls)
	}
}
