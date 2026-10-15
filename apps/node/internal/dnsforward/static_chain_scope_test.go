package dnsforward

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"golang.org/x/net/dns/dnsmessage"
)

func TestStaticChainRequiresEffectiveProfileOwnership(t *testing.T) {
	for _, endpoints := range []bool{false, true} {
		for _, nestedAllowed := range []bool{false, true} {
			for _, terminal := range []string{"A", "AAAA", "CNAME"} {
				for _, queryKind := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeCNAME} {
					t.Run(fmt.Sprintf("endpoints=%v/nestedAllowed=%v/%s/query=%v", endpoints, nestedAllowed, terminal, queryKind), func(t *testing.T) {
						f := New(nil, nil)
						p := externalProfileFixture()
						if !endpoints {
							p.Config.Endpoints = nil
						}
						value := "10.180.10.229"
						if terminal == "AAAA" {
							value = "fd00::229"
						}
						if terminal == "CNAME" {
							value = "public.example"
						}
						p.StaticRecords = []StaticRecord{{"alias.office.test", "CNAME", "hidden.private.office.test", 300}, {"hidden.private.office.test", terminal, value, 300}}
						nested := staticProfileFixture()
						nested.Config.ProfileID = "33333333-3333-4333-8333-333333333333"
						nested.ZoneSuffixes = []string{"private.office.test"}
						nested.StaticRecords = []StaticRecord{{"other.private.office.test", "A", "10.20.0.81", 300}}
						if !nestedAllowed {
							nested.AllowedSources = nil
						}
						f.SetResolverProfiles([]ResolverProfile{p, nested})
						calls := 0
						f.staticTargetTransport = privateProfileTransport(func(_ context.Context, _ fqdnrpc.ResolverConfig, _ fqdnrpc.ResolverEndpoint, wire []byte) ([]byte, error) {
							calls++
							q := decodeDNS(t, wire).Questions[0]
							return targetAnswer(wire, addressRecord(q.Name.String(), q.Type, 30)), nil
						})
						source := netip.MustParseAddr("10.99.0.7")
						wantDirect := dnsmessage.RCodeRefused
						if nestedAllowed {
							wantDirect = dnsmessage.RCodeNameError
						}
						if direct := packetRCode(t, f.handle(mkQuery("hidden.private.office.test."), source)); direct != wantDirect {
							t.Fatal("direct lookup did not select nested owner", direct)
						}
						query := queryType("alias.office.test.", queryKind)
						got := decodeDNS(t, f.handle(query, source))
						if got.RCode != dnsmessage.RCodeServerFailure || len(got.Answers) != 0 || calls != 0 {
							t.Fatal("local chain escaped selected owner", got, calls)
						}
						// Nested profile is not exposed on this LAN listener. The outer profile's
						// LAN entitlement must not expose the hidden local record either.
						got = decodeDNS(t, f.handleLAN(query, netip.MustParseAddr("192.168.1.50"), "udp", compileLANListener(*p.LANListener).key))
						if got.RCode != dnsmessage.RCodeServerFailure || len(got.Answers) != 0 || calls != 0 {
							t.Fatal("LAN local chain escaped selected owner", got, calls)
						}
					})
				}
			}
		}
	}
}

func TestStaticChainAmbiguousNestedOwnerFailsClosed(t *testing.T) {
	f := New(nil, nil)
	p := externalProfileFixture()
	p.StaticRecords = []StaticRecord{{"alias.office.test", "CNAME", "hidden.private.office.test", 300}, {"hidden.private.office.test", "A", "10.180.10.229", 300}}
	nested := staticProfileFixture()
	nested.Config.ProfileID = "33333333-3333-4333-8333-333333333333"
	nested.ZoneSuffixes = []string{"private.office.test"}
	nested.StaticRecords = []StaticRecord{{"hidden.private.office.test", "A", "10.20.0.81", 300}}
	duplicate := nested
	duplicate.Config.ProfileID = "44444444-4444-4444-8444-444444444444"
	f.SetResolverProfiles([]ResolverProfile{p, nested, duplicate})
	if got := decodeDNS(t, f.handle(mkQuery("alias.office.test."), netip.MustParseAddr("10.99.0.7"))); got.RCode != dnsmessage.RCodeServerFailure || len(got.Answers) != 0 {
		t.Fatal("ambiguous nested owner returned local record", got)
	}
}

func TestStaticChainRetainsSameProfileAcrossItsZones(t *testing.T) {
	for _, kind := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		f := New(nil, nil)
		p := externalProfileFixture()
		p.ZoneSuffixes = []string{"office.test", "shared.test"}
		p.StaticRecords = []StaticRecord{{"alias.office.test", "CNAME", "target.shared.test", 300}, {"target.shared.test", "A", "10.20.0.80", 300}, {"target.shared.test", "AAAA", "fd00::80", 300}}
		f.SetResolverProfiles([]ResolverProfile{p})
		f.staticTargetTransport = privateProfileTransport(func(context.Context, fqdnrpc.ResolverConfig, fqdnrpc.ResolverEndpoint, []byte) ([]byte, error) {
			t.Fatal("same-profile answer invoked upstream")
			return nil, nil
		})
		got := decodeDNS(t, f.handle(queryType("alias.office.test.", kind), netip.MustParseAddr("10.99.0.7")))
		if got.RCode != 0 || len(got.Answers) != 2 || got.Answers[1].Header.Type != kind {
			t.Fatal("same-profile local chain changed", got)
		}
	}
}
