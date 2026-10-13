package dnsforward

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"golang.org/x/net/dns/dnsmessage"
)

type privateProfileTransport func(context.Context, fqdnrpc.ResolverConfig, fqdnrpc.ResolverEndpoint, []byte) ([]byte, error)

func (f privateProfileTransport) ExchangeDNS(ctx context.Context, c fqdnrpc.ResolverConfig, e fqdnrpc.ResolverEndpoint, p []byte) ([]byte, error) {
	return f(ctx, c, e, p)
}
func privateProfile() ResolverProfile {
	return ResolverProfile{Config: fqdnrpc.ResolverConfig{ID: "66666666-6666-4666-8666-666666666666", Version: 4, ProfileID: "77777777-7777-4777-8777-777777777777", Endpoints: []fqdnrpc.ResolverEndpoint{{Address: "10.20.0.53", Port: 53, Transport: "udp"}, {Address: "10.20.0.54", Port: 53, Transport: "udp"}}, IPsecPath: &fqdnrpc.IPsecPath{ConnectionID: "88888888-8888-4888-8888-888888888888", ConfigurationRevision: 2, SourceAddress: "10.10.0.1"}}, ZoneSuffixes: []string{"aws.private.test"}, AllowedSources: []string{"10.99.0.7/32"}}
}
func privatePacketReply(query []byte) ([]byte, error) {
	var message dnsmessage.Message
	if err := message.Unpack(query); err != nil {
		return nil, err
	}
	message.Response = true
	message.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: message.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 5}, Body: &dnsmessage.AResource{A: [4]byte{10, 20, 0, 80}}}}
	return message.Pack()
}
func packetRCode(t *testing.T, p []byte) dnsmessage.RCode {
	t.Helper()
	var message dnsmessage.Message
	if err := message.Unpack(p); err != nil {
		t.Fatal(err)
	}
	return message.RCode
}

func TestPrivateResolverNoFallbackOnExpiryDisableDeleteAndRestart(t *testing.T) {
	for _, cause := range []string{"leaseexpired", "disabled", "deleting", "coldrestart", "missingroute", "foreignsource"} {
		t.Run(cause, func(t *testing.T) {
			lanCalls := 0
			f := New(nil, func(netip.Addr, []byte) ([]byte, error) { lanCalls++; return nil, nil })
			f.SetTable([]Entry{{Domain: "aws.private.test", ResolverIP: "8.8.8.8"}})
			f.SetResolverProfiles([]ResolverProfile{privateProfile()})
			f.SetResolverTransport(privateProfileTransport(func(context.Context, fqdnrpc.ResolverConfig, fqdnrpc.ResolverEndpoint, []byte) ([]byte, error) {
				return nil, errors.New(cause)
			}))
			response := f.handle(mkQuery("app.aws.private.test."), netip.MustParseAddr("10.99.0.7"))
			if packetRCode(t, response) != dnsmessage.RCodeServerFailure || lanCalls != 0 {
				t.Fatal("inactiveprivatezone fellthrough", cause)
			}
		})
	}
}

func TestPrivateResolverEntitlementLongestSuffixAndConfiguredEndpointFailover(t *testing.T) {
	f := New(nil, func(netip.Addr, []byte) ([]byte, error) { t.Fatal("LANfallback"); return nil, nil })
	p := privateProfile()
	specific := privateProfile()
	specific.Config.ProfileID = "99999999-9999-4999-8999-999999999999"
	specific.ZoneSuffixes = []string{"prod.aws.private.test"}
	f.SetResolverProfiles([]ResolverProfile{p, specific})
	calls := 0
	f.SetResolverTransport(privateProfileTransport(func(_ context.Context, c fqdnrpc.ResolverConfig, e fqdnrpc.ResolverEndpoint, query []byte) ([]byte, error) {
		calls++
		if c.ProfileID != specific.Config.ProfileID {
			t.Fatal("did not selectlongestsuffix")
		}
		if e.Address == "10.20.0.53" {
			return nil, errors.New("firstresolverdown")
		}
		return privatePacketReply(query)
	}))
	if got := f.handle(mkQuery("app.prod.aws.private.test."), netip.MustParseAddr("10.99.0.8")); packetRCode(t, got) != dnsmessage.RCodeRefused || calls != 0 {
		t.Fatal("unauthorizedclient reachedresolver")
	}
	if got := f.handle(mkQuery("app.prod.aws.private.test."), netip.MustParseAddr("10.99.0.7")); packetRCode(t, got) != dnsmessage.RCodeSuccess || calls != 2 {
		t.Fatal("configuredendpointfailover", calls)
	}
	if got := f.handle(mkQuery("public.example."), netip.MustParseAddr("10.99.0.7")); packetRCode(t, got) != dnsmessage.RCodeRefused {
		t.Fatal("gatewayforwarderbecamepublicresolver")
	}
}

func TestPrivateResolverRefusesRemovedEntitlementAndSupersededResponse(t *testing.T) {
	f := New(nil, nil)
	p := privateProfile()
	f.SetResolverProfiles([]ResolverProfile{p})
	f.SetResolverTransport(privateProfileTransport(func(_ context.Context, _ fqdnrpc.ResolverConfig, _ fqdnrpc.ResolverEndpoint, query []byte) ([]byte, error) {
		changed := p
		changed.Config.Version++
		changed.AllowedSources = nil
		f.SetResolverProfiles([]ResolverProfile{changed})
		return privatePacketReply(query)
	}))
	if packetRCode(t, f.handle(mkQuery("app.aws.private.test."), netip.MustParseAddr("10.99.0.7"))) != dnsmessage.RCodeServerFailure {
		t.Fatal("supersededresponseescaped")
	}
	if packetRCode(t, f.handle(mkQuery("app.aws.private.test."), netip.MustParseAddr("10.99.0.7"))) != dnsmessage.RCodeRefused {
		t.Fatal("removedsourcekeptentitlement")
	}
}

func TestPrivateResolverUnchangedPolicyDoesNotDiscardInFlightAnswer(t *testing.T) {
	f := New(nil, nil)
	p := privateProfile()
	f.SetResolverProfiles([]ResolverProfile{p})
	f.SetResolverTransport(privateProfileTransport(func(_ context.Context, _ fqdnrpc.ResolverConfig, _ fqdnrpc.ResolverEndpoint, query []byte) ([]byte, error) {
		f.SetResolverProfiles([]ResolverProfile{p})
		return privatePacketReply(query)
	}))
	if packetRCode(t, f.handle(mkQuery("app.aws.private.test."), netip.MustParseAddr("10.99.0.7"))) != dnsmessage.RCodeSuccess {
		t.Fatal("identicalpolicyfetchdiscardedanswer")
	}
}

func TestDNSDownstreamTCPRealFramesAndWithdrawal(t *testing.T) {
	f := New(nil, func(_ netip.Addr, query []byte) ([]byte, error) { return privatePacketReply(query) })
	f.SetTable([]Entry{{Domain: "lan.private.test", ResolverIP: "10.20.0.53"}})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer listener.Close()
	done := make(chan struct{})
	go func() { defer close(done); f.serveTCP(ctx, listener) }()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	for _, name := range []string{"one.lan.private.test.", "two.lan.private.test."} {
		query := mkQuery(name)
		frame := make([]byte, len(query)+2)
		binary.BigEndian.PutUint16(frame, uint16(len(query)))
		copy(frame[2:], query)
		if _, err := conn.Write(frame); err != nil {
			t.Fatal(err)
		}
		var length [2]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, binary.BigEndian.Uint16(length[:]))
		if _, err := io.ReadFull(conn, response); err != nil || packetRCode(t, response) != dnsmessage.RCodeSuccess {
			t.Fatal("TCPframeexchange", err)
		}
	}
	cancel()
	_ = listener.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("withdrawalleftacceptedTCPsession")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TCPwithdrawaldidnotjoin")
	}
}
