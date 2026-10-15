package dnsforward

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"golang.org/x/net/dns/dnsmessage"
)

// Production keeps canonical public :53 upstreams and private LAN ownership.
// Only the test transport redirects them to an isolated local fake resolver.
func TestLANDefaultRealSocketsPublicPrivateTruncationAndWithdrawal(t *testing.T) {
	query := mkQuery("www.example.com.")
	large := decodeDNS(t, publicDNSAnswer(query))
	for i := 0; i < 60; i++ {
		large.Answers = append(large.Answers, large.Answers[0])
	}
	full, err := large.Pack()
	if err != nil {
		t.Fatal(err)
	}
	truncated := large
	truncated.Truncated = true
	truncated.Answers = nil
	stub, _ := truncated.Pack()
	port, stop := fakeResolver(t, stub, full)
	defer stop()
	f := New(nil, nil)
	defer f.closeOwnedBinds()
	p := fullLANProfile()
	p.LANListener.DefaultUpstreams = []string{"1.1.1.1"}
	install := func(profile ResolverProfile) {
		// Build before publishing so no mutable table is visible to socket goroutines.
		builder := New(nil, nil)
		builder.SetResolverProfiles([]ResolverProfile{profile})
		builder.profiles.Load().entries[0].lan.sources = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
		f.profiles.Store(builder.profiles.Load())
	}
	install(p)
	f.lanOwned = func(lanBindKey) error { return nil }
	var udp *net.UDPConn
	var tcp net.Listener
	f.lanListenUDP = func(netip.Addr, string) (udpListener, error) {
		var err error
		udp, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		return udp, err
	}
	f.lanListenTCP = func(netip.Addr, string) (net.Listener, error) {
		var err error
		tcp, err = net.Listen("tcp", "127.0.0.1:0")
		return tcp, err
	}
	var udpCalls, tcpCalls atomic.Int32
	f.lanDefaultTransport = privateProfileTransport(func(ctx context.Context, _ fqdnrpc.ResolverConfig, e fqdnrpc.ResolverEndpoint, wire []byte) ([]byte, error) {
		if e.Address != "1.1.1.1" || e.Port != 53 {
			t.Error("unexpected production endpoint", e)
		}
		if e.Transport == "udp" {
			udpCalls.Add(1)
		} else {
			tcpCalls.Add(1)
		}
		e.Address, e.Port = "127.0.0.1", int(port)
		return fqdnrpc.ExchangeBoundSocket(ctx, e, netip.Addr{}, wire)
	})
	f.reconcileLANBinds("wg0")
	if udp == nil || tcp == nil {
		t.Fatal("LAN socket setup failed", f.AppliedLANListeners())
	}
	udpQuery := func(wire []byte) []byte {
		t.Helper()
		c, err := net.Dial("udp", udp.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write(wire); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 65535)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		return buf[:n]
	}
	if m := decodeDNS(t, udpQuery(mkQuery("alias.office.test."))); len(m.Answers) != 2 || udpCalls.Load() != 0 || tcpCalls.Load() != 0 {
		t.Fatal("private answer used public resolver", m)
	}
	publicUDP := udpQuery(query)
	if m := decodeDNS(t, publicUDP); !m.Truncated || len(publicUDP) > 512 || udpCalls.Load() != 1 || tcpCalls.Load() != 1 {
		t.Fatal("UDP truncation/TCP retry contract lost", len(publicUDP), m, udpCalls.Load(), tcpCalls.Load())
	}
	c, err := net.Dial("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)
	if _, err := c.Write(frame); err != nil {
		t.Fatal(err)
	}
	var size [2]byte
	if _, err := io.ReadFull(c, size[:]); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(c, response); err != nil {
		t.Fatal(err)
	}
	if m := decodeDNS(t, response); m.Truncated || len(m.Answers) != len(large.Answers) || tcpCalls.Load() != 2 || udpCalls.Load() != 1 {
		t.Fatal("TCP did not preserve complete public answer", m)
	}
	p.LANListener.DefaultUpstreams = nil
	install(p)
	f.reconcileLANBinds("wg0")
	if packetRCode(t, udpQuery(query)) != dnsmessage.RCodeRefused || tcpCalls.Load() != 2 || udpCalls.Load() != 1 {
		t.Fatal("withdrawn default forwarding remained active")
	}
	if packetRCode(t, udpQuery(mkQuery("app.office.test."))) != 0 {
		t.Fatal("default withdrawal removed private service")
	}
}

func TestLANDefaultValidatesReplyIdentityAndRetriesExplicitUpstream(t *testing.T) {
	for _, bad := range []string{"id", "question", "truncated-tcp", "timeout"} {
		t.Run(bad, func(t *testing.T) {
			f := New(nil, nil)
			p := fullLANProfile()
			f.SetResolverProfiles([]ResolverProfile{p})
			var calls []string
			f.lanDefaultTransport = privateProfileTransport(func(_ context.Context, _ fqdnrpc.ResolverConfig, e fqdnrpc.ResolverEndpoint, query []byte) ([]byte, error) {
				calls = append(calls, e.Address)
				answer := decodeDNS(t, publicDNSAnswer(query))
				if e.Address == "1.1.1.1" {
					switch bad {
					case "id":
						answer.ID++
					case "question":
						answer.Questions[0].Name = dnsmessage.MustNewName("different.example.")
					case "truncated-tcp":
						answer.Truncated = true
					case "timeout":
						return nil, context.DeadlineExceeded
					}
				}
				return answer.Pack()
			})
			key := compileLANListener(*p.LANListener).key
			if packetRCode(t, f.handleLAN(mkQuery("www.example.com."), netip.MustParseAddr("192.168.1.50"), "tcp", key)) != 0 || len(calls) != 2 || calls[0] != "1.1.1.1" || calls[1] != "8.8.8.8" {
				t.Fatal("invalid answer was accepted or escaped explicit upstreams", calls)
			}
		})
	}
}
