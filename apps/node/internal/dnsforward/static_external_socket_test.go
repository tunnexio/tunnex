package dnsforward

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"golang.org/x/net/dns/dnsmessage"
)

// Native sockets stay on localhost. Only the test transport redirects the
// profile's canonical public endpoint to the isolated upstream's ephemeral port.
func TestStaticExternalCNAMERealSocketsTruncationRetryAndWithdrawal(t *testing.T) {
	for _, lan := range []bool{false, true} {
		label := "WireGuard"
		if lan {
			label = "LAN"
		}
		t.Run(label, func(t *testing.T) {
			targetQuery := queryType("internal.lb.example.", dnsmessage.TypeA)
			large := decodeDNS(t, targetAnswer(targetQuery))
			for i := 0; i < 32; i++ {
				record := addressRecord("internal.lb.example.", dnsmessage.TypeA, 37)
				record.Body = &dnsmessage.AResource{A: [4]byte{10, 180, 10, byte(i + 1)}}
				large.Answers = append(large.Answers, record)
			}
			full, err := large.Pack()
			if err != nil {
				t.Fatal(err)
			}
			truncated := large
			truncated.Truncated = true
			truncated.Answers = nil
			stub, err := truncated.Pack()
			if err != nil {
				t.Fatal(err)
			}
			port, stop := fakeResolver(t, stub, full)
			defer stop()
			f := New(nil, nil)
			p := externalProfileFixture()
			p.AllowedSources = []string{"127.0.0.1/32"}
			builder := New(nil, nil)
			builder.SetResolverProfiles([]ResolverProfile{p})
			// Test listener source is localhost, published immutably before serving.
			builder.profiles.Load().entries[0].lan.sources = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
			f.profiles.Store(builder.profiles.Load())
			var udpCalls, tcpCalls atomic.Int32
			f.staticTargetTransport = privateProfileTransport(func(ctx context.Context, _ fqdnrpc.ResolverConfig, e fqdnrpc.ResolverEndpoint, wire []byte) ([]byte, error) {
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
			udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			tcp, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				udp.Close()
				t.Fatal(err)
			}
			handler := f.handleTransport
			if lan {
				key := compileLANListener(*p.LANListener).key
				handler = func(wire []byte, source netip.Addr, transport string) []byte {
					return f.handleLAN(wire, source, transport, key)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			var servers sync.WaitGroup
			servers.Add(2)
			go func() { defer servers.Done(); f.serveConnWithHandler(ctx, udp, handler) }()
			go func() { defer servers.Done(); f.serveTCPWithHandler(ctx, tcp, handler) }()
			defer func() { cancel(); udp.Close(); tcp.Close(); servers.Wait() }()
			udpQuery := func(wire []byte) []byte {
				t.Helper()
				c, err := net.Dial("udp", udp.LocalAddr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(2 * time.Second))
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
			query := queryType("external.office.test.", dnsmessage.TypeA)
			response := udpQuery(query)
			if m := decodeDNS(t, response); m.RCode != 0 || !m.Truncated || len(response) > 512 || udpCalls.Load() != 1 || tcpCalls.Load() != 1 {
				t.Fatal("native UDP size or upstream TCP retry lost", m, len(response), udpCalls.Load(), tcpCalls.Load())
			}
			c, err := net.Dial("tcp", tcp.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(2 * time.Second))
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
			response = make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, err := io.ReadFull(c, response); err != nil {
				t.Fatal(err)
			}
			if m := decodeDNS(t, response); m.RCode != 0 || m.Truncated || len(m.Answers) != 33 || m.Answers[32].Header.TTL != 37 || udpCalls.Load() != 1 || tcpCalls.Load() != 2 {
				t.Fatal("native TCP answer lost connected terminal records", m, udpCalls.Load(), tcpCalls.Load())
			}
			f.SetResolverProfiles(nil)
			if packetRCode(t, udpQuery(query)) != dnsmessage.RCodeRefused || udpCalls.Load() != 1 || tcpCalls.Load() != 2 {
				t.Fatal("removed profile still invoked target upstream")
			}
		})
	}
}
