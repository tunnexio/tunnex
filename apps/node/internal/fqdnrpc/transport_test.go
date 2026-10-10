package fqdnrpc

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type checkedTransport struct {
	valid bool
	calls int
}

func (c *checkedTransport) ValidateDNSPath(context.Context, ResolverConfig, ResolverEndpoint) error {
	if !c.valid {
		return errors.New("expired")
	}
	return nil
}
func (c *checkedTransport) ExchangeDNS(_ context.Context, _ ResolverConfig, e ResolverEndpoint, payload []byte) ([]byte, error) {
	c.calls++
	if !c.valid {
		return nil, errors.New("withdrawn")
	}
	var msg dnsmessage.Message
	_ = msg.Unpack(payload)
	msg.Response = true
	if msg.Questions[0].Type == dnsmessage.TypeA {
		msg.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: msg.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 5}, Body: &dnsmessage.AResource{A: [4]byte{10, 20, 0, 8}}}}
	}
	return msg.Pack()
}

func TestIPsecResolverCachedRetryRequiresFreshAuthority(t *testing.T) {
	now := time.Now()
	request := testRequest(now)
	request.ResolverIPsecPath = &IPsecPath{ConnectionID: "88888888-8888-4888-8888-888888888888", ConfigurationRevision: 3, SourceAddress: "10.10.0.1"}
	transport := &checkedTransport{valid: true}
	responder := NewResponder(DirectResolver{Transport: transport})
	if got := responder.Handle(t.Context(), testGateway, request); got.Status != StatusNoError || transport.calls != 2 {
		t.Fatalf("first %+v calls%d", got, transport.calls)
	}
	transport.valid = false
	if got := responder.Handle(t.Context(), testGateway, request); got.Status != StatusServFail || len(got.Records) != 0 {
		t.Fatalf("cache survived expiry %+v", got)
	}
	transport.valid = true
	if got := responder.Handle(t.Context(), testGateway, request); got.Status != StatusNoError || transport.calls != 2 {
		t.Fatalf("current native retry must not requery %+v", got)
	}
	changed := *request.ResolverIPsecPath
	changed.ConfigurationRevision++
	request.ResolverIPsecPath = &changed
	if got := responder.Handle(t.Context(), testGateway, request); got.Status != StatusServFail {
		t.Fatal("cache ignored path revision")
	}
}

func TestIPsecResolverCannotUsePlainOrInjectedWANResolver(t *testing.T) {
	request := testRequest(time.Now())
	request.ResolverIPsecPath = &IPsecPath{ConnectionID: "88888888-8888-4888-8888-888888888888", ConfigurationRevision: 1, SourceAddress: "10.10.0.1"}
	plain := &fakeResolver{records: []Record{{Name: request.Hostname, Type: RecordA, Address: "10.20.0.8", TTLSeconds: 30}}}
	if got := NewResponder(plain).Handle(t.Context(), testGateway, request); got.Status != StatusServFail || plain.calls != 0 {
		t.Fatal("plain resolver bypass")
	}
	called := false
	direct := DirectResolver{exchange: func(context.Context, ResolverEndpoint, string, RecordType) ([]Record, error) {
		called = true
		return nil, nil
	}}
	if got := NewResponder(direct).Handle(t.Context(), testGateway, request); got.Status != StatusServFail || called {
		t.Fatal("injected ordinary resolver bypass")
	}
}

func TestDNSBoundSocketUsesActualSourceUDPAndTCP(t *testing.T) {
	source := netip.MustParseAddr("127.0.0.1")
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: 915}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("service.private.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	payload, _ := query.Pack()
	query.Response = true
	reply, _ := query.Pack()
	for _, protocol := range []string{"udp", "tcp"} {
		t.Run(protocol, func(t *testing.T) {
			seen := make(chan string, 1)
			var port int
			if protocol == "udp" {
				listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				port = listener.LocalAddr().(*net.UDPAddr).Port
				go func() {
					buf := make([]byte, 65535)
					_, addr, err := listener.ReadFromUDP(buf)
					if err == nil {
						seen <- addr.IP.String()
						_, _ = listener.WriteToUDP(reply, addr)
					}
				}()
			} else {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				port = listener.Addr().(*net.TCPAddr).Port
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					defer conn.Close()
					seen <- conn.RemoteAddr().(*net.TCPAddr).IP.String()
					var length [2]byte
					_, _ = io.ReadFull(conn, length[:])
					body := make([]byte, binary.BigEndian.Uint16(length[:]))
					_, _ = io.ReadFull(conn, body)
					binary.BigEndian.PutUint16(length[:], uint16(len(reply)))
					_, _ = conn.Write(append(length[:], reply...))
				}()
			}
			got, err := ExchangeBoundSocket(t.Context(), ResolverEndpoint{Address: "127.0.0.1", Port: port, Transport: protocol}, source, payload)
			if err != nil || string(got) != string(reply) {
				t.Fatalf("actual%s exchange %v", protocol, err)
			}
			if got := <-seen; got != source.String() {
				t.Fatalf("source%s", got)
			}
			if _, err := ExchangeBoundSocket(t.Context(), ResolverEndpoint{Address: "127.0.0.1", Port: port, Transport: protocol}, netip.MustParseAddr("203.0.113.250"), payload); err == nil {
				t.Fatal("unassigned explicit source fell back to defaultsource")
			}
		})
	}
}

type packetTransport func(context.Context, ResolverConfig, ResolverEndpoint, []byte) ([]byte, error)

func (f packetTransport) ExchangeDNS(ctx context.Context, c ResolverConfig, e ResolverEndpoint, p []byte) ([]byte, error) {
	return f(ctx, c, e, p)
}
func TestDNSBoundTCFallbackStaysSameEndpointAndValidatesQuestion(t *testing.T) {
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: 51}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("service.private.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	payload, _ := query.Pack()
	calls := 0
	transport := packetTransport(func(_ context.Context, _ ResolverConfig, e ResolverEndpoint, _ []byte) ([]byte, error) {
		calls++
		if e.Address != "10.20.0.53" || e.Port != 53 {
			t.Fatal("fallback changed resolver")
		}
		reply := query
		reply.Response = true
		if calls == 1 {
			if e.Transport != "udp" {
				t.Fatal("firstTCP")
			}
			reply.Truncated = true
		} else if e.Transport != "tcp" {
			t.Fatal("TCdidnotretryTCP")
		}
		return reply.Pack()
	})
	if _, err := exchangeDNSPacket(t.Context(), transport, ResolverConfig{}, ResolverEndpoint{Address: "10.20.0.53", Port: 53, Transport: "udp"}, payload); err != nil || calls != 2 {
		t.Fatal(err, calls)
	}
	bad := packetTransport(func(context.Context, ResolverConfig, ResolverEndpoint, []byte) ([]byte, error) {
		reply := query
		reply.Response = true
		reply.Questions = append([]dnsmessage.Question(nil), reply.Questions...)
		reply.Questions[0].Name = dnsmessage.MustNewName("different.test.")
		return reply.Pack()
	})
	if _, err := exchangeDNSPacket(t.Context(), bad, ResolverConfig{}, ResolverEndpoint{Address: "10.20.0.53", Port: 53, Transport: "udp"}, payload); err == nil {
		t.Fatal("different question answer accepted")
	}
	partialTCP := packetTransport(func(context.Context, ResolverConfig, ResolverEndpoint, []byte) ([]byte, error) {
		reply := query
		reply.Response = true
		reply.Truncated = true
		return reply.Pack()
	})
	if _, err := exchangeDNSPacket(t.Context(), partialTCP, ResolverConfig{}, ResolverEndpoint{Address: "10.20.0.53", Port: 53, Transport: "tcp"}, payload); err == nil {
		t.Fatal("truncated TCP observation accepted as complete DNS answer")
	}
}
