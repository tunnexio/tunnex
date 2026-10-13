package dnsforward

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func proxyContractForwarder(t *testing.T, source string, calls *[]string) *Forwarder {
	t.Helper()
	f := New(nil, func(netip.Addr, []byte) ([]byte, error) { t.Fatal("private fallback"); return nil, nil })
	p := privateProfile()
	p.Config.Endpoints = p.Config.Endpoints[:1]
	p.AllowedSources = []string{source}
	f.SetResolverProfiles([]ResolverProfile{p})
	f.SetResolverTransport(privateProfileTransport(func(_ context.Context, c fqdnrpc.ResolverConfig, e fqdnrpc.ResolverEndpoint, query []byte) ([]byte, error) {
		if c.ID != p.Config.ID || c.Version != p.Config.Version || c.IPsecPath == nil || *c.IPsecPath != *p.Config.IPsecPath || e.Address != p.Config.Endpoints[0].Address || e.Port != 53 {
			t.Error("endpoint/config/path changed")
		}
		*calls = append(*calls, e.Transport)
		var m dnsmessage.Message
		if err := m.Unpack(query); err != nil {
			return nil, err
		}
		m.Response = true
		if e.Transport == "udp" {
			m.Truncated = true
		} else {
			m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 5}, Body: &dnsmessage.TXTResource{TXT: []string{"large answer"}}}}
		}
		return m.Pack()
	}))
	return f
}
func TestProxyUDPReturnsValidatedTCWithoutInternalTCP(t *testing.T) {
	for _, size := range []uint16{512, 1232} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			var calls []string
			f := proxyContractForwarder(t, "10.99.0.7/32", &calls)
			q := proxyTXTQuery()
			if size == 1232 {
				var m dnsmessage.Message
				_ = m.Unpack(q)
				m.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: dnsmessage.Class(size)}, Body: &dnsmessage.OPTResource{}}}
				q, _ = m.Pack()
			}
			response := f.handle(q, netip.MustParseAddr("10.99.0.7"))
			var m dnsmessage.Message
			if m.Unpack(response) != nil || !m.Response || !m.Truncated || !reflect.DeepEqual(calls, []string{"udp"}) {
				t.Fatalf("client TC was consumed upstream: TC%v calls%v", m.Truncated, calls)
			}
		})
	}
}
func TestProxyTCPUsesConfiguredEndpointTCPDirectly(t *testing.T) {
	var calls []string
	f := proxyContractForwarder(t, "127.0.0.1/32", &calls)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
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
	q := proxyTXTQuery()
	b := make([]byte, len(q)+2)
	binary.BigEndian.PutUint16(b, uint16(len(q)))
	copy(b[2:], q)
	if _, err = conn.Write(b); err != nil {
		t.Fatal(err)
	}
	var size [2]byte
	if _, err = io.ReadFull(conn, size[:]); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err = io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	if m.Unpack(response) != nil || m.Truncated || m.RCode != dnsmessage.RCodeSuccess {
		t.Fatal("TCP fullanswer refused")
	}
	cancel()
	_ = conn.Close()
	_ = listener.Close()
	<-done
	if !reflect.DeepEqual(calls, []string{"tcp"}) {
		t.Fatalf("TCP client performed upstream UDP/fallback: %v", calls)
	}
}

func proxyTXTQuery() []byte {
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: 51}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("app.aws.private.test."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}}}
	p, _ := m.Pack()
	return p
}
