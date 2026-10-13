package fqdnrpc

import (
	"context"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"reflect"
	"testing"
)

func proxyConfig() ResolverConfig {
	return ResolverConfig{ID: "66666666-6666-4666-8666-666666666666", Version: 4, ProfileID: "77777777-7777-4777-8777-777777777777", Endpoints: []ResolverEndpoint{{Address: "10.20.0.53", Port: 53, Transport: "udp"}}, IPsecPath: &IPsecPath{ConnectionID: "88888888-8888-4888-8888-888888888888", ConfigurationRevision: 2, SourceAddress: "10.10.0.1"}}
}
func TestProxyDNSExactMembershipAndPacketChecks(t *testing.T) {
	for _, tc := range []struct {
		name     string
		protocol string
		input    func(*ResolverConfig, *ResolverEndpoint, *dnsmessage.Message)
		reply    func(*dnsmessage.Message)
		fail     bool
		calls    int
	}{
		{"udp_TC", "udp", nil, func(m *dnsmessage.Message) { m.Truncated = true }, false, 1},
		{"tcp_full", "tcp", nil, nil, false, 1},
		{"unlisted_address", "tcp", func(_ *ResolverConfig, e *ResolverEndpoint, _ *dnsmessage.Message) { e.Address = "10.20.0.54" }, nil, true, 0},
		{"unlisted_original_transport", "tcp", func(_ *ResolverConfig, e *ResolverEndpoint, _ *dnsmessage.Message) { e.Transport = "tcp" }, nil, true, 0},
		{"wrong_port", "tcp", func(_ *ResolverConfig, e *ResolverEndpoint, _ *dnsmessage.Message) { e.Port = 54 }, nil, true, 0},
		{"invalid_revision", "tcp", func(c *ResolverConfig, _ *ResolverEndpoint, _ *dnsmessage.Message) {
			c.IPsecPath.ConfigurationRevision = 0
		}, nil, true, 0},
		{"invalid_protocol", "tls", nil, nil, true, 0},
		{"query_is_answer", "udp", func(_ *ResolverConfig, _ *ResolverEndpoint, m *dnsmessage.Message) { m.Response = true }, nil, true, 0},
		{"multiple_questions", "udp", func(_ *ResolverConfig, _ *ResolverEndpoint, m *dnsmessage.Message) {
			m.Questions = append(m.Questions, m.Questions[0])
		}, nil, true, 0},
		{"wrong_id", "udp", nil, func(m *dnsmessage.Message) { m.ID++ }, true, 1},
		{"wrong_question", "udp", nil, func(m *dnsmessage.Message) { m.Questions[0].Name = dnsmessage.MustNewName("different.test.") }, true, 1},
		{"wrong_opcode", "udp", nil, func(m *dnsmessage.Message) { m.OpCode = 1 }, true, 1},
		{"not_response", "udp", nil, func(m *dnsmessage.Message) { m.Response = false }, true, 1},
		{"truncated_TCP", "tcp", nil, func(m *dnsmessage.Message) { m.Truncated = true }, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := proxyConfig()
			e := c.Endpoints[0]
			q := dnsmessage.Message{Header: dnsmessage.Header{ID: 51}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("service.private.test."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}}}
			if tc.input != nil {
				tc.input(&c, &e, &q)
			}
			p, _ := q.Pack()
			calls := 0
			transport := packetTransport(func(_ context.Context, got ResolverConfig, endpoint ResolverEndpoint, payload []byte) ([]byte, error) {
				calls++
				if !reflect.DeepEqual(got, c) || endpoint.Address != e.Address || endpoint.Port != e.Port || endpoint.Transport != tc.protocol || string(payload) != string(p) {
					t.Fatal("immutable path/payload/endpoint changed")
				}
				var a dnsmessage.Message
				_ = a.Unpack(payload)
				a.Response = true
				if tc.reply != nil {
					tc.reply(&a)
				}
				return a.Pack()
			})
			r, err := ExchangeProxyDNS(t.Context(), transport, c, e, tc.protocol, p)
			if (err != nil) != tc.fail || calls != tc.calls {
				t.Fatalf("err%v calls%d wantfail%v calls%d", err, calls, tc.fail, tc.calls)
			}
			if tc.fail && r != nil {
				t.Fatal("refusal returned packet")
			}
		})
	}
}
func TestProxyDNSRequiresBoundAuthorityAndLiveContext(t *testing.T) {
	c := proxyConfig()
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 51}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("service.private.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	p, _ := q.Pack()
	if _, err := ExchangeProxyDNS(t.Context(), nil, c, c.Endpoints[0], "udp", p); err == nil {
		t.Fatal("IPsec path used configless transport")
	}
	transport := packetTransport(func(_ context.Context, _ ResolverConfig, _ ResolverEndpoint, p []byte) ([]byte, error) {
		var a dnsmessage.Message
		_ = a.Unpack(p)
		a.Response = true
		return a.Pack()
	})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := ExchangeProxyDNS(ctx, transport, c, c.Endpoints[0], "udp", p); err == nil {
		t.Fatal("expired context returned response")
	}
	refusal := packetTransport(func(context.Context, ResolverConfig, ResolverEndpoint, []byte) ([]byte, error) {
		return nil, errors.New("missing exact transport authority")
	})
	if _, err := ExchangeProxyDNS(t.Context(), refusal, c, c.Endpoints[0], "tcp", p); err == nil {
		t.Fatal("refused transport fell through")
	}
}

func TestProxyDNSClientsRetainConfiguredTCP(t *testing.T) {
	for _, tc := range []struct {
		name      string
		protocol  string
		truncated bool
	}{{"UDP_client_full_answer", "udp", false}, {"TCP_client_full_answer", "tcp", false}, {"UDP_client_truncated_TCP_refused", "udp", true}, {"TCP_client_truncated_TCP_refused", "tcp", true}} {
		t.Run(tc.name, func(t *testing.T) {
			c := proxyConfig()
			c.Endpoints[0].Transport = "tcp"
			e := c.Endpoints[0]
			q := dnsmessage.Message{Header: dnsmessage.Header{ID: 51}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("service.private.test."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}}}
			p, _ := q.Pack()
			calls := 0
			transport := packetTransport(func(_ context.Context, got ResolverConfig, endpoint ResolverEndpoint, payload []byte) ([]byte, error) {
				calls++
				if !reflect.DeepEqual(got, c) || endpoint != e || string(payload) != string(p) {
					t.Fatal("configured TCP transport changed")
				}
				var a dnsmessage.Message
				_ = a.Unpack(payload)
				a.Response = true
				a.Truncated = tc.truncated
				return a.Pack()
			})
			response, err := ExchangeProxyDNS(t.Context(), transport, c, e, tc.protocol, p)
			if (err != nil) != tc.truncated || calls != 1 || tc.truncated && response != nil {
				t.Fatalf("err%v calls%d", err, calls)
			}
		})
	}
}
