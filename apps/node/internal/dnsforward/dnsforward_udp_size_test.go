package dnsforward

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDownstreamUDPAdvertisedSizeOffersTCPRatherThanFragmentation(t *testing.T) {
	question := dnsmessage.Question{Name: dnsmessage.MustNewName("service.private.test."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 19, RecursionDesired: true}, Questions: []dnsmessage.Question{question}}
	a := q
	a.Response = true
	a.RecursionAvailable = true
	for n := 0; n < 6; n++ {
		a.Answers = append(a.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 10}, Body: &dnsmessage.TXTResource{TXT: []string{string(make([]byte, 230))}}})
	}
	full, err := a.Pack()
	if err != nil || len(full) < 1232 {
		t.Fatal("fixture not a large DNS answer", err)
	}
	for _, advertised := range []int{0, 128, 512, 1232, 4096} {
		q.Additionals = nil
		if advertised != 0 {
			q.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: dnsmessage.Class(advertised)}, Body: &dnsmessage.OPTResource{}}}
		}
		query, _ := q.Pack()
		raw := downstreamUDPResponse(query, full)
		var truncated dnsmessage.Message
		if truncated.Unpack(raw) != nil || !truncated.Response || !truncated.Truncated || truncated.ID != q.ID || len(truncated.Questions) != 1 || truncated.Questions[0] != question || len(truncated.Answers) != 0 || !truncated.RecursionAvailable {
			t.Fatal("malformed TCP retry response", advertised)
		}
		if len(raw) > 512 {
			t.Fatal("truncated response exceeded minimum downstream bound")
		}
	}
	q.Additionals = nil
	a.Answers = a.Answers[:1]
	small, _ := a.Pack()
	query, _ := q.Pack()
	if got := downstreamUDPResponse(query, small); string(got) != string(small) {
		t.Fatal("valid small reply changed")
	}
	// Neither an unreadable query nor duplicate OPT records can negotiate a
	// larger downstream datagram. A 700-byte response must still become TC.
	a.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}, Body: &dnsmessage.TXTResource{TXT: []string{strings.Repeat("x", 230), strings.Repeat("y", 230), strings.Repeat("z", 230)}}}}
	medium, _ := a.Pack()
	q.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 4096}, Body: &dnsmessage.OPTResource{}}, {Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 4096}, Body: &dnsmessage.OPTResource{}}}
	multiple, _ := q.Pack()
	for _, malformed := range [][]byte{{0, 1}, multiple} {
		var parsed dnsmessage.Message
		if parsed.Unpack(downstreamUDPResponse(malformed, medium)) != nil || !parsed.Truncated {
			t.Fatal("malformed OPT negotiated an oversized datagram")
		}
	}
}

func TestPrivateDNSRealUDPTruncationThenTCPFullSameQuery(t *testing.T) {
	f := New(nil, nil)
	profile := privateProfile()
	profile.AllowedSources = []string{"127.0.0.1/32"}
	f.SetResolverProfiles([]ResolverProfile{profile})
	f.SetResolverTransport(privateProfileTransport(func(_ context.Context, _ fqdnrpc.ResolverConfig, _ fqdnrpc.ResolverEndpoint, raw []byte) ([]byte, error) {
		var message dnsmessage.Message
		if err := message.Unpack(raw); err != nil {
			return nil, err
		}
		message.Response = true
		message.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: message.Questions[0].Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 5}, Body: &dnsmessage.TXTResource{TXT: []string{strings.Repeat("x", 230), strings.Repeat("y", 230), strings.Repeat("z", 230)}}}}
		return message.Pack()
	}))
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		udp.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	udpDone, tcpDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(udpDone); f.serveConn(ctx, udp) }()
	go func() { defer close(tcpDone); f.serveTCP(ctx, tcp) }()
	defer func() {
		cancel()
		udp.Close()
		tcp.Close()
		for _, done := range []chan struct{}{udpDone, tcpDone} {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("DNS test socket lifecycle did not join")
			}
		}
	}()
	message := dnsmessage.Message{Header: dnsmessage.Header{ID: 734, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("large.aws.private.test."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}}}
	query, _ := message.Pack()
	client, err := net.DialUDP("udp", nil, udp.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(time.Second))
	if _, err := client.Write(query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	n, err := client.Read(buf)
	var answer dnsmessage.Message
	if err != nil || n > 512 || answer.Unpack(buf[:n]) != nil || !answer.Truncated || answer.ID != message.ID {
		t.Fatal("actual UDP failed to offer bounded TCP retry", err, n)
	}
	stream, err := net.Dial("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	stream.SetDeadline(time.Now().Add(time.Second))
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)
	if _, err := stream.Write(frame); err != nil {
		t.Fatal(err)
	}
	var length [2]byte
	if _, err := io.ReadFull(stream, length[:]); err != nil {
		t.Fatal(err)
	}
	full := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(stream, full); err != nil {
		t.Fatal(err)
	}
	answer = dnsmessage.Message{}
	if len(full) <= 512 || answer.Unpack(full) != nil || answer.Truncated || answer.ID != message.ID || len(answer.Answers) != 1 || answer.Questions[0] != message.Questions[0] {
		t.Fatal("TCP retry lost complete same-query answer")
	}
}
