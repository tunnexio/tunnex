package dnsforward

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
)

// fakeResolver stands up a UDP + TCP listener on the SAME unprivileged port (like a real resolver on 53).
// udpReply is returned to any UDP query; tcpReply to any TCP query. Returns the port + a stop func.
func fakeResolver(t *testing.T, udpReply, tcpReply []byte) (uint16, func()) {
	t.Helper()
	uc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	port := uint16(uc.LocalAddr().(*net.UDPAddr).Port)
	tl, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		uc.Close()
		t.Fatalf("tcp listen on %d: %v", port, err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := uc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			_ = n
			_, _ = uc.WriteToUDPAddrPort(udpReply, addr)
		}
	}()
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				var pfx [2]byte
				binary.BigEndian.PutUint16(pfx[:], uint16(len(tcpReply)))
				_, _ = c.Write(append(pfx[:], tcpReply...))
			}(c)
		}
	}()
	return port, func() { uc.Close(); tl.Close() }
}

func itoa(p uint16) string {
	if p == 0 {
		return "0"
	}
	var b []byte
	for p > 0 {
		b = append([]byte{byte('0' + p%10)}, b...)
		p /= 10
	}
	return string(b)
}

func withDNSPort(t *testing.T, p uint16) {
	t.Helper()
	old := dnsPort
	dnsPort = p
	t.Cleanup(func() { dnsPort = old })
}

// TestUDPExchangeNoSelfTruncate (F2) — a large (>1500B) UDP answer with NO TC bit must come back INTACT,
// not clipped to a fixed 1500-byte buffer.
func TestUDPExchangeNoSelfTruncate(t *testing.T) {
	big := make([]byte, 2000)
	big[0], big[1] = 0x12, 0x34 // header id
	// byte 2 has NO TC bit → a plain (large) UDP answer.
	for i := 12; i < len(big); i++ {
		big[i] = byte(i)
	}
	port, stop := fakeResolver(t, big, nil)
	defer stop()
	withDNSPort(t, port)
	resp, err := udpExchange(netip.MustParseAddr("127.0.0.1"), mkQuery("nas.corp.local."))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if len(resp) != len(big) {
		t.Fatalf("large answer truncated: got %d bytes, want %d", len(resp), len(big))
	}
}

// TestUDPExchangeFollowsTCToTCP (F2) — an upstream UDP reply with the TC bit set triggers a TCP re-query,
// and the FULL TCP answer is what's returned (never the truncated UDP stub).
func TestUDPExchangeFollowsTCToTCP(t *testing.T) {
	udpStub := []byte{0x12, 0x34, 0x02, 0x00} // byte 2 = 0x02 → TC set (truncated)
	tcpFull := make([]byte, 3000)
	tcpFull[0], tcpFull[1] = 0x12, 0x34
	for i := 12; i < len(tcpFull); i++ {
		tcpFull[i] = byte(i * 7)
	}
	port, stop := fakeResolver(t, udpStub, tcpFull)
	defer stop()
	withDNSPort(t, port)
	resp, err := udpExchange(netip.MustParseAddr("127.0.0.1"), mkQuery("nas.corp.local."))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if len(resp) != len(tcpFull) {
		t.Fatalf("TC must fall back to TCP for the full answer: got %d bytes, want %d", len(resp), len(tcpFull))
	}
}

// TestUDPExchangeTCPFallbackFailsServfail (F2) — TC set but TCP unavailable → error (caller SERVFAILs),
// never a silently-truncated reply.
func TestUDPExchangeTCPFallbackFailsServfail(t *testing.T) {
	udpStub := []byte{0x12, 0x34, 0x02, 0x00} // TC set
	// UDP-only fake: TCP listener closed immediately so the fallback dial fails.
	uc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	defer uc.Close()
	port := uint16(uc.LocalAddr().(*net.UDPAddr).Port)
	go func() {
		buf := make([]byte, 4096)
		for {
			_, addr, err := uc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			_, _ = uc.WriteToUDPAddrPort(udpStub, addr)
		}
	}()
	withDNSPort(t, port)
	if _, err := udpExchange(netip.MustParseAddr("127.0.0.1"), mkQuery("nas.corp.local.")); err == nil {
		t.Fatal("TC with no TCP fallback must error (→ SERVFAIL), not return the truncated stub")
	}
}
