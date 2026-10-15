package dnsforward

import (
	"encoding/binary"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// The loopback override is test-only: production compileLANListener refuses it.
// It exercises real sockets without claiming private-interface/native bind proof.
func TestLANRealUDPTCPSocketsAndAcceptedSessionWithdrawal(t *testing.T) {
	f := New(nil, nil)
	defer f.closeOwnedBinds()
	p := lanProfileFixture()
	f.SetResolverProfiles([]ResolverProfile{p})
	f.profiles.Load().entries[0].lan.sources = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
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
	f.reconcileLANBinds("wg0")
	if udp == nil || tcp == nil || len(f.AppliedLANListeners()) != 1 || !f.AppliedLANListeners()[0].Ready {
		t.Fatal("fixture sockets absent")
	}
	udpClient, err := net.Dial("udp", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udpClient.Close()
	_ = udpClient.SetDeadline(time.Now().Add(time.Second))
	query := queryType("alias.office.test.", dnsmessage.TypeAAAA)
	if _, err := udpClient.Write(query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := udpClient.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if m := decodeDNS(t, buf[:n]); len(m.Answers) != 2 || m.Answers[1].Header.Type != dnsmessage.TypeAAAA {
		t.Fatal("real UDP static alias lost address", m)
	}
	tcpClient, err := net.Dial("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tcpClient.Close()
	_ = tcpClient.SetDeadline(time.Now().Add(time.Second))
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)
	if _, err := tcpClient.Write(frame); err != nil {
		t.Fatal(err)
	}
	var size [2]byte
	if _, err := io.ReadFull(tcpClient, size[:]); err != nil {
		t.Fatal(err)
	}
	answer := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(tcpClient, answer); err != nil {
		t.Fatal(err)
	}
	if m := decodeDNS(t, answer); len(m.Answers) != 2 {
		t.Fatal("real TCP static alias lost address", m)
	}
	f.SetResolverProfiles(nil)
	f.reconcileLANBinds("wg0")
	_ = tcpClient.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := tcpClient.Read(buf); err == nil {
		t.Fatal("profile deletion left accepted TCP session open")
	}
	if len(f.AppliedLANListeners()) != 0 {
		t.Fatal("deleted listeners reported ready")
	}
}
