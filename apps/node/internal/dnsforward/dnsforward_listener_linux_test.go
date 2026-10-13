//go:build linux

package dnsforward

import (
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Run this bounded socket fixture on the owned Linux gateway after lifecycle
// qualification. It creates no interfaces, routes, policy or cloud resources.
func TestNativeDNSDeviceListenerScope(t *testing.T) {
	if os.Getenv("TUNNEX_TEST_NATIVE_DNS_LISTENER") != "1" {
		t.Skip("explicit owned Linux native socket qualification")
	}
	old := dnsPort
	dnsPort = 0
	defer func() { dnsPort = old }()
	address := netip.MustParseAddr("127.0.0.1")
	udp, err := listenUDPOnInterface(address, "lo")
	if err != nil {
		t.Fatal("native interface-bound UDP refused", err)
	}
	defer udp.Close()
	tcp, err := listenTCPOnInterface(address, "lo")
	if err != nil {
		t.Fatal("native interface-bound TCP refused", err)
	}
	defer tcp.Close()
	for _, socket := range []syscall.Conn{udp.(*net.UDPConn), tcp.(*net.TCPListener)} {
		raw, err := socket.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var device string
		var observed error
		if err := raw.Control(func(fd uintptr) {
			device, observed = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
		}); err != nil {
			t.Fatal(err)
		}
		if observed != nil || device != "lo" {
			t.Fatal("DNS listener lost actual ingress scope", device, observed)
		}
	}
	for _, iface := range []string{"", "tnx-dns-missing"} {
		if listener, err := listenUDPOnInterface(address, iface); err == nil {
			listener.Close()
			t.Fatal("UDP fell back from absent interface")
		}
		if listener, err := listenTCPOnInterface(address, iface); err == nil {
			listener.Close()
			t.Fatal("TCP fell back from absent interface")
		}
	}
}
