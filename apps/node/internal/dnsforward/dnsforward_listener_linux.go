//go:build linux

package dnsforward

import (
	"context"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

// Bind both address AND ingress interface. Binding only the WG IP can accept
// packets routed to that IP on a physical interface, including a spoofed
// entitled UDP source. SO_BINDTODEVICE preserves the authenticated WG scope.
func interfaceDNSListenConfig(iface string) net.ListenConfig {
	return net.ListenConfig{Control: func(_ string, _ string, raw syscall.RawConn) error {
		if iface == "" {
			return errWGIfaceNotFound
		}
		var scopeErr error
		if err := raw.Control(func(fd uintptr) {
			scopeErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		return scopeErr
	}}
}
func listenUDPOnInterface(address netip.Addr, iface string) (udpListener, error) {
	config := interfaceDNSListenConfig(iface)
	packet, err := config.ListenPacket(context.Background(), "udp", netip.AddrPortFrom(address, dnsPort).String())
	if err != nil {
		return nil, err
	}
	conn, ok := packet.(*net.UDPConn)
	if !ok {
		packet.Close()
		return nil, errWGIfaceNotFound
	}
	return conn, nil
}
func listenTCPOnInterface(address netip.Addr, iface string) (net.Listener, error) {
	config := interfaceDNSListenConfig(iface)
	return config.Listen(context.Background(), "tcp", netip.AddrPortFrom(address, dnsPort).String())
}
