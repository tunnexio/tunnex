//go:build !linux

package dnsforward

import (
	"net"
	"net/netip"
)

// Native gateway DNS listener scope is qualified only on Linux. An unsupported
// host must not replace interface-bound listeners with address-only listeners.
func listenUDPOnInterface(netip.Addr, string) (udpListener, error)  { return nil, errWGIfaceNotFound }
func listenTCPOnInterface(netip.Addr, string) (net.Listener, error) { return nil, errWGIfaceNotFound }
