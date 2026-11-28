//go:build linux

package aiinternal

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

// ownedAddress requires the address on exactly one active, non-loopback interface of this host, like
// the DNS LAN listener's ownership check. An unreadable interface list is a refusal.
func ownedAddress(address netip.Addr) error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return errors.New("interfaces unavailable")
	}
	owners := 0
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return errors.New("interface addresses unavailable")
		}
		for _, raw := range addrs {
			prefix, err := netip.ParsePrefix(raw.String())
			if err != nil || prefix.Addr().Unmap() != address {
				continue
			}
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				return errors.New("address is not on an active non-loopback interface")
			}
			owners++
		}
	}
	if owners != 1 {
		return errors.New("address is not owned by exactly one interface")
	}
	return nil
}

// listenTCP4 binds the address without SO_BINDTODEVICE: VPN and site traffic to a LAN address arrives
// on the tunnel interface, which a device-bound socket would refuse. The source filter is the guard.
func listenTCP4(ctx context.Context, address string) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(ctx, "tcp4", address)
}
