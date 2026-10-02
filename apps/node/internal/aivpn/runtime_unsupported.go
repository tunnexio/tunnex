//go:build !linux

package aivpn

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

func observeInterface(context.Context, string, netip.Addr) (int, error) {
	return 0, errors.New("native WireGuard VPN AI requires Linux")
}
func listenInterface(context.Context, string, string) (net.Listener, error) {
	return nil, errors.New("VPN interface binding requires Linux")
}
func kernelPeers(context.Context, string) (string, error) {
	return "", errors.New("native WireGuard peer identity requires Linux")
}
