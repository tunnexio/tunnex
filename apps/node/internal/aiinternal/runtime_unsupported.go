//go:build !linux

package aiinternal

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

func ownedAddress(netip.Addr) error {
	return errors.New("the internal AI endpoint requires Linux")
}

func listenTCP4(context.Context, string) (net.Listener, error) {
	return nil, errors.New("the internal AI endpoint requires Linux")
}
