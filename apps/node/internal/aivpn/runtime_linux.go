//go:build linux

package aivpn

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func observeInterface(ctx context.Context, name string, address netip.Addr) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil || iface.Flags&net.FlagUp == 0 {
		return 0, errors.New("VPN interface unavailable")
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return 0, err
	}
	found := false
	for _, raw := range addrs {
		prefix, err := netip.ParsePrefix(raw.String())
		if err == nil && prefix.Addr() == address {
			found = true
		}
	}
	if !found {
		return 0, errors.New("VPN address unavailable")
	}
	// net.Interface alone cannot distinguish a WireGuard device from another
	// interface with the same name. A kernel WireGuard readback is mandatory.
	if _, err := kernelPeers(ctx, name); err != nil {
		return 0, err
	}
	return iface.Index, nil
}

func listenInterface(ctx context.Context, iface, address string) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var bindErr error
		if err := raw.Control(func(fd uintptr) {
			bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		return bindErr
	}}
	return lc.Listen(ctx, "tcp4", address)
}

func kernelPeers(ctx context.Context, iface string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "wg", "show", iface, "allowed-ips")
	var out boundedReadback
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", errors.New("WireGuard peer readback unavailable")
	}
	return out.String(), nil
}

type boundedReadback struct{ bytes.Buffer }

func (b *boundedReadback) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 1<<20 {
		return 0, errors.New("WireGuard peer readback too large")
	}
	return b.Buffer.Write(p)
}
