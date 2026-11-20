//go:build linux

package reconcile

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// NewHostNetworkProbe returns the Linux host probe (SSI-7). tunnelIfaces names overlay devices the agent
// owns (its WireGuard interface); WireGuard and TUN/TAP devices are also recognised from sysfs, so an
// OpenVPN tun or a second WireGuard device is never mistaken for a LAN.
func NewHostNetworkProbe(tunnelIfaces ...string) *HostNetworkProbe {
	owned := map[string]bool{}
	for _, n := range tunnelIfaces {
		if n != "" {
			owned[n] = true
		}
	}
	return &HostNetworkProbe{
		Networks: func() []HostNetwork { return linuxHostNetworks(owned) },
		RouteDev: linuxRouteDev,
	}
}

func linuxHostNetworks(owned map[string]bool) []HostNetwork {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []HostNetwork
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		tunnel := owned[ifc.Name] || isTunnelDevice(ifc.Name)
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			v4 := ipnet.IP.To4()
			if v4 == nil {
				continue
			}
			addr, ok := netip.AddrFromSlice(v4)
			ones, bits := ipnet.Mask.Size()
			if !ok || bits != 32 {
				continue
			}
			out = append(out, HostNetwork{
				Prefix: netip.PrefixFrom(addr, ones).Masked(), Addr: addr, Iface: ifc.Name, Tunnel: tunnel,
			})
		}
	}
	return out
}

// isTunnelDevice recognises overlay devices from sysfs: a TUN/TAP device exposes tun_flags, and a WireGuard
// or IPsec virtual device names itself in its uevent DEVTYPE.
func isTunnelDevice(name string) bool {
	base := filepath.Join("/sys/class/net", filepath.Base(name))
	if _, err := os.Stat(filepath.Join(base, "tun_flags")); err == nil {
		return true
	}
	f, err := os.Open(filepath.Join(base, "uevent"))
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		switch strings.TrimSpace(sc.Text()) {
		case "DEVTYPE=wireguard", "DEVTYPE=vti", "DEVTYPE=xfrm", "DEVTYPE=ipip", "DEVTYPE=gre":
			return true
		}
	}
	return false
}

// linuxRouteDev asks the kernel which interface it would use for addr.
func linuxRouteDev(addr netip.Addr) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", "-o", "route", "get", addr.String()).Output()
	if err != nil {
		return "", false
	}
	return parseRouteGetDev(string(out))
}
