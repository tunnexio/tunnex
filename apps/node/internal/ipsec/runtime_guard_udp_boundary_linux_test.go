//go:build linux

package ipsec

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// Routed UDP-only component; no encryption/CP claim.
func TestGuardUDPBoundaryNative(t *testing.T) {
	if os.Getenv("TUNNEX_IPSEC_UDP_BOUNDARY_LAB") != "1" {
		t.Skip("owned isolated fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	run := func(input []byte, args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Stdin = bytes.NewReader(input)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("owned fixture command %v: %v %s", args, err, out)
		}
		return out
	}
	if string(bytes.TrimSpace(run(nil, "cat", "/proc/sys/net/ipv4/ip_forward"))) != "1" {
		t.Fatal("fixture must declare ip_forward=1 before start")
	}
	var links []map[string]any
	if json.Unmarshal(run(nil, "ip", "-j", "link", "show"), &links) != nil || len(links) != 1 || links[0]["ifname"] != "lo" {
		t.Fatal("requires fresh networknone namespace")
	}
	tables := run(nil, "nft", "-j", "list", "tables")
	if bytes.Contains(tables, []byte(`"table"`)) {
		t.Fatal("foreign nft tables present")
	}
	run(nil, "ip", "link", "add", "msslan", "type", "veth", "peer", "name", "msslpeer")
	defer exec.Command("ip", "link", "del", "msslan").Run()
	run(nil, "ip", "link", "add", "msstun", "type", "veth", "peer", "name", "msstpeer")
	defer exec.Command("ip", "link", "del", "msstun").Run()
	run(nil, "ip", "link", "add", "mssspare", "type", "dummy")
	defer exec.Command("ip", "link", "del", "mssspare").Run()
	for _, name := range []string{"msslan", "msslpeer", "msstun", "msstpeer", "mssspare"} {
		run(nil, "ip", "link", "set", "dev", name, "up")
	}
	run(nil, "ip", "link", "set", "dev", "msstun", "mtu", "1422")
	run(nil, "ip", "addr", "add", "10.10.0.254/24", "dev", "msslan")
	run(nil, "ip", "addr", "add", "10.20.0.254/24", "dev", "msstun")
	lan, _ := net.InterfaceByName("msslan")
	lp, _ := net.InterfaceByName("msslpeer")
	tun, _ := net.InterfaceByName("msstun")
	tp, _ := net.InterfaceByName("msstpeer")
	spare, _ := net.InterfaceByName("mssspare")
	if lan == nil || lp == nil || tun == nil || tp == nil || spare == nil || tun.MTU != 1422 {
		t.Fatal("actual interface identity absent")
	}
	run(nil, "ip", "neigh", "add", "10.10.0.1", "lladdr", lp.HardwareAddr.String(), "nud", "permanent", "dev", lan.Name)
	run(nil, "ip", "neigh", "add", "10.20.0.1", "lladdr", tp.HardwareAddr.String(), "nud", "permanent", "dev", tun.Name)
	ns := run(nil, "readlink", "/proc/self/ns/net")
	i := guardFixture()
	i.Namespace = string(bytes.TrimSpace(ns))
	c := &i.Connections[0]
	c.Tunnels = [2]Ownership{{Namespace: i.Namespace, InterfaceName: tun.Name, InterfaceIndex: tun.Index, XFRMID: 60001}, {Namespace: i.Namespace, InterfaceName: spare.Name, InterfaceIndex: spare.Index, XFRMID: 60002}}
	c.LocalIngressIndices = []int{lan.Index}
	c.PermittedInterfaceIndices = []int{tun.Index}
	c.ReplyIngressIndices = []int{tun.Index}
	c.TunnelMTUs = []GuardTunnelMTU{{tun.Index, 1422}}
	c.Grants = []GuardGrant{{Source: netip.MustParsePrefix("10.10.0.1/32"), Destination: netip.MustParsePrefix("10.20.0.1/32"), Protocol: GuardUDP, PortLow: 42002, PortHigh: 42002}}
	g, err := RenderGuard(i)
	if err != nil {
		t.Fatal(err)
	}
	run([]byte(g.NFTJSON), "nft", "-j", "-f", "-")
	defer exec.Command("nft", "delete", "table", "inet", "tunnex_ipsec").Run()
	actual := run(nil, "nft", "-j", "list", "table", "inet", "tunnex_ipsec")
	mapping := []GuardInterface{{Name: lan.Name, Index: lan.Index}, {Name: tun.Name, Index: tun.Index}, {Name: spare.Name, Index: spare.Index}}
	if err = VerifyGuardReadbackWithInterfaces([]byte(g.ExpectedJSON), actual, mapping); err != nil {
		t.Fatalf("native MSS semantic readback: %v\nexpected=%s\nactual=%s", err, g.ExpectedJSON, actual)
	}
	socket := func(iface *net.Interface) int {
		t.Helper()
		fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0800)))
		if err != nil {
			t.Fatal(err)
		}
		if syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(0x0800), Ifindex: iface.Index}) != nil {
			t.Fatal("packet bind")
		}
		syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Usec: 400000})
		t.Cleanup(func() { syscall.Close(fd) })
		return fd
	}

	lf, tf := socket(lp), socket(tp)
	for _, size := range []int{1421, 1422, 1423} {
		b := make([]byte, 14+size)
		copy(b[:6], lan.HardwareAddr)
		copy(b[6:12], lp.HardwareAddr)
		binary.BigEndian.PutUint16(b[12:14], 0x800)
		ip := b[14:34]
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], uint16(size))
		binary.BigEndian.PutUint16(ip[6:8], 0x4000)
		ip[8] = 64
		ip[9] = 17
		copy(ip[12:16], []byte{10, 10, 0, 1})
		copy(ip[16:20], []byte{10, 20, 0, 1})
		binary.BigEndian.PutUint16(ip[10:12], mssChecksum(ip))
		binary.BigEndian.PutUint16(b[34:36], 42001)
		binary.BigEndian.PutUint16(b[36:38], 42002)
		binary.BigEndian.PutUint16(b[38:40], uint16(size-20))
		if e := syscall.Sendto(lf, b, 0, &syscall.SockaddrLinklayer{Ifindex: lp.Index, Protocol: htons(0x800), Halen: 6}); e != nil {
			t.Fatal(e)
		}
		fd := tf
		if size > 1422 {
			fd = lf
		}
		found := false
		buf := make([]byte, 4096)
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			n, _, e := syscall.Recvfrom(fd, buf, 0)
			if e != nil || n < 42 {
				continue
			}
			if size <= 1422 && buf[23] == 17 && binary.BigEndian.Uint16(buf[16:18]) == uint16(size) {
				found = true
				break
			}
			if size > 1422 && buf[23] == 1 && buf[34] == 3 && buf[35] == 4 {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing UDP DF boundary size %d", size)
		}
		t.Log("actual UDP-only local boundary passed", size)
	}
	// Exact quoted UDP parent from approved remote router. Current shipping guard
	// intentionally lacks UDP RELATED exception; record actual denial, not success.
	f := mssICMPFrame(tp.HardwareAddr, tun.HardwareAddr, 3, 4, 42002, [4]byte{10, 20, 0, 2})
	q := f[42:62]
	q[9] = 17
	binary.BigEndian.PutUint16(q[10:12], 0)
	binary.BigEndian.PutUint16(q[10:12], mssChecksum(q))
	binary.BigEndian.PutUint16(f[62:64], 42001)
	binary.BigEndian.PutUint16(f[64:66], 42002)
	binary.BigEndian.PutUint16(f[36:38], 0)
	binary.BigEndian.PutUint16(f[36:38], mssChecksum(f[34:]))
	if err := syscall.Sendto(tf, f, 0, &syscall.SockaddrLinklayer{Ifindex: tp.Index, Protocol: htons(0x800), Halen: 6}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	until := time.Now().Add(700 * time.Millisecond)
	for time.Now().Before(until) {
		n, _, e := syscall.Recvfrom(lf, buf, 0)
		if e == nil && n >= 78 && buf[23] == 1 && buf[34] == 3 && buf[35] == 4 && bytes.Equal(buf[26:30], []byte{10, 20, 0, 2}) {
			t.Fatal("unexpected UDP remote related authority")
		}
	}
	t.Log("actual exact remote quoted UDP fragmentation-needed denied under UDP-only grant; no encrypted proof claimed")

}
