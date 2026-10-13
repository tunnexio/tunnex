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

// Component-only: synthetic permit/grant and tunnel authority over real isolated
// veth forwarding. This proves nft grammar/readback and SYN/SYNACK mangling,
// NOT SA encryption, production ownership qualification, CP lease or PMTUD.
func TestGuardMSSNativePackets(t *testing.T)         { runGuardMSSNativePackets(t, false) }
func TestGuardRelatedICMPNativePackets(t *testing.T) { runGuardMSSNativePackets(t, true) }
func runGuardMSSNativePackets(t *testing.T, related bool) {
	if os.Getenv("TUNNEX_IPSEC_MSS_LAB") != "1" {
		t.Skip("disconnected native component fixture only")
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
	c.Grants = []GuardGrant{{Source: netip.MustParsePrefix("10.10.0.1/32"), Destination: netip.MustParsePrefix("10.20.0.1/32"), Protocol: GuardTCP, PortLow: 8080, PortHigh: 8080}}
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
	receive := func(fd int, port uint16, want uint16) {
		t.Helper()
		b := make([]byte, 2048)
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			n, _, err := syscall.Recvfrom(fd, b, 0)
			if err != nil {
				continue
			}
			if n < 58 || b[14] != 0x45 {
				continue
			}
			tcp := b[34:n]
			if binary.BigEndian.Uint16(tcp[:2]) != port && binary.BigEndian.Uint16(tcp[2:4]) != port {
				continue
			}
			if tcp[20] != 2 || tcp[21] != 4 {
				t.Fatal("missing MSS option")
			}
			got := binary.BigEndian.Uint16(tcp[22:24])
			if got != want {
				t.Fatalf("actual MSS %d want%d", got, want)
			}
			return
		}
		t.Fatal("owned forwarded SYN packet absent")
	}
	send := func(fd int, peer, router *net.Interface, reply bool, port, mss uint16) {
		t.Helper()
		frame := mssFrame(peer.HardwareAddr, router.HardwareAddr, reply, port, mss)
		if err := syscall.Sendto(fd, frame, 0, &syscall.SockaddrLinklayer{Ifindex: peer.Index, Protocol: htons(0x0800), Halen: 6}); err != nil {
			t.Fatal(err)
		}
	}
	for k, mss := range []uint16{8961, 1200} {
		port := uint16(41000 + k)
		want := mss
		if want > 1382 {
			want = 1382
		}
		send(lf, lp, lan, false, port, mss)
		receive(tf, port, want)
		send(tf, tp, tun, true, port, mss)
		receive(lf, port, want)
	}

	// ANY grants must still scope the mangle expression to TCP. The UDP
	// payload deliberately resembles TCP flags and an MSS option.
	c.Grants[0].Protocol = GuardAny
	c.Grants[0].PortLow, c.Grants[0].PortHigh = 0, 0
	i.Revision++
	g, err = RenderGuard(i)
	if err != nil {
		t.Fatal(err)
	}
	run([]byte(g.NFTJSON), "nft", "-j", "-f", "-")
	actual = run(nil, "nft", "-j", "list", "table", "inet", "tunnex_ipsec")
	if err = VerifyGuardReadbackWithInterfaces([]byte(g.ExpectedJSON), actual, mapping); err != nil {
		t.Fatalf("native ANY MSS readback: %v\nexpected=%s\nactual=%s", err, g.ExpectedJSON, actual)
	}
	send(lf, lp, lan, false, 41003, 8961)
	receive(tf, 41003, 1382)
	udp := mssFrame(lp.HardwareAddr, lan.HardwareAddr, false, 41004, 8961)
	udp[23] = 17
	binary.BigEndian.PutUint16(udp[24:26], 0)
	binary.BigEndian.PutUint16(udp[24:26], mssChecksum(udp[14:34]))
	binary.BigEndian.PutUint16(udp[38:40], 24)
	binary.BigEndian.PutUint16(udp[40:42], 0) // IPv4 UDP checksum omitted legally.
	if err := syscall.Sendto(lf, udp, 0, &syscall.SockaddrLinklayer{Ifindex: lp.Index, Protocol: htons(0x0800), Halen: 6}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	foundUDP := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, _, e := syscall.Recvfrom(tf, buf, 0)
		if e != nil || n < len(udp) || buf[23] != 17 || binary.BigEndian.Uint16(buf[34:36]) != 41004 {
			continue
		}
		if !bytes.Equal(buf[34:58], udp[34:58]) {
			t.Fatal("ANY MSS rule mutated UDP payload")
		}
		foundUDP = true
		break
	}
	if !foundUDP {
		t.Fatal("ANY-granted UDP packet absent")
	}
	c.Grants[0].Protocol = GuardTCP
	c.Grants[0].PortLow, c.Grants[0].PortHigh = 8080, 8080
	i.Revision++
	g, err = RenderGuard(i)
	if err != nil {
		t.Fatal(err)
	}
	run([]byte(g.NFTJSON), "nft", "-j", "-f", "-")

	if related {
		received := func(want bool) {
			t.Helper()
			buf := make([]byte, 2048)
			deadline := time.Now().Add(550 * time.Millisecond)
			for time.Now().Before(deadline) {
				n, _, err := syscall.Recvfrom(lf, buf, 0)
				if err != nil {
					continue
				}
				if n >= 78 && buf[23] == 1 {
					if !want {
						t.Fatal("unapproved related ICMP forwarded")
					}
					if buf[34] != 3 || buf[35] != 4 {
						t.Fatal("wrong ICMP type/code forwarded")
					}
					return
				}
			}
			if want {
				t.Fatal("legitimate related fragment-needed blocked")
			}
		}
		inject := func(kind, code byte, quoteport uint16, router [4]byte) {
			t.Helper()
			frame := mssICMPFrame(tp.HardwareAddr, tun.HardwareAddr, kind, code, quoteport, router)
			if err := syscall.Sendto(tf, frame, 0, &syscall.SockaddrLinklayer{Ifindex: tp.Index, Protocol: htons(0x0800), Halen: 6}); err != nil {
				t.Fatal(err)
			}
		}
		for _, x := range []struct {
			kind, code byte
			port       uint16
			router     [4]byte
			want       bool
		}{{3, 4, 8080, [4]byte{10, 20, 0, 2}, true}, {8, 0, 8080, [4]byte{10, 20, 0, 2}, false}, {3, 3, 8080, [4]byte{10, 20, 0, 2}, false}, {3, 4, 8081, [4]byte{10, 20, 0, 2}, false}, {3, 4, 8080, [4]byte{10, 21, 0, 2}, false}} {
			inject(x.kind, x.code, x.port, x.router)
			received(x.want)
		}
		original := c.Grants
		c.Grants = nil
		i.Revision++
		g, err = RenderGuard(i)
		if err != nil {
			t.Fatal(err)
		}
		run([]byte(g.NFTJSON), "nft", "-j", "-f", "-")
		inject(3, 4, 8080, [4]byte{10, 20, 0, 2})
		received(false)

		c.Grants = original
		c.ReplyIngressIndices = nil
		i.Revision++
		g, err = RenderGuard(i)
		if err != nil {
			t.Fatal(err)
		}
		run([]byte(g.NFTJSON), "nft", "-j", "-f", "-")
		inject(3, 4, 8080, [4]byte{10, 20, 0, 2})
		received(false)
		c.ReplyIngressIndices = []int{tun.Index}
		c.Grants = original
		c.PermitFor = time.Second
		i.Revision++
		g, err = RenderGuard(i)
		if err != nil {
			t.Fatal(err)
		}
		run([]byte(g.NFTJSON), "nft", "-j", "-f", "-")
		time.Sleep(1250 * time.Millisecond)
		inject(3, 4, 8080, [4]byte{10, 20, 0, 2})
		received(false)
		c.PermitFor = 30 * time.Second
		i.Revision++
		g, err = RenderGuard(i)
		if err != nil {
			t.Fatal(err)
		}
		run([]byte(g.NFTJSON), "nft", "-j", "-f", "-")
		t.Log("actual NFCT related fragment-needed only exact TCP parent; wrong type/code/quotedport/router, withdrawn grant and expired lease denied")
	}
	// A subsequent lower observed tunnel MTU gets a smaller bound, not 1382.
	run(nil, "ip", "link", "set", "dev", "msstun", "mtu", "1300")
	c.TunnelMTUs[0].MTU = 1300
	i.Revision++
	g, err = RenderGuard(i)
	if err != nil {
		t.Fatal(err)
	}
	run([]byte(g.NFTJSON), "nft", "-j", "-f", "-")
	send(lf, lp, lan, false, 41002, 8961)
	receive(tf, 41002, 1260)
	send(tf, tp, tun, true, 41002, 8961)
	receive(lf, 41002, 1260)
	t.Log("real nft readback; SYN/SYNACK 8961->1382, 1200 unchanged, MTU1300->1260; synthetic component authority only")
}
func htons(v uint16) uint16 { return v<<8 | v>>8 }
func mssChecksum(b []byte) uint16 {
	var sum uint32
	for len(b) > 1 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}
func mssFrame(srcmac, dstmac net.HardwareAddr, reply bool, port, mss uint16) []byte {
	b := make([]byte, 58)
	copy(b[:6], dstmac)
	copy(b[6:12], srcmac)
	binary.BigEndian.PutUint16(b[12:14], 0x0800)
	ip := b[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 44)
	ip[8] = 64
	ip[9] = 6
	src, dst := [4]byte{10, 10, 0, 1}, [4]byte{10, 20, 0, 1}
	if reply {
		src, dst = dst, src
	}
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	binary.BigEndian.PutUint16(ip[10:12], mssChecksum(ip))
	tcp := b[34:]
	sport, dport := port, uint16(8080)
	if reply {
		sport, dport = dport, sport
	}
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], 1000)
	tcp[12] = 6 << 4
	tcp[13] = 2
	if reply {
		tcp[13] = 0x12
		binary.BigEndian.PutUint32(tcp[8:12], 1001)
	}
	binary.BigEndian.PutUint16(tcp[14:16], 32768)
	tcp[20] = 2
	tcp[21] = 4
	binary.BigEndian.PutUint16(tcp[22:24], mss)
	pseudo := append([]byte{}, src[:]...)
	pseudo = append(pseudo, dst[:]...)
	pseudo = append(pseudo, 0, 6, 0, 24)
	pseudo = append(pseudo, tcp...)
	binary.BigEndian.PutUint16(tcp[16:18], mssChecksum(pseudo))
	return b
}

func mssICMPFrame(srcmac, dstmac net.HardwareAddr, kind, code byte, quotedPort uint16, router [4]byte) []byte {
	b := make([]byte, 78)
	copy(b[:6], dstmac)
	copy(b[6:12], srcmac)
	binary.BigEndian.PutUint16(b[12:14], 0x0800)
	ip := b[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 64)
	ip[8] = 64
	ip[9] = 1
	copy(ip[12:16], router[:])
	copy(ip[16:20], []byte{10, 10, 0, 1})
	binary.BigEndian.PutUint16(ip[10:12], mssChecksum(ip))
	icmp := b[34:]
	icmp[0] = kind
	icmp[1] = code
	binary.BigEndian.PutUint16(icmp[6:8], 1300)
	quoted := mssFrame(srcmac, dstmac, false, 41000, 8961)[14:42]
	copy(icmp[8:], quoted)
	binary.BigEndian.PutUint16(icmp[30:32], quotedPort)
	binary.BigEndian.PutUint16(icmp[2:4], mssChecksum(icmp))
	return b
}
