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
	"strconv"
	"syscall"
	"testing"
	"time"
)

// Disconnected component only: real owned kernel links, verified NFT denial,
// production lowering and real outbound AES-CBC/SHA256-128 UDP-encapsulated ESP.
// Synthetic keys/authority; no inbound decryption or CP/AWS traffic claim.
func TestUnderlayMTUNativeEncryptedDFBoundary(t *testing.T) {
	if os.Getenv("TUNNEX_UNDERLAY_MTU_LAB") != "1" {
		t.Skip("fresh disconnected native namespace only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	run := func(args ...string) []byte {
		t.Helper()
		b, e := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		if e != nil {
			t.Fatalf("fixture command %s: %v %s", args[0], e, b)
		}
		return b
	}
	var links []map[string]any
	if json.Unmarshal(run("ip", "-j", "link", "show"), &links) != nil || len(links) != 1 || links[0]["ifname"] != "lo" {
		t.Fatal("requires fresh networknone")
	}
	if bytes.Contains(run("nft", "-j", "list", "tables"), []byte(`"table"`)) {
		t.Fatal("foreign nft tables")
	}
	e := bgpEntryFixture(t)
	p := e.Allocation
	p.Namespace, _ = os.Readlink("/proc/self/ns/net")
	a, err := NewKernelApplier("/sbin/ip")
	if err != nil {
		t.Fatal(err)
	}
	own, err := a.Apply(ctx, p, [2]Ownership{})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Remove(context.Background(), p, own)
	guard, err := RenderGuard(GuardIntent{Namespace: p.Namespace, OwnerID: e.Engines[0].Binding.GatewayID, Revision: 1, Connections: []GuardConnection{{ID: p.ConnectionID, Local: e.Engines[0].LocalPrefixes, Remote: e.Engines[0].RemotePrefixes, PrefixOnly: true}}})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "nft", "-j", "-f", "-")
	cmd.Stdin = bytes.NewBufferString(guard.NFTJSON)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("denial install %v %s", err, b)
	}
	defer exec.Command("nft", "delete", "table", "inet", "tunnex_ipsec").Run()
	deny := func(context.Context) error {
		raw := run("nft", "-j", "list", "table", "inet", "tunnex_ipsec")
		return VerifyGuardReadback([]byte(guard.ExpectedJSON), raw)
	}
	if err := a.LowerTunnelMTUs(ctx, p, own, [2]uint32{1300, 1300}, nil, deny); err != nil {
		t.Fatal(err)
	}
	snap, err := a.snapshotBGPRoutes(ctx, p, nil)
	if err != nil || snap.mtu != [2]uint64{1230, 1230} {
		t.Fatal("owned inner ceiling", err, snap.mtu)
	}
	run("ip", "link", "add", "outermtu", "type", "veth", "peer", "name", "wiremtu")
	defer exec.Command("ip", "link", "del", "outermtu").Run()
	for _, n := range []string{"outermtu", "wiremtu"} {
		run("ip", "link", "set", n, "mtu", "1300", "up")
	}
	run("ip", "addr", "add", "198.18.0.1/24", "dev", "outermtu")
	wire, _ := net.InterfaceByName("wiremtu")
	if wire == nil {
		t.Fatal("wire identity")
	}
	run("ip", "neigh", "add", "198.18.0.2", "lladdr", wire.HardwareAddr.String(), "nud", "permanent", "dev", "outermtu")
	tun := p.Tunnels[0]
	xid := strconv.FormatUint(uint64(tun.XFRMID), 10)
	key := "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	run("ip", "xfrm", "state", "add", "src", "198.18.0.1", "dst", "198.18.0.2", "proto", "esp", "spi", "0x601", "reqid", "601", "mode", "tunnel", "if_id", xid, "enc", "cbc(aes)", key, "auth-trunc", "hmac(sha256)", key, "128", "encap", "espinudp", "4500", "4500", "0.0.0.0")
	defer exec.Command("ip", "xfrm", "state", "delete", "src", "198.18.0.1", "dst", "198.18.0.2", "proto", "esp", "spi", "0x601").Run()
	src, dst := tun.InsideAddress.Addr(), tun.BGP.Peer
	run("ip", "xfrm", "policy", "add", "dir", "out", "src", netip.PrefixFrom(src, 32).String(), "dst", netip.PrefixFrom(dst, 32).String(), "if_id", xid, "tmpl", "src", "198.18.0.1", "dst", "198.18.0.2", "proto", "esp", "reqid", "601", "mode", "tunnel")
	defer exec.Command("ip", "xfrm", "policy", "delete", "dir", "out", "src", netip.PrefixFrom(src, 32).String(), "dst", netip.PrefixFrom(dst, 32).String(), "if_id", xid).Run()
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0800)))
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(0x0800), Ifindex: wire.Index}); err != nil {
		t.Fatal(err)
	}
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 1})
	udp, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(udp)
	if err := syscall.SetsockoptInt(udp, syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DO); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Bind(udp, &syscall.SockaddrInet4{Addr: src.As4(), Port: 42001}); err != nil {
		t.Fatal(err)
	}
	dest := &syscall.SockaddrInet4{Addr: dst.As4(), Port: 42002}
	if err := syscall.Sendto(udp, bytes.Repeat([]byte{0x5a}, 1202), 0, dest); err != nil {
		t.Fatal("inner1230", err)
	}
	buf := make([]byte, 2048)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil || n < 34 || buf[23] != 17 || binary.BigEndian.Uint16(buf[16:18]) != 1300 || binary.BigEndian.Uint16(buf[34:36]) != 4500 || binary.BigEndian.Uint16(buf[36:38]) != 4500 || binary.BigEndian.Uint32(buf[42:46]) != 0x601 {
		t.Fatalf("actual NATT outer1300 missing n=%d err=%v", n, err)
	}
	if err := syscall.Sendto(udp, bytes.Repeat([]byte{0x5a}, 1203), 0, dest); err != syscall.EMSGSIZE {
		t.Fatalf("inner1231 DF must EMSGSIZE got%v", err)
	}
	if n, _, err := syscall.Recvfrom(fd, buf, 0); err == nil {
		t.Fatalf("oversize emitted packet%d", n)
	}
	t.Log("real owned denial/lowering1230; AES-CBC256 SHA256-128 NATT inner1230 emits outer1300; inner1231 DF EMSGSIZE/no wire packet; outbound-only synthetic component")
}
