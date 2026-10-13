//go:build linux

package ipsec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Two fresh disconnected containers, synthetic fixture keys only. Real kernel
// AES256-CBC/SHA256-128 ESPinUDP in both directions; no CP or AWS authority.
func TestUnderlayDualNativeEncryptedTransfer(t *testing.T) {
	role := os.Getenv("TUNNEX_UNDERLAY_DUAL_ROLE")
	if role != "client" && role != "server" {
		t.Skip("owned disconnected dual-container fixture only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	run := func(args ...string) []byte {
		t.Helper()
		b, e := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		if e != nil {
			t.Fatalf("fixture %s %v %s", args[0], e, b)
		}
		return b
	}
	if !runtimeQualifiedHookCensus(ctx, "/usr/sbin/nft", run("nft", "-j", "list", "ruleset"), nil) || len(bytes.TrimSpace(run("ip", "xfrm", "state"))) != 0 {
		t.Fatal("foreign nft/XFRM")
	}
	local, remote, inner, peer, spiout, spiin := "198.18.240.10", "198.18.240.20", "10.10.0.1", "10.20.0.1", "0x701", "0x702"
	if role == "server" {
		local, remote = remote, local
		inner, peer = peer, inner
		spiout, spiin = spiin, spiout
	}
	links := run("ip", "-j", "link", "show", "eth0")
	var l []map[string]any
	if json.Unmarshal(links, &l) != nil || len(l) != 1 || l[0]["mtu"] != float64(1300) {
		t.Fatal("actual outer MTU1300 required")
	}
	run("ip", "link", "add", "dfowned", "type", "xfrm", "if_id", "60001")
	defer exec.Command("ip", "link", "del", "dfowned").Run()
	run("ip", "link", "set", "dfowned", "mtu", "1230", "up")
	run("ip", "addr", "add", inner+"/32", "dev", "dfowned")
	run("ip", "route", "add", peer+"/32", "dev", "dfowned", "proto", "242")
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_UDP, 100, 2); err != nil {
		t.Fatal("UDP_ENCAP_ESPINUDP", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: 4500}); err != nil {
		t.Fatal(err)
	}
	key := "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	for _, r := range [][3]string{{local, remote, spiout}, {remote, local, spiin}} {
		run("ip", "xfrm", "state", "add", "src", r[0], "dst", r[1], "proto", "esp", "spi", r[2], "reqid", "701", "mode", "tunnel", "if_id", "60001", "enc", "cbc(aes)", key, "auth-trunc", "hmac(sha256)", key, "128", "encap", "espinudp", "4500", "4500", "0.0.0.0")
		defer exec.Command("ip", "xfrm", "state", "delete", "src", r[0], "dst", r[1], "proto", "esp", "spi", r[2]).Run()
	}
	for _, r := range [][5]string{{"out", inner, peer, local, remote}, {"in", peer, inner, remote, local}} {
		run("ip", "xfrm", "policy", "add", "dir", r[0], "src", r[1]+"/32", "dst", r[2]+"/32", "if_id", "60001", "tmpl", "src", r[3], "dst", r[4], "proto", "esp", "reqid", "701", "mode", "tunnel")
		defer exec.Command("ip", "xfrm", "policy", "delete", "dir", r[0], "src", r[1]+"/32", "dst", r[2]+"/32", "if_id", "60001").Run()
	}
	nonce := os.Getenv("TUNNEX_UNDERLAY_DUAL_NONCE")
	if len(nonce) != 32 {
		t.Fatal("fresh harness nonce required")
	}
	port := 42001
	if role == "server" {
		port = 42002
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(inner), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(75 * time.Second))
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	setDF := func(value int) {
		t.Helper()
		var se error
		if err := raw.Control(func(f uintptr) {
			se = syscall.SetsockoptInt(int(f), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, value)
		}); err != nil || se != nil {
			t.Fatal("DF setting", err, se)
		}
	}
	setDF(syscall.IP_PMTUDISC_DONT)
	before := run("ip", "-s", "xfrm", "state", "list", "nokeys")
	snmpBefore := run("cat", "/proc/net/snmp")
	digest := sha256.New()
	buf := make([]byte, 65535)
	payload := func(size, index int) []byte {
		p := bytes.Repeat([]byte(nonce), (size+31)/32)[:size]
		binary.BigEndian.PutUint32(p[:4], uint32(index))
		return p
	}
	if role == "server" {
		fmt.Println("DUAL_READY")
		for index := 0; index < 1026; index++ {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				t.Fatal("server receive", index, err)
			}
			size := 4096
			if index == 0 {
				size = 1202
			}
			if !bytes.Equal(buf[:n], payload(size, index)) || addr.IP.String() != peer || addr.Port != 42001 {
				t.Fatal("authenticated fixture payload mismatch", index, n, addr)
			}
			if index >= 2 {
				digest.Write(buf[:n])
			}
			if _, err := conn.WriteToUDP(buf[:n], addr); err != nil {
				t.Fatal("echo", err)
			}
		}
	} else {
		addr := &net.UDPAddr{IP: net.ParseIP(peer), Port: 42002}
		for index := 0; index < 1026; index++ {
			size := 4096
			if index == 0 {
				size = 1202
				setDF(syscall.IP_PMTUDISC_DO)
			}
			if index == 1 {
				p := payload(1203, index)
				if _, err := conn.WriteToUDP(p, addr); err == nil || !strings.Contains(err.Error(), "message too long") {
					t.Fatal("DF1231 must fail", err)
				}
				setDF(syscall.IP_PMTUDISC_DONT)
			}
			p := payload(size, index)
			if _, err := conn.WriteToUDP(p, addr); err != nil {
				t.Fatal("client send", index, err)
			}
			n, got, err := conn.ReadFromUDP(buf)
			if err != nil || !bytes.Equal(buf[:n], p) || got.IP.String() != peer || got.Port != 42002 {
				t.Fatal("encrypted echo mismatch", index, n, got, err)
			}
			if index >= 2 {
				digest.Write(p)
			}
		}
	}
	after := run("ip", "-s", "xfrm", "state", "list", "nokeys")
	snmpAfter := run("cat", "/proc/net/snmp")
	t.Log("real bidirectional CBC256/SHA256128 NATT DFinner1230 success/1231 localreject; nonDF4096 reassembled; 4MiB eachdirection hash", hex.EncodeToString(digest.Sum(nil)), "role", role)
	// Only the explicit nokeys command can enter proof logs: iproute2 XFRM
	// ignores -j and prints text, unlike route/link inventories.
	for _, raw := range [][]byte{before, after} {
		if bytes.Count(raw, []byte("enc cbc(aes)")) != 2 || bytes.Count(raw, []byte("auth-trunc hmac(sha256)")) != 2 || bytes.Count(raw, []byte("encap type espinudp")) != 2 || !bytes.Contains(raw, []byte("lifetime current:")) {
			t.Fatal("no-key actual SA crypto/counter inventory")
		}
		t.Log("actual nokeys SA transforms/counters", string(raw))
	}

	t.Log("fragment/reassembly counters before", strconv.Quote(string(snmpBefore)), "after", strconv.Quote(string(snmpAfter)))
}
