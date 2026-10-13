// Linux-only local test observer: no payload logging, promiscuity, or mutations.
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) != 5 {
		panic("four exact owned interface names required")
	}
	allowed := map[int]string{}
	for _, name := range os.Args[1:] {
		iface, e := net.InterfaceByName(name)
		if e != nil || iface.Index <= 0 {
			panic("owned interface absent")
		}
		if _, exists := allowed[iface.Index]; exists {
			panic("duplicate interface identity")
		}
		allowed[iface.Index] = name
	}
	// ETH_P_IP in network byte order. No membership/promiscuous request is made.
	fd, e := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, 0x0008)
	if e != nil {
		panic("metadata socket unavailable")
	}
	defer syscall.Close(fd)
	tv := syscall.Timeval{Sec: 0, Usec: 200000}
	if syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv) != nil {
		panic("bounded read unavailable")
	}
	deadline := time.Now().Add(8 * time.Second)
	buf := make([]byte, 1600)
	packets := 0
	encoder := json.NewEncoder(os.Stdout)
	for time.Now().Before(deadline) && packets < 100 {
		n, from, e := syscall.Recvfrom(fd, buf, 0)
		if e == syscall.EAGAIN || e == syscall.EINTR {
			continue
		}
		if e != nil {
			panic("metadata read unavailable")
		}
		ll, ok := from.(*syscall.SockaddrLinklayer)
		if !ok {
			continue
		}
		name, ok := allowed[ll.Ifindex]
		if !ok || n < 20 {
			continue
		}
		offset := 0
		switch ll.Hatype {
		case 1:
			if n < 34 || binary.BigEndian.Uint16(buf[12:14]) != 0x0800 {
				continue
			}
			offset = 14
		case 65534:
		default:
			continue
		}
		ip := buf[offset:n]
		if len(ip) < 20 || ip[0]>>4 != 4 || ip[9] != 6 || binary.BigEndian.Uint16(ip[6:8])&0x1fff != 0 {
			continue
		}

		ihl := int(ip[0]&15) * 4
		if ihl < 20 || len(ip) < ihl+20 {
			continue
		}
		src := net.IP(ip[12:16]).String()
		dst := net.IP(ip[16:20]).String()
		tcp := ip[ihl:]
		if int(tcp[12]>>4)*4 < 20 || int(tcp[12]>>4)*4 > len(tcp) {
			continue
		}
		sp := binary.BigEndian.Uint16(tcp[:2])
		dp := binary.BigEndian.Uint16(tcp[2:4])
		if !((src == "10.10.0.2" && dst == "10.20.0.2" && dp == 18080) || (src == "10.20.0.2" && dst == "10.10.0.2" && sp == 18080)) {
			continue
		}
		packets++
		encoder.Encode(struct {
			At              string `json:"at"`
			IfIndex         int    `json:"ifindex"`
			Interface       string `json:"interface"`
			PacketType      uint8  `json:"packet_type"`
			Source          string `json:"source"`
			Destination     string `json:"destination"`
			SourcePort      uint16 `json:"source_port"`
			DestinationPort uint16 `json:"destination_port"`
			Flags           byte   `json:"tcp_flags"`
		}{time.Now().UTC().Format(time.RFC3339Nano), ll.Ifindex, name, ll.Pkttype, src, dst, sp, dp, tcp[13]})
	}
	fmt.Fprintf(os.Stderr, "bounded metadata observation complete: %d matching packets\n", packets)
}
