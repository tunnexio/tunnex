package flowlog

import "net/netip"

// ParsePacket extracts L3/L4 facts from a raw IPv4 packet (the nflog payload the kernel
// copies with each logged flow-start). Best-effort: ok=false for non-IPv4, truncated, or
// unparseable — a bad packet is skipped, never guessed. IPv4 only (the pool is v4). TCP(6)/
// UDP(17) yield a dst port; other protocols yield port 0 + "any".
func ParsePacket(p []byte) (srcIP, dstIP, proto string, dstPort int, ok bool) {
	if len(p) < 20 || p[0]>>4 != 4 { // need a full IPv4 header, version 4
		return "", "", "", 0, false
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || len(p) < ihl {
		return "", "", "", 0, false
	}
	src, ok1 := netip.AddrFromSlice(p[12:16])
	dst, ok2 := netip.AddrFromSlice(p[16:20])
	if !ok1 || !ok2 {
		return "", "", "", 0, false
	}
	switch p[9] { // IP protocol field
	case 6:
		proto = "tcp"
	case 17:
		proto = "udp"
	default:
		proto = "any"
	}
	if (proto == "tcp" || proto == "udp") && len(p) >= ihl+4 {
		dstPort = int(p[ihl+2])<<8 | int(p[ihl+3]) // L4 dst port = 3rd/4th bytes of the L4 header
	}
	return src.String(), dst.String(), proto, dstPort, true
}
