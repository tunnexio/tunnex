package flowlog

import "net/netip"

// ParsePacket extracts L3/L4 facts from a raw IPv4 or IPv6 packet (the nflog payload the
// kernel copies with each logged flow-start). Best-effort: ok=false for an unsupported IP
// version, a truncated header/extension chain, or an unparseable address — a bad packet is
// skipped, never guessed. TCP(6)/UDP(17) yield a destination port when the transport header
// is present; other protocols and non-initial IPv6 fragments yield port 0.
func ParsePacket(p []byte) (srcIP, dstIP, proto string, dstPort int, ok bool) {
	if len(p) == 0 {
		return "", "", "", 0, false
	}

	var nextHeader byte
	var transportOffset int
	var nonInitialFragment bool
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
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
		srcIP, dstIP = src.String(), dst.String()
		nextHeader, transportOffset = p[9], ihl
	case 6:
		if len(p) < 40 {
			return "", "", "", 0, false
		}
		src, ok1 := netip.AddrFromSlice(p[8:24])
		dst, ok2 := netip.AddrFromSlice(p[24:40])
		if !ok1 || !ok2 {
			return "", "", "", 0, false
		}
		srcIP, dstIP = src.String(), dst.String()
		nextHeader, transportOffset, nonInitialFragment, ok = ipv6Transport(p, p[6], 40)
		if !ok {
			return "", "", "", 0, false
		}
	default:
		return "", "", "", 0, false
	}

	switch nextHeader {
	case 6:
		proto = "tcp"
	case 17:
		proto = "udp"
	default:
		proto = "any"
	}
	if !nonInitialFragment && (proto == "tcp" || proto == "udp") && len(p) >= transportOffset+4 {
		dstPort = int(p[transportOffset+2])<<8 | int(p[transportOffset+3]) // L4 dst port = 3rd/4th bytes of the L4 header
	}
	return srcIP, dstIP, proto, dstPort, true
}

// ipv6Transport walks the bounded extension-header chain to the upper-layer protocol.
// Eight headers is far beyond a useful gateway flow while keeping attacker-controlled
// packets from making parsing unbounded. ESP cannot be inspected, so it remains `any`.
func ipv6Transport(p []byte, next byte, offset int) (byte, int, bool, bool) {
	nonInitialFragment := false
	for extensions := 0; ; extensions++ {
		switch next {
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
			if extensions >= 8 {
				return 0, 0, false, false
			}
			if len(p) < offset+2 {
				return 0, 0, false, false
			}
			headerLen := (int(p[offset+1]) + 1) * 8
			if headerLen < 8 || len(p) < offset+headerLen {
				return 0, 0, false, false
			}
			next, offset = p[offset], offset+headerLen
		case 44: // Fragment
			if extensions >= 8 {
				return 0, 0, false, false
			}
			if len(p) < offset+8 {
				return 0, 0, false, false
			}
			fragmentOffset := (uint16(p[offset+2])<<8 | uint16(p[offset+3])) >> 3
			nonInitialFragment = nonInitialFragment || fragmentOffset != 0
			next, offset = p[offset], offset+8
		case 51: // Authentication Header: length is in 32-bit words, minus 2
			if extensions >= 8 {
				return 0, 0, false, false
			}
			if len(p) < offset+2 {
				return 0, 0, false, false
			}
			headerLen := (int(p[offset+1]) + 2) * 4
			if headerLen < 8 || len(p) < offset+headerLen {
				return 0, 0, false, false
			}
			next, offset = p[offset], offset+headerLen
		default:
			return next, offset, nonInitialFragment, true
		}
	}
}
