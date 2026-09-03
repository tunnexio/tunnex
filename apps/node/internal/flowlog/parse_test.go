package flowlog

import (
	"net/netip"
	"testing"
)

func TestParsePacket(t *testing.T) {
	// IPv4 TCP: 20-byte header, proto 6, src 10.99.0.10 -> dst 10.0.5.5, dst port 5432.
	pkt := []byte{
		0x45, 0x00, 0x00, 0x00, // v4, ihl=5
		0x00, 0x00, 0x00, 0x00,
		0x40, 0x06, 0x00, 0x00, // ttl, proto=6 (tcp)
		10, 99, 0, 10, // src
		10, 0, 5, 5, // dst
		0x30, 0x39, 0x15, 0x38, // L4: src port 12345, dst port 5432
	}
	src, dst, proto, port, ok := ParsePacket(pkt)
	if !ok || src != "10.99.0.10" || dst != "10.0.5.5" || proto != "tcp" || port != 5432 {
		t.Fatalf("tcp parse wrong: src=%s dst=%s proto=%s port=%d ok=%v", src, dst, proto, port, ok)
	}
	// UDP proto 17, no port bytes present past the header -> port 0 tolerated.
	udp := append([]byte{}, pkt...)
	udp[9] = 17
	if _, _, proto, _, ok := ParsePacket(udp); !ok || proto != "udp" {
		t.Fatalf("udp proto wrong: %s ok=%v", proto, ok)
	}
	// Unsupported IP version -> skipped.
	if _, _, _, _, ok := ParsePacket([]byte{0x50}); ok {
		t.Fatal("unsupported IP version must not parse")
	}
	// Truncated -> skipped.
	if _, _, _, _, ok := ParsePacket([]byte{0x45, 0x00}); ok {
		t.Fatal("truncated must not parse")
	}
}

func TestParsePacketIPv6(t *testing.T) {
	t.Run("tcp without extensions", func(t *testing.T) {
		pkt := ipv6Packet(t, 6, nil, []byte{0x30, 0x39, 0x01, 0xbb})
		src, dst, proto, port, ok := ParsePacket(pkt)
		if !ok || src != "2001:db8::10" || dst != "2001:db8:1::5" || proto != "tcp" || port != 443 {
			t.Fatalf("IPv6 TCP parse wrong: src=%s dst=%s proto=%s port=%d ok=%v", src, dst, proto, port, ok)
		}
	})

	t.Run("udp after destination options", func(t *testing.T) {
		// Destination Options header: next=UDP, hdr-ext-len=0 => 8 bytes.
		ext := []byte{17, 0, 0, 0, 0, 0, 0, 0}
		pkt := ipv6Packet(t, 60, ext, []byte{0x14, 0xe9, 0x00, 0x35})
		_, _, proto, port, ok := ParsePacket(pkt)
		if !ok || proto != "udp" || port != 53 {
			t.Fatalf("IPv6 extension parse wrong: proto=%s port=%d ok=%v", proto, port, ok)
		}
	})

	t.Run("non-initial fragment has no guessed port", func(t *testing.T) {
		// Fragment header: next=TCP and offset=1 (encoded as 1<<3).
		ext := []byte{6, 0, 0, 8, 0, 0, 0, 1}
		pkt := ipv6Packet(t, 44, ext, []byte{0x30, 0x39, 0x01, 0xbb})
		_, _, proto, port, ok := ParsePacket(pkt)
		if !ok || proto != "tcp" || port != 0 {
			t.Fatalf("IPv6 fragment parse wrong: proto=%s port=%d ok=%v", proto, port, ok)
		}
	})

	t.Run("truncated extension is refused", func(t *testing.T) {
		pkt := ipv6Packet(t, 60, []byte{17}, nil)
		if _, _, _, _, ok := ParsePacket(pkt); ok {
			t.Fatal("truncated IPv6 extension must not parse")
		}
	})
}

func ipv6Packet(t *testing.T, next byte, extension, transport []byte) []byte {
	t.Helper()
	pkt := make([]byte, 40, 40+len(extension)+len(transport))
	pkt[0] = 0x60
	pkt[6] = next
	pkt[7] = 64
	src := netip.MustParseAddr("2001:db8::10").As16()
	dst := netip.MustParseAddr("2001:db8:1::5").As16()
	copy(pkt[8:24], src[:])
	copy(pkt[24:40], dst[:])
	pkt = append(pkt, extension...)
	pkt = append(pkt, transport...)
	payloadLen := len(extension) + len(transport)
	pkt[4], pkt[5] = byte(payloadLen>>8), byte(payloadLen)
	return pkt
}
