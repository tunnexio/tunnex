package flowlog

import "testing"

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
	// Non-IPv4 (version 6 nibble) -> skipped.
	if _, _, _, _, ok := ParsePacket([]byte{0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}); ok {
		t.Fatal("non-IPv4 must not parse")
	}
	// Truncated -> skipped.
	if _, _, _, _, ok := ParsePacket([]byte{0x45, 0x00}); ok {
		t.Fatal("truncated must not parse")
	}
}
