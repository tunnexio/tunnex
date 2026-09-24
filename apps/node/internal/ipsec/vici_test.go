package ipsec

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestVICICodecRoundTrip(t *testing.T) {
	m := viciMessage{"secret": viciScalar([]byte("Synthetic.PSK_value")), "items": viciList("a", "b"), "child": viciSection(viciMessage{"key": viciText("value")})}
	encoded, err := encodeVICI(m)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeVICI(encoded)
	if err != nil || !reflect.DeepEqual(m, decoded) {
		t.Fatalf("round trip failed: %v", err)
	}
}
func TestVICIRefusesMalformedElements(t *testing.T) {
	for name, raw := range map[string][]byte{"duplicate": {3, 1, 'x', 0, 1, 'a', 3, 1, 'x', 0, 1, 'b'}, "type alias": {3, 1, 'x', 0, 1, 'a', 1, 1, 'x', 2}, "unbalanced": {1, 1, 'x'}, "extra end": {2}, "list item outside": {5, 0, 1, 'a'}, "section in list": {4, 1, 'x', 1, 1, 'y', 2, 6}, "list missing end": {4, 1, 'x', 5, 0, 1, 'a'}, "truncated": {3, 1, 'x', 255, 255}, "unknown type": {9}, "empty name": {3, 0, 0, 0}} {
		t.Run(name, func(t *testing.T) {
			_, err := decodeVICI(raw)
			if !errors.Is(err, ErrDaemonProtocol) {
				t.Fatal("malformed message accepted")
			}
		})
	}
}
func TestVICILimits(t *testing.T) {
	m := viciMessage{"x": viciScalar(make([]byte, 65536))}
	if _, err := encodeVICI(m); err == nil {
		t.Fatal("oversize value")
	}
	deep := []byte{}
	for i := 0; i < 17; i++ {
		deep = append(deep, 1, 1, 'x')
	}
	for i := 0; i < 17; i++ {
		deep = append(deep, 2)
	}
	if _, err := decodeVICI(deep); err == nil {
		t.Fatal("depth accepted")
	}
	if _, err := decodeVICI(make([]byte, viciFrameLimit+1)); err == nil {
		t.Fatal("oversize frame accepted")
	}
	many := []byte{4, 1, 'x'}
	for i := 0; i < 4097; i++ {
		many = append(many, 5, 0, 0)
	}
	many = append(many, 6)
	if _, err := decodeVICI(many); err == nil {
		t.Fatal("element count accepted")
	}
}
func TestVICIHeaderBoundBeforeBody(t *testing.T) {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, 1<<32-1)
	_, err := readVICIPacket(bytes.NewReader(header))
	if !errors.Is(err, ErrDaemonProtocol) {
		t.Fatal("oversize header not rejected before body read")
	}
}
func TestVICICancelAndStaticErrors(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	transport := viciTransport{dial: func(context.Context) (net.Conn, error) { return client, nil }}
	done := make(chan error, 1)
	go func() { _, _, err := transport.call(ctx, "version", "", viciMessage{}); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, ErrDaemonProtocol) {
			t.Fatal("nonstatic cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not interrupt I/O")
	}
}
func TestVICIStreamingExchange(t *testing.T) {
	client, server := net.Pipe()
	transport := viciTransport{dial: func(context.Context) (net.Conn, error) { return client, nil }}
	go func() {
		defer server.Close()
		p, _ := readVICIPacket(server)
		if len(p) == 0 || p[0] != 3 {
			return
		}
		writeVICIPacket(server, []byte{5})
		p, _ = readVICIPacket(server)
		if len(p) == 0 || p[0] != 0 {
			return
		}
		body, _ := encodeVICI(viciMessage{"sa": viciSection(viciMessage{"uniqueid": viciText("1")})})
		event := append([]byte{7, 7}, []byte("list-sa")...)
		writeVICIPacket(server, append(event, body...))
		writeVICIPacket(server, []byte{1})
	}()
	_, events, err := transport.call(context.Background(), "list-sas", "list-sa", viciMessage{})
	if err != nil || len(events) != 1 {
		t.Fatalf("stream failed: %v", err)
	}
}
func TestVICIUnexpectedEventRefused(t *testing.T) {
	client, server := net.Pipe()
	transport := viciTransport{dial: func(context.Context) (net.Conn, error) { return client, nil }}
	go func() {
		defer server.Close()
		readVICIPacket(server)
		writeVICIPacket(server, []byte{7, 3, 'l', 'o', 'g'})
	}()
	_, _, err := transport.call(context.Background(), "version", "", viciMessage{})
	if !errors.Is(err, ErrDaemonProtocol) {
		t.Fatal("unregistered event accepted")
	}
}

func TestVICIAggregateBeforeAllocation(t *testing.T) {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, 100)
	if _, err := readVICIPacketBound(bytes.NewReader(header), 99); err != ErrDaemonProtocol {
		t.Fatal("aggregate allocation bound not enforced at header")
	}
}
