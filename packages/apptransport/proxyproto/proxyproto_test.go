package proxyproto

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

var token = bytes.Repeat([]byte{7}, 32)

func addr(s string, port int) *net.TCPAddr { return &net.TCPAddr{IP: net.ParseIP(s), Port: port} }

func TestHeaderRoundTrip(t *testing.T) {
	for _, src := range []*net.TCPAddr{addr("203.0.113.9", 51000), addr("2001:db8::9", 443)} {
		h, err := Header(src, addr("172.31.254.3", 443), token)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Read(bytes.NewReader(h), token)
		if err != nil || !got.IP.Equal(src.IP) || got.Port != src.Port {
			t.Fatal(src, got, err)
		}
	}
}

func TestReadFailsClosed(t *testing.T) {
	good, _ := Header(addr("203.0.113.9", 1), addr("10.0.0.1", 443), token)
	noToken, _ := Header(addr("203.0.113.9", 1), addr("10.0.0.1", 443), nil)
	wrong, _ := Header(addr("203.0.113.9", 1), addr("10.0.0.1", 443), bytes.Repeat([]byte{8}, 32))
	twice := append(append([]byte{}, good...), 0)
	twice = twice[:len(good)]
	dup := append(append([]byte{}, good[:14]...), 0, 0)
	body := append(append([]byte{}, good[16:]...), TokenTLV, 0, 32)
	body = append(body, token...)
	dup[14], dup[15] = byte(len(body)>>8), byte(len(body))
	dup = append(dup, body...)
	long := append(append([]byte{}, good[:14]...), 0xff, 0xff)
	for name, raw := range map[string][]byte{"no token": noToken, "wrong token": wrong, "duplicate token": dup, "oversized": long, "truncated": good[:20], "v1": []byte("PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n"), "local cmd": append(append(append([]byte{}, Signature...), 0x20, 0x11), good[14:]...)} {
		if _, err := Read(bytes.NewReader(raw), token); err == nil {
			t.Fatal(name, "accepted")
		}
	}
	if _, err := Read(bytes.NewReader(twice), token); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(bytes.NewReader(good), nil); err == nil {
		t.Fatal("empty token configuration accepted a header")
	}
}

func FuzzRead(f *testing.F) {
	good, _ := Header(addr("203.0.113.9", 1), addr("10.0.0.1", 443), token)
	f.Add(good)
	f.Fuzz(func(t *testing.T, raw []byte) { _, _ = Read(bytes.NewReader(raw), token) })
}

func listen(t *testing.T) (*Listener, string) {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewListener(inner, token, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, inner.Addr().String()
}

func TestListenerEdgeDirectAndRejected(t *testing.T) {
	l, address := listen(t)
	send := func(prefix []byte, payload string) {
		c, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		_, _ = c.Write(append(append([]byte{}, prefix...), payload...))
	}
	h, _ := Header(addr("198.51.100.7", 4242), addr("127.0.0.1", 443), token)
	bad, _ := Header(addr("198.51.100.8", 4242), addr("127.0.0.1", 443), bytes.Repeat([]byte{9}, 32))
	send(bad, "spoofed-client-hello")
	send(h, "edge-client-hello")
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if c.RemoteAddr().String() != "198.51.100.7:4242" {
		t.Fatal("edge address not applied", c.RemoteAddr())
	}
	got := make([]byte, len("edge-client-hello"))
	if _, err = io.ReadFull(c, got); err != nil || string(got) != "edge-client-hello" {
		t.Fatal("payload after header lost", string(got), err)
	}
	send(nil, "direct-client-hello")
	c, err = l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if host, _, _ := net.SplitHostPort(c.RemoteAddr().String()); host != "127.0.0.1" {
		t.Fatal("direct caller address changed", c.RemoteAddr())
	}
	got = make([]byte, len("direct-client-hello"))
	if _, err = io.ReadFull(c, got); err != nil || string(got) != "direct-client-hello" {
		t.Fatal("direct payload lost", string(got), err)
	}
}

func TestNewListenerRequiresToken(t *testing.T) {
	inner, _ := net.Listen("tcp", "127.0.0.1:0")
	defer inner.Close()
	if _, err := NewListener(inner, []byte("short"), time.Second); err == nil {
		t.Fatal("short token accepted")
	}
}
