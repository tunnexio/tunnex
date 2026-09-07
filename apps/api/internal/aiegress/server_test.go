package aiegress

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestConnectAuthenticationAndDestinationRefusal(t *testing.T) {
	p := fixturePolicy(t)
	h, e := NewServer(p, "fixture", "password")
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(h)
	defer server.Close()
	for _, tc := range []struct {
		method, target, auth string
		status               int
	}{{"CONNECT", "127.0.0.1:443", "", 407}, {"GET", "/", "Basic Zml4dHVyZTpwYXNzd29yZA==", 405}, {"CONNECT", "127.0.0.1:443", "Basic Zml4dHVyZTpwYXNzd29yZA==", 403}, {"CONNECT", "169.254.169.254:80", "Basic Zml4dHVyZTpwYXNzd29yZA==", 403}} {
		c, e := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		host := tc.target
		if tc.method == "GET" {
			host = "fixture"
		}
		fmt.Fprintf(c, "%s %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\nConnection: close\r\n\r\n", tc.method, tc.target, host, tc.auth)
		r, e := http.ReadResponse(bufio.NewReader(c), nil)
		if e != nil {
			t.Fatal(e)
		}
		if r.StatusCode != tc.status {
			t.Fatalf("expected%d got%d", tc.status, r.StatusCode)
		}
		r.Body.Close()
		c.Close()
	}
}

func TestConnectApprovedTunnelAndLifetime(t *testing.T) {
	p := fixturePolicy(t)
	h, _ := NewServer(p, "fixture", "password")
	h.lifetime = 100 * time.Millisecond
	done := make(chan struct{})
	h.dial = func(ctx context.Context, target string) (net.Conn, error) {
		_, e := p.addresses(ctx, target, func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "control.internal" {
				return []netip.Addr{netip.MustParseAddr("10.20.3.3")}, nil
			}
			return []netip.Addr{netip.MustParseAddr("10.20.2.3")}, nil
		})
		if e != nil {
			return nil, e
		}
		client, upstream := net.Pipe()
		go func() {
			defer close(done)
			defer upstream.Close()
			buf := make([]byte, 4)
			if _, e := io.ReadFull(upstream, buf); e == nil && string(buf) == "ping" {
				upstream.Write([]byte("pong"))
			}
			io.Copy(io.Discard, upstream)
		}()
		return client, nil
	}
	server := httptest.NewServer(h)
	defer server.Close()
	c, e := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	fmt.Fprint(c, "CONNECT models.internal:443 HTTP/1.1\r\nHost: models.internal:443\r\nProxy-Authorization: Basic Zml4dHVyZTpwYXNzd29yZA==\r\n\r\n")
	reader := bufio.NewReader(c)
	response, e := http.ReadResponse(reader, nil)
	if e != nil || response.StatusCode != 200 {
		t.Fatal("approved CONNECT refused")
	}
	c.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, e = io.ReadFull(reader, buf); e != nil || string(buf) != "pong" {
		t.Fatal("tunnel lost payload")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("tunnel exceeded lifetime")
	}
	deadline := time.Now().Add(time.Second)
	for len(h.slots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(h.slots) != 0 {
		t.Fatal("completed tunnel leaked concurrency slot")
	}
}
