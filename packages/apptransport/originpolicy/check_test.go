package originpolicy

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestCheckerExactDialNoRedirectAndNoBody(t *testing.T) {
	var second atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { second.Add(1) }))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "origin.example" {
			t.Errorf("Host %s", r.Host)
		}
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(302)
		w.Write(make([]byte, 100000))
	}))
	defer origin.Close()
	var address string
	c := Checker{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
	}, Dial: func(ctx context.Context, n, a string) (net.Conn, error) {
		address = a
		return (&net.Dialer{}).DialContext(ctx, n, origin.Listener.Addr().String())
	}}
	p, _ := Normalize([]string{"10.1.0.0/16"}, "")
	r := c.Check(context.Background(), "http://origin.example", p)
	if r.Status != "ready" || r.HTTPStatus != 302 || second.Load() != 0 || address != "10.1.2.3:80" {
		t.Fatal(r, address, second.Load())
	}
}
func TestCheckerValidatesAllAnswersAndControl(t *testing.T) {
	var dials atomic.Int32
	c := Checker{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("::ffff:127.0.0.1")}, nil
	}, Dial: func(context.Context, string, string) (net.Conn, error) { dials.Add(1); return nil, nil }}
	p, _ := Normalize(nil, "")
	if r := c.Check(context.Background(), "http://origin.example", p); r.Status != "dns_refused" || dials.Load() != 0 {
		t.Fatal(r)
	}
	c.ControlHosts = []string{"origin.example"}
	if r := c.Check(context.Background(), "http://origin.example", p); r.Status != "origin_refused" {
		t.Fatal(r)
	}
}
func TestCheckerTLSChainAndHostname(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	cert, e := x509.ParseCertificate(server.TLS.Certificates[0].Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	p, e := Normalize([]string{"10.1.0.0/16"}, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
	if e != nil {
		t.Fatal("test fixture CA", e)
	}
	c := Checker{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
	}, Dial: func(ctx context.Context, n, a string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, n, server.Listener.Addr().String())
	}}
	if r := c.Check(context.Background(), "https://example.com", p); r.Status != "ready" {
		t.Fatal(r)
	}
	if r := c.Check(context.Background(), "https://wrong.example", p); r.Status != "tls_refused" {
		t.Fatal(r)
	}
	untrusted, _ := Normalize(p.AllowedDestinationCIDRs, "")
	if r := c.Check(context.Background(), "https://example.com", untrusted); r.Status != "tls_refused" {
		t.Fatal(r)
	}
}
func TestCheckerCancellation(t *testing.T) {
	entered := make(chan struct{})
	stopped := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done(); close(stopped) }))
	defer server.Close()
	c := Checker{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
	}, Dial: func(ctx context.Context, n, a string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, n, server.Listener.Addr().String())
	}}
	p, _ := Normalize([]string{"10.1.0.0/16"}, "")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Result)
	go func() { done <- c.Check(ctx, "http://origin.example", p) }()
	<-entered
	cancel()
	select {
	case r := <-done:
		if r.Status != "cancelled" {
			t.Fatal(r)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel blocked")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("origin leaked")
	}
}

func TestCheckerRejectsAmbiguousRootOrigins(t *testing.T) {
	p, _ := Normalize(nil, "")
	for _, origin := range []string{"https://example.com/?", "https://example.com/#", "https://example.com/%2f", "https://example.com/path", "http://user@example.com"} {
		if r := (Checker{}).Check(context.Background(), origin, p); r.Status != "origin_refused" {
			t.Fatal(origin, r)
		}
	}
}

func TestMixedSpecialUseDNSNeverDials(t *testing.T) {
	p, _ := Normalize(nil, "")
	for _, bad := range []string{"3fff::1", "2001:2::1", "2001:10::1", "192.88.99.1"} {
		var calls atomic.Int32
		c := Checker{Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr(bad)}, nil
		}, Dial: func(context.Context, string, string) (net.Conn, error) { calls.Add(1); return nil, nil }}
		if r := c.Check(context.Background(), "http://origin.example", p); r.Status != "dns_refused" || calls.Load() != 0 {
			t.Fatal(bad, r)
		}
	}
}
