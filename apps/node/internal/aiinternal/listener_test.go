package aiinternal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingConn counts what the client receives.
type recordingConn struct {
	net.Conn
	mu   sync.Mutex
	read int
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.read += n
	c.mu.Unlock()
	return n, err
}

func loopbackCert(t *testing.T, ca *testCA, names ...string) *tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	leafPEM := ca.leaf(t, &key.PublicKey, []net.IP{net.ParseIP("127.0.0.1")}, names, now.Add(-time.Minute), now.Add(time.Hour))
	cert, err := parseCertificates(leafPEM, 1)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{cert[0].Raw}, PrivateKey: key, Leaf: cert[0]}
}

// startServer serves handler on a loopback socket behind the source filter, as the runtime does.
func startServer(t *testing.T, handler http.Handler, dnsName string, cert *tls.Certificate, allowed func(netip.Addr) bool) string {
	t.Helper()
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(t.Context(), handler, tlsConfig(dnsName, func() (*tls.Certificate, error) { return cert, nil }))
	go func() { _ = serve(srv, raw, allowed) }()
	t.Cleanup(func() { _ = srv.Close(); _ = raw.Close() })
	return raw.Addr().String()
}

func clientTLS(ca *testCA, serverName string) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return &tls.Config{RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS12}
}

func TestAPeerOutsideTheSourcesIsClosedBeforeTLS(t *testing.T) {
	ca := newTestCA(t)
	address := startServer(t, http.NotFoundHandler(), "", loopbackCert(t, ca), func(netip.Addr) bool { return false })
	for i := 0; i < 3; i++ { // the refusal never stops Accept
		conn, err := net.Dial("tcp4", address)
		if err != nil {
			t.Fatal(err)
		}
		rec := &recordingConn{Conn: conn}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		err = tls.Client(rec, clientTLS(ca, "127.0.0.1")).Handshake()
		_ = conn.Close()
		if err == nil {
			t.Fatal("a refused peer completed a TLS handshake")
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Fatal("the refused connection was left open")
		}
		rec.mu.Lock()
		read := rec.read
		rec.mu.Unlock()
		if read != 0 {
			t.Fatalf("a refused peer received %d bytes (a ServerHello)", read)
		}
	}
}

type fakeListener struct {
	conns chan net.Conn
}

func (l *fakeListener) Accept() (net.Conn, error) {
	c, ok := <-l.conns
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}
func (l *fakeListener) Close() error   { return nil }
func (l *fakeListener) Addr() net.Addr { return &net.TCPAddr{} }

type fakeConn struct {
	net.Conn
	remote  net.Addr
	closed  bool
	written int
}

func (c *fakeConn) RemoteAddr() net.Addr        { return c.remote }
func (c *fakeConn) Close() error                { c.closed = true; return nil }
func (c *fakeConn) Write(p []byte) (int, error) { c.written += len(p); return len(p), nil }

func TestSourceFilterClosesWithoutWritingAndChecksTheUnmappedPeer(t *testing.T) {
	sources := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}
	outside := &fakeConn{remote: &net.TCPAddr{IP: net.ParseIP("10.21.0.1"), Port: 1}}
	v6 := &fakeConn{remote: &net.TCPAddr{IP: net.ParseIP("fd00::1"), Port: 1}}
	mapped := &fakeConn{remote: &net.TCPAddr{IP: net.ParseIP("::ffff:10.20.0.9"), Port: 1}}
	l := &fakeListener{conns: make(chan net.Conn, 3)}
	l.conns <- outside
	l.conns <- v6
	l.conns <- mapped
	got, err := sourceFilter{Listener: l, allowed: func(a netip.Addr) bool { return allows(sources, a) }}.Accept()
	if err != nil || got != mapped {
		t.Fatalf("accepted %v, %v", got, err)
	}
	for _, c := range []*fakeConn{outside, v6} {
		if !c.closed || c.written != 0 {
			t.Fatalf("refused conn closed=%v written=%d", c.closed, c.written)
		}
	}
	if mapped.closed {
		t.Fatal("the allowed connection was closed")
	}
}

func TestTLSServesTheEndpointAndRefusesAnotherSNI(t *testing.T) {
	ca := newTestCA(t)
	up := &fakeControl{}
	upstream := httptest.NewServer(up)
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	// The handler's own peer check runs on the loopback peer here.
	handler := Handler(target, upstream.Client().Transport, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	address := startServer(t, handler, "ai.internal.example", loopbackCert(t, ca, "ai.internal.example"), func(netip.Addr) bool { return true })
	dial := func(sni string) (*tls.Conn, error) {
		conn, err := net.Dial("tcp4", address)
		if err != nil {
			return nil, err
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		cfg := clientTLS(ca, sni)
		if sni == "" {
			cfg.ServerName = "127.0.0.1" // an IP: the client sends no SNI and checks the IP SAN
		}
		tc := tls.Client(conn, cfg)
		if err := tc.Handshake(); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return tc, nil
	}
	for _, sni := range []string{"", "ai.internal.example"} {
		tc, err := dial(sni)
		if err != nil {
			t.Fatalf("SNI %q: %v", sni, err)
		}
		if tc.ConnectionState().NegotiatedProtocol == "h2" || tc.ConnectionState().Version < tls.VersionTLS12 {
			t.Fatalf("negotiated %+v", tc.ConnectionState())
		}
		_ = tc.Close()
	}
	if _, err := dial("other.example"); err == nil {
		t.Fatal("an unexpected SNI was served")
	}
	// TLS 1.1 is refused.
	conn, _ := net.Dial("tcp4", address)
	old := clientTLS(ca, "ai.internal.example")
	old.MinVersion, old.MaxVersion = tls.VersionTLS10, tls.VersionTLS11
	if err := tls.Client(conn, old).Handshake(); err == nil {
		t.Fatal("TLS 1.1 was accepted")
	}
	_ = conn.Close()
	// A full request over TLS reaches the control plane with the peer the gateway saw.
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS(ca, "ai.internal.example")}}
	req, _ := http.NewRequest(http.MethodPost, "https://"+address+"/v1/chat/completions", strings.NewReader(`{}`))
	req.Header = bearer()
	req.Header.Set("X-Tunnex-Peer-IP", "10.20.1.1")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || resp.ProtoMajor != 1 {
		t.Fatalf("status=%d proto=%s", resp.StatusCode, resp.Proto)
	}
	if got := up.requests(); len(got) != 1 || got[0].header.Get("X-Tunnex-Peer-Ip") != "127.0.0.1" {
		t.Fatalf("upstream: %+v", got)
	}
	// Plain HTTP is not served.
	plain, err := http.Post("http://"+address+"/v1/chat/completions", "application/json", strings.NewReader(`{}`))
	if err == nil {
		defer plain.Body.Close()
		if plain.StatusCode == 200 {
			t.Fatal("plain HTTP was relayed")
		}
	}
	if len(up.requests()) != 1 {
		t.Fatal("plain HTTP reached the control plane")
	}
}

func TestServerTimeoutsAndLimitsAreTheRelays(t *testing.T) {
	srv := newServer(context.Background(), http.NotFoundHandler(), &tls.Config{})
	if srv.ReadHeaderTimeout != 5*time.Second || srv.ReadTimeout != 61*time.Minute || srv.WriteTimeout != 62*time.Minute ||
		srv.IdleTimeout != 30*time.Second || srv.MaxHeaderBytes != 16<<10 {
		t.Fatalf("server: %+v", srv)
	}
	if srv.TLSNextProto == nil || len(srv.TLSNextProto) != 0 {
		t.Fatal("HTTP/2 is not disabled")
	}
	cfg := tlsConfig("", nil)
	if cfg.MinVersion != tls.VersionTLS12 || len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "http/1.1" {
		t.Fatalf("tls: %+v", cfg)
	}
}
