package proxy

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"github.com/tunnexio/tunnex/packages/apptransport"
	"github.com/tunnexio/tunnex/packages/apptransport/authoritywire"
	"github.com/tunnexio/tunnex/packages/apptransport/originpolicy"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func browserCertificates(t *testing.T) (func(int64, bool) ([]byte, []byte), []byte) {
	caPub, caKey, _ := ed25519.GenerateKey(rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	leaf := func(serial int64, server bool) ([]byte, []byte) {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		usage := x509.ExtKeyUsageClientAuth
		if server {
			usage = x509.ExtKeyUsageServerAuth
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"tunnex-app-proxy", "app.apps.example.net", "console.example.com"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, e := x509.CreateCertificate(rand.Reader, template, ca, pub, caKey)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := x509.MarshalPKCS8PrivateKey(key)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})
	}
	return leaf, caPEM
}

type fixtureAuthority struct {
	route   Route
	serial  string
	streams atomic.Int32
	denied  atomic.Bool
}

func (a *fixtureAuthority) Lookup(_ context.Context, host string) (Route, error) {
	if a.denied.Load() || host != a.route.Binding.Hostname {
		return Route{}, ErrDenied
	}
	return a.route, nil
}
func (a *fixtureAuthority) Authorize(_ context.Context, b Binding, token string, r Request) (Decision, error) {
	if r.RelativePath == "" || !strings.HasPrefix(r.RelativePath, "/") || r.Origin != "https://app.apps.test" {
		return Decision{}, ErrDenied
	}
	if a.denied.Load() || b != Binding(a.route.Binding) || token != "app-session" {
		return Decision{}, ErrDenied
	}
	a.streams.Add(1)
	return Decision{StreamID: "stream", ExpiresAt: time.Now().Add(3 * time.Second)}, nil
}
func (a *fixtureAuthority) Renew(_ context.Context, b Binding, id string) (Decision, error) {
	if a.denied.Load() {
		return Decision{}, ErrDenied
	}
	return Decision{StreamID: id, ExpiresAt: time.Now().Add(3 * time.Second)}, nil
}
func (a *fixtureAuthority) Channel(_ context.Context, b Binding, serial string) (time.Time, error) {
	if a.denied.Load() || b != Binding(a.route.Binding) || serial != a.serial {
		return time.Time{}, ErrDenied
	}
	return time.Now().Add(3 * time.Second), nil
}

type fixtureConn struct {
	net.Conn
	reader *bufio.Reader
	done   chan struct{}
	once   sync.Once
}

func (c *fixtureConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *fixtureConn) Close() error {
	e := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return e
}

type fixtureListener struct {
	conn     *fixtureConn
	accepted bool
}

func (l *fixtureListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return l.conn, nil
	}
	<-l.conn.done
	return nil, net.ErrClosed
}
func (l *fixtureListener) Close() error   { return l.conn.Close() }
func (l *fixtureListener) Addr() net.Addr { return l.conn.LocalAddr() }
func TestPublicHandlerActualOutboundTransport(t *testing.T) {
	leaf, caPEM := browserCertificates(t)
	serverPEM, key := leaf(4, true)
	serverCert, _ := tls.X509KeyPair(serverPEM, key)
	clientPEM, clientKey := leaf(2, false)
	clientCert, _ := tls.X509KeyPair(clientPEM, clientKey)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	b := Binding{OrgID: "11111111-1111-1111-1111-111111111111", GatewayID: "22222222-2222-2222-2222-222222222222", AppID: "33333333-3333-3333-3333-333333333333", Generation: "44444444-4444-4444-4444-444444444444", Revision: 1, AuthorityVersion: 1, Digest: strings.Repeat("a", 64), Hostname: "app.apps.test", Purpose: "browser_proxy"}
	a := &fixtureAuthority{route: Route{Binding: authoritywire.AppProxyRouteBinding(b), OriginURL: "http://origin.example"}, serial: "2"}
	broker, gatewayHandler := NewGateway("apps.test", a)
	defer broker.Close()
	gateway := httptest.NewUnstartedServer(gatewayHandler)
	gateway.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	gateway.StartTLS()
	defer gateway.Close()
	originClosed := make(chan struct{}, 4)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "origin.example" || strings.Contains(r.Header.Get("Cookie"), "tunnex") || r.Header.Get("X-App-ID") != "" || r.Header.Get("Authorization") != "Bearer ordinary-app-token" || r.Header.Get("X-Auth-Token") != "ordinary-header-token" {
			t.Errorf("origin leaked or lost credentials: %s %v", r.Host, r.Header)
		}
		w.Header().Set(apptransport.OriginHeaderTiming, "private-origin-spoof")
		w.Header().Add(apptransport.OriginHeaderTiming, "999999999999999999")
		switch r.URL.Path {
		case "/form":
			body, _ := io.ReadAll(r.Body)
			w.Write(body)
		case "/redirect":
			w.Header().Set("Location", "http://origin.example/done")
			w.Header().Set("Set-Cookie", "app=value; Domain=origin.example; HttpOnly")
			w.WriteHeader(302)
		case "/events":
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "data: ready\n\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			originClosed <- struct{}{}
		case "/ws":
			c, rw, e := w.(http.Hijacker).Hijack()
			if e != nil {
				return
			}
			defer c.Close()
			echoWebSocket(c, rw, r.Header.Get("Sec-WebSocket-Key"))
			originClosed <- struct{}{}
		default:
			io.WriteString(w, "asset")
		}
	}))
	defer origin.Close()
	policy, _ := originpolicy.Normalize([]string{"10.1.2.3/32"}, "")
	checker := originpolicy.Checker{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
	}, Dial: func(ctx context.Context, n, address string) (net.Conn, error) {
		if address != "10.1.2.3:80" {
			t.Errorf("unexpected dial %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, n, origin.Listener.Addr().String())
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var connectors sync.WaitGroup
	connect := func() {
		connectors.Add(1)
		go func() {
			defer connectors.Done()
			conn, e := tls.Dial("tcp", gateway.Listener.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "tunnex-app-proxy", RootCAs: roots, Certificates: []tls.Certificate{clientCert}, NextProtos: []string{"http/1.1"}})
			if e != nil {
				t.Error(e)
				return
			}
			defer conn.Close()
			closeOnCancel := context.AfterFunc(ctx, func() { conn.Close() })
			defer closeOnCancel()
			request := &http.Request{Method: "CONNECT", URL: &url.URL{Opaque: "/app-access/channel"}, Host: gateway.Listener.Addr().String(), Header: make(http.Header)}
			apptransport.BindingHeaders(request.Header, b.Transport())
			request.Write(conn)
			reader := bufio.NewReader(conn)
			response, e := http.ReadResponse(reader, request)
			if e != nil || response.StatusCode != 200 {
				t.Errorf("channel: %v %v", response, e)
				return
			}
			tracked := &fixtureConn{Conn: conn, reader: reader, done: make(chan struct{})}
			defer tracked.Close()
			server := &http.Server{Handler: apptransport.BrowserOrigin(b.Transport(), &originpolicy.Transport{Checker: checker, Origin: a.route.OriginURL, Policy: policy}), BaseContext: func(net.Listener) context.Context { return ctx }}
			defer server.Close()
			server.Serve(&fixtureListener{conn: tracked})
		}()
	}
	publicHandler := NewHandler("apps.test", a, broker)
	public := httptest.NewUnstartedServer(publicHandler)
	public.Config.ConnContext = ConnectionContext
	public.StartTLS()
	defer func() { cancel(); broker.Close(); public.Close(); connectors.Wait() }()
	client := public.Client()
	client.Timeout = 10 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	request := func(method, path, body string) *http.Request {
		r, _ := http.NewRequest(method, public.URL+path, strings.NewReader(body))
		r.Host = b.Hostname
		r.Header.Set("Cookie", apptransport.AppSessionCookie+"=app-session; ordinary=value; tunnex_session=control")
		r.Header.Set("Authorization", "Bearer ordinary-app-token")
		r.Header.Set("X-Auth-Token", "ordinary-header-token")
		r.Header.Set("X-App-ID", "forged")
		r.Header.Set("Origin", "https://"+b.Hostname)
		return r
	}
	for _, tc := range []struct{ method, path, body, want string }{{"POST", "/form", "field=value", "field=value"}, {"GET", "/asset", "", "asset"}} {
		connect()
		response, e := client.Do(request(tc.method, tc.path, tc.body))
		if e != nil {
			t.Fatal(e)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if len(response.Header.Values(apptransport.OriginHeaderTiming)) != 0 {
			t.Fatal("internal origin timing exposed to browser")
		}
		if response.StatusCode != 200 || string(body) != tc.want {
			t.Fatal(response.StatusCode, string(body))
		}
	}
	connect()
	if publicHandler.metrics.originHeaders.count.Load() != 2 {
		t.Fatal("actual gateway origin header measurements missing")
	}
	response, e := client.Do(request("GET", "/redirect", ""))
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.Header.Get("Location") != "https://app.apps.test/done" || strings.Contains(response.Header.Get("Set-Cookie"), "Domain=") || !strings.Contains(response.Header.Get("Set-Cookie"), "Secure") {
		t.Fatal(response.Header)
	}
	connect()
	response, e = client.Do(request("GET", "/events", ""))
	if e != nil {
		t.Fatal(e)
	}
	line, _ := bufio.NewReader(response.Body).ReadString('\n')
	if line != "data: ready\n" {
		t.Fatal(line)
	}
	response.Body.Close()
	select {
	case <-originClosed:
	case <-time.After(time.Second):
		t.Fatal("SSE cancellation did not reach origin")
	}
	connect()
	client.Timeout = 0
	wsCtx, wsCancel := context.WithTimeout(ctx, 5*time.Second)
	defer wsCancel()
	r := request("GET", "/ws", "").WithContext(wsCtx)
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	r.Header.Set("Sec-WebSocket-Version", "13")
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	response, e = client.Do(r)
	if e != nil || response.StatusCode != 101 {
		t.Fatal(response, e)
	}
	stream := response.Body.(io.ReadWriteCloser)
	if response.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatal("invalid websocket handshake")
	}
	for _, text := range []string{"one", "two"} {
		frame := string(append([]byte{0x81, byte(len(text))}, []byte(text)...))
		stream.Write(maskedFrame(text))
		got := make([]byte, len(frame))
		if _, e = io.ReadFull(stream, got); e != nil || string(got) != frame {
			t.Fatal(got, e)
		}
	}
	stream.Close()
	select {
	case <-originClosed:
	case <-time.After(time.Second):
		t.Fatal("WebSocket cancellation did not reach origin")
	}
	// Keep route/session leases renewing while a legitimate declared upload
	// stops progressing. The body idle bound must independently terminate it.
	connect()
	stalled, e := tls.Dial("tcp", public.Listener.Addr().String(), public.Client().Transport.(*http.Transport).TLSClientConfig.Clone())
	if e != nil {
		t.Fatal(e)
	}
	io.WriteString(stalled, "POST /form HTTP/1.1\r\nHost: app.apps.test\r\nOrigin: https://app.apps.test\r\nCookie: __Host-tunnex_app_session=app-session; ordinary=value\r\nAuthorization: Bearer ordinary-app-token\r\nX-Auth-Token: ordinary-header-token\r\nContent-Length: 1000\r\n\r\nx")
	stalled.SetReadDeadline(time.Now().Add(18 * time.Second))
	stalledLine, e := bufio.NewReader(stalled).ReadString('\n')
	stalled.Close()
	if e != nil || (!strings.Contains(stalledLine, "403") && !strings.Contains(stalledLine, "502")) {
		t.Fatal("renewing stalled upload did not end", stalledLine, e)
	}
	a.denied.Store(true)
	response, e = client.Do(request("GET", "/asset", ""))
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("positive authority cached", response.StatusCode)
	}
	cancel()
}

func echoWebSocket(c net.Conn, rw *bufio.ReadWriter, key string) {
	defer c.Close()
	if key != "dGhlIHNhbXBsZSBub25jZQ==" {
		return
	}
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n")
	rw.Flush()
	for {
		var header [2]byte
		if _, e := io.ReadFull(rw, header[:]); e != nil {
			return
		}
		if header[0] != 0x81 || header[1]&0x80 == 0 || header[1]&0x7f > 125 {
			return
		}
		var mask [4]byte
		if _, e := io.ReadFull(rw, mask[:]); e != nil {
			return
		}
		body := make([]byte, int(header[1]&0x7f))
		if _, e := io.ReadFull(rw, body); e != nil {
			return
		}
		for i := range body {
			body[i] ^= mask[i%4]
		}
		if _, e := c.Write(append([]byte{0x81, byte(len(body))}, body...)); e != nil {
			return
		}
	}
}
func maskedFrame(text string) []byte {
	out := []byte{0x81, 0x80 | byte(len(text)), 1, 2, 3, 4}
	for i, c := range []byte(text) {
		out = append(out, c^byte(i%4+1))
	}
	return out
}

func (a *fixtureAuthority) Redeem(context.Context, RedeemInput) (RedeemResult, error) {
	return RedeemResult{}, ErrDenied
}

func (a *fixtureAuthority) Pending(context.Context, PendingInput) (PendingResult, error) {
	return PendingResult{}, ErrDenied
}
