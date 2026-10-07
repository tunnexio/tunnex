package beam

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"github.com/tunnexio/tunnex/packages/apptransport"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type connectorFixture struct {
	t             *testing.T
	connector     *Connector
	broker        *apptransport.Broker
	options       ConnectorOptions
	cancel        context.CancelFunc
	done          chan error
	allowed       atomic.Bool
	origin        *httptest.Server
	gateway       *httptest.Server
	requests      atomic.Int64
	streamBytes   atomic.Int64
	upgradeClosed atomic.Int64
}

func generateCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Beam test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	raw, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := x509.ParseCertificate(raw)
	if e != nil {
		t.Fatal(e)
	}
	return cert, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
}
func generateLeaf(t *testing.T, ca *x509.Certificate, key *ecdsa.PrivateKey, serial int64, server string, ip net.IP) (tls.Certificate, string, string) {
	t.Helper()
	leafKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	if server != "" {
		template.DNSNames = []string{server}
	}
	if ip != nil {
		template.IPAddresses = []net.IP{ip}
	}
	raw, e := x509.CreateCertificate(rand.Reader, template, ca, &leafKey.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	keyRaw, e := x509.MarshalPKCS8PrivateKey(leafKey)
	if e != nil {
		t.Fatal(e)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyRaw}))
	cert, e := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if e != nil {
		t.Fatal(e)
	}
	return cert, certPEM, keyPEM
}
func targetOf(t *testing.T, server *httptest.Server, ca string) Target {
	t.Helper()
	u, e := url.Parse(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	port, _ := strconv.Atoi(u.Port())
	return Target{Protocol: u.Scheme, Address: u.Hostname(), Port: port, CAPEM: ca}
}
func fixture(t *testing.T, httpsOrigin, wrongOrigin bool, lifetime time.Duration, routes ...Route) *connectorFixture {
	t.Helper()
	f := &connectorFixture{t: t, done: make(chan error, 1)}
	f.allowed.Store(true)
	ca, key, caPEM := generateCA(t)
	serverCert, _, _ := generateLeaf(t, ca, key, 2, proxyServerName, nil)
	_, certPEM, keyPEM := generateLeaf(t, ca, key, 3, "", nil)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.URL.Path == "/blocked" {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			block := make([]byte, 32<<10)
			for i := 0; i < 2048; i++ {
				n, e := w.Write(block)
				f.streamBytes.Add(int64(n))
				w.(http.Flusher).Flush()
				if e != nil {
					return
				}
			}
			return
		}
		if r.URL.Path == "/body" {
			_, _ = io.Copy(io.Discard, r.Body)
			io.WriteString(w, "uploaded")
			return
		}
		if r.URL.Path == "/ws-stall" {
			<-r.Context().Done()
			f.upgradeClosed.Add(1)
			return
		}
		if r.URL.Path == "/huge-response" {
			w.Header().Set("Content-Length", strconv.Itoa(maxBody+1))
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		if r.URL.Path == "/sse" {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			io.WriteString(w, "data: ready\n\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		if r.URL.Path == "/ws" || r.URL.Path == "/compression" || r.URL.Path == "/origin-oversize" || r.URL.Path == "/origin-mask" {
			peer, rw, e := w.(http.Hijacker).Hijack()
			if e != nil {
				return
			}
			defer peer.Close()
			if r.Header.Get("Sec-WebSocket-Extensions") != "" {
				return
			}
			fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Protocol: vite-hmr\r\n")
			if r.URL.Path == "/compression" {
				fmt.Fprint(rw, "Sec-WebSocket-Extensions: permessage-deflate\r\n")
			}
			fmt.Fprint(rw, "\r\n")
			rw.Write([]byte{0x81, 2, 'o', 'k'})
			rw.Flush()
			if r.URL.Path == "/compression" {
				return
			}
			if r.URL.Path == "/origin-oversize" {
				peer.Write([]byte{0x81, 127, 0, 0, 0, 0, 0, 0x10, 0, 1})
				return
			}
			if r.URL.Path == "/origin-mask" {
				peer.Write([]byte{0x81, 0x80, 0, 0, 0, 0})
				return
			}
			_, _ = copyFrames(io.Discard, rw.Reader, true)
			return
		}
		if r.URL.Path == "/credentials" {
			if r.Host != testBinding().Hostname || r.Header.Get("X-App-Org-ID") != "" || r.Header.Get("Authorization") != "" || strings.Contains(r.Header.Get("Cookie"), "tunnex") {
				http.Error(w, "leak", 500)
				return
			}
			w.Header().Set("Set-Cookie", "app=ok; Domain=127.0.0.1; Path=/")
			w.Header().Set("Location", "http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(f.options.Target.Port))+"/next")
			io.WriteString(w, "clean")
			return
		}
		io.WriteString(w, "local Beam app")
	})
	f.origin = httptest.NewUnstartedServer(handler)
	f.origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	originCA := ""
	if httpsOrigin {
		dns := ""
		ip := net.ParseIP("127.0.0.1")
		if wrongOrigin {
			dns = "wrong.example"
			ip = nil
		}
		originCert, _, _ := generateLeaf(t, ca, key, 4, dns, ip)
		f.origin.TLS = &tls.Config{Certificates: []tls.Certificate{originCert}}
		f.origin.StartTLS()
		originCA = caPEM
	} else {
		f.origin.Start()
	}
	broker, gatewayHandler, e := NewGateway(testBinding(), func(context.Context, apptransport.Binding, string) (time.Time, error) {
		if !f.allowed.Load() {
			return time.Time{}, errRefused
		}
		return time.Now().Add(4 * time.Second), nil
	})
	if e != nil {
		t.Fatal(e)
	}
	f.broker = broker
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(caPEM))
	f.gateway = httptest.NewUnstartedServer(gatewayHandler)
	f.gateway.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, NextProtos: []string{"http/1.1"}}
	f.gateway.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.gateway.StartTLS()
	f.options = ConnectorOptions{ProxyURL: f.gateway.URL, ServerName: proxyServerName, Binding: testBinding(), Target: targetOf(t, f.origin, originCA), CertificatePEM: certPEM, KeyPEM: keyPEM, CAPEM: caPEM, ExpiresAt: time.Now().Add(lifetime)}
	f.options.Target.Routes = routes
	f.connector, e = NewConnector(f.options)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	go func() { f.done <- f.connector.Run(ctx) }()
	t.Cleanup(func() {
		f.cancel()
		select {
		case <-f.done:
		case <-time.After(2 * time.Second):
			t.Error("connector cancellation hung")
		}
		f.broker.Close()
		f.gateway.Close()
		f.origin.Close()
	})
	eventually(t, 2*time.Second, func() bool { return f.connector.Stats().Idle == 2 })
	return f
}
func eventually(t *testing.T, timeout time.Duration, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition did not settle within", timeout)
}
func (f *connectorFixture) dial(path string, extra http.Header) (net.Conn, *http.Response, *bufio.Reader) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	peer, e := f.broker.Dial(ctx, testBinding())
	if e != nil {
		f.t.Fatal(e)
	}
	peer.SetDeadline(time.Now().Add(5 * time.Second))
	r := &http.Request{Method: "GET", URL: &url.URL{Path: path}, Host: testBinding().Hostname, Header: extra.Clone()}
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	apptransport.BindingHeaders(r.Header, testBinding())
	r.Header.Set("X-App-Stream-ID", "test-stream")
	if e = r.Write(peer); e != nil {
		peer.Close()
		f.t.Fatal(e)
	}
	reader := bufio.NewReader(peer)
	response, e := http.ReadResponse(reader, r)
	if e != nil {
		peer.Close()
		f.t.Fatal(e)
	}
	return peer, response, reader
}
func TestConnectorActualTLSStreamsPoolWithdrawalAndCredentials(t *testing.T) {
	f := fixture(t, false, false, time.Minute)
	if e := CheckTarget(context.Background(), f.options.Target); e != nil {
		t.Fatal(e)
	}
	sse, sseResponse, _ := f.dial("/sse", nil)
	defer sse.Close()
	line := make([]byte, len("data: ready\n\n"))
	if _, e := io.ReadFull(sseResponse.Body, line); e != nil || string(line) != "data: ready\n\n" {
		t.Fatal("SSE did not stream immediately", string(line), e)
	}
	ws, wsResponse, wsReader := f.dial("/ws", http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Origin": {"https://" + testBinding().Hostname}, "Sec-Websocket-Protocol": {"vite-hmr"}, "Sec-Websocket-Extensions": {"permessage-deflate"}})
	defer ws.Close()
	if wsResponse.StatusCode != 101 || wsResponse.Header.Get("Sec-WebSocket-Protocol") != "vite-hmr" {
		t.Fatal("WS subprotocol", wsResponse)
	}
	head := make([]byte, 4)
	if _, e := io.ReadFull(wsReader, head); e != nil || !bytes.Equal(head, []byte{0x81, 2, 'o', 'k'}) {
		t.Fatal("upgrade head lost", head, e)
	}
	eventually(t, 2*time.Second, func() bool { s := f.connector.Stats(); return s.Active == 2 && s.Idle == 2 })
	conn, response, _ := f.dial("/credentials", http.Header{"Authorization": {"Bearer tnx_hidden"}, "Cookie": {"__Host-tunnex_beam_session=secret; app=own"}})
	raw, e := io.ReadAll(response.Body)
	conn.Close()
	if e != nil || string(raw) != "clean" || response.StatusCode != 200 {
		t.Fatal("concurrent HTTP or credentials", string(raw), e)
	}
	if response.Header.Get("Location") != "https://"+testBinding().Hostname+"/next" || strings.Contains(response.Header.Get("Set-Cookie"), "Domain=") || !strings.Contains(response.Header.Get("Set-Cookie"), "Secure") {
		t.Fatal("response origin isolation", response.Header)
	}
	f.allowed.Store(false)
	start := time.Now()
	ws.SetReadDeadline(start.Add(5 * time.Second))
	if _, e = wsReader.ReadByte(); e == nil {
		t.Fatal("revoked WebSocket stayed open")
	}
	sse.SetReadDeadline(start.Add(5 * time.Second))
	if _, e = sseResponse.Body.Read(make([]byte, 1)); e == nil {
		t.Fatal("revoked SSE stayed open")
	}
	eventually(t, time.Second, func() bool { return !f.connector.Ready() && f.connector.Stats().Active == 0 })
	t.Log("TLS HTTP/SSE/WS withdrawal", time.Since(start), "pool", f.connector.Stats())
}
func TestConnectorHTTPSVerifiesNumericLoopbackForHTTPAndWebSocket(t *testing.T) {
	f := fixture(t, true, false, time.Minute)
	if e := CheckTarget(context.Background(), f.options.Target); e != nil {
		t.Fatal(e)
	}
	peer, r, _ := f.dial("/", nil)
	body, e := io.ReadAll(r.Body)
	peer.Close()
	if e != nil || string(body) != "local Beam app" {
		t.Fatal("HTTPS public Host changed TLS identity", e)
	}
	peer, r, reader := f.dial("/ws", http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Origin": {"https://" + testBinding().Hostname}})
	defer peer.Close()
	if r.StatusCode != 101 {
		t.Fatal(r.StatusCode)
	}
	if _, e = io.ReadFull(reader, make([]byte, 4)); e != nil {
		t.Fatal(e)
	}
	wrong := fixture(t, true, true, time.Minute)
	if e = CheckTarget(context.Background(), wrong.options.Target); e == nil {
		t.Fatal("wrong origin SAN accepted")
	}
	conn, r, _ := wrong.dial("/", nil)
	conn.Close()
	if r.StatusCode != 502 {
		t.Fatal("wrong HTTPS SAN forwarding accepted", r.StatusCode)
	}
}
func TestConnectorExpiresAndCancellationReleasesAllReservations(t *testing.T) {
	f := fixture(t, false, false, 300*time.Millisecond)
	eventually(t, 2*time.Second, func() bool { return !f.connector.Ready() && f.connector.Stats() == (ConnectorStats{}) })
	select {
	case e := <-f.done:
		if e != ErrExpired {
			t.Fatal(e)
		}
		f.done <- e
	case <-time.After(time.Second):
		t.Fatal("expiry did not end Run")
	}
}
func TestConnectorRejectsAssignmentTargetsAndProxyIdentity(t *testing.T) {
	f := fixture(t, false, false, time.Minute)
	for _, mutate := range []func(*ConnectorOptions){func(o *ConnectorOptions) { o.ServerName = "other" }, func(o *ConnectorOptions) { o.ProxyURL = "http://127.0.0.1" }, func(o *ConnectorOptions) { o.ProxyURL += "?target=elsewhere" }, func(o *ConnectorOptions) { o.Target.Address = "localhost" }, func(o *ConnectorOptions) { o.Target.Address = "127.0.0.2" }, func(o *ConnectorOptions) { o.Binding.Purpose = "browser_proxy" }, func(o *ConnectorOptions) { o.ExpiresAt = time.Now().Add(-time.Second) }, func(o *ConnectorOptions) { o.CAPEM = "wrong" }} {
		o := f.options
		mutate(&o)
		if _, e := NewConnector(o); e == nil {
			t.Fatal("invalid immutable options accepted")
		}
	}
}
func TestConnectorRejectsDeclaredOversizeBeforeBodyAndForeignRequests(t *testing.T) {
	f := fixture(t, false, false, time.Minute)
	for _, kind := range []string{"oversize", "binding", "absolute", "stream", "headers"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		peer, e := f.broker.Dial(ctx, testBinding())
		cancel()
		if e != nil {
			t.Fatal(e)
		}
		peer.SetDeadline(time.Now().Add(time.Second))
		r := &http.Request{Method: "POST", URL: &url.URL{Path: "/"}, Host: testBinding().Hostname, Header: make(http.Header)}
		apptransport.BindingHeaders(r.Header, testBinding())
		r.Header.Set("X-App-Stream-ID", "test-stream")
		status := 403
		switch kind {
		case "oversize":
			r.Header.Set("Content-Length", strconv.Itoa(maxBody+1))
			status = 413
		case "binding":
			r.Header.Set("X-App-Generation", "wrong")
		case "absolute":
			r.URL = &url.URL{Scheme: "https", Host: "evil.example", Path: "/"}
		case "stream":
			r.Header.Add("X-App-Stream-ID", "duplicate")
		case "headers":
			r.Header.Set("X-Large", strings.Repeat("x", maxHeaders))
			status = 0
		}
		before := f.requests.Load()
		path := r.URL.String()
		fmt.Fprintf(peer, "POST %s HTTP/1.1\r\nHost: %s\r\n", path, r.Host)
		r.Header.Write(peer)
		io.WriteString(peer, "\r\n")
		response, e := http.ReadResponse(bufio.NewReader(peer), r)
		peer.Close()
		if status == 0 {
			if e == nil {
				t.Fatal("oversize header admitted")
			}
		} else if e != nil || response.StatusCode != status {
			t.Fatal(kind, e, response)
		}
		if f.requests.Load() != before {
			t.Fatal("refused request reached local app", kind)
		}
	}
}
func TestConnectorWSClientAndOriginFrameBoundsAndCompression(t *testing.T) {
	f := fixture(t, false, false, time.Minute)
	for _, bad := range [][]byte{{0x81, 1, 'x'}, {0x81, 0x80 | 127, 0, 0, 0, 0, 0, 0x10, 0, 1}, {0xc1, 0x80, 0, 0, 0, 0}, {0x89, 0x80 | 126, 0, 126}} {
		peer, response, reader := f.dial("/ws", http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Origin": {"https://" + testBinding().Hostname}})
		if response.StatusCode != 101 {
			t.Fatal(response.StatusCode)
		}
		io.ReadFull(reader, make([]byte, 4))
		peer.Write(bad)
		peer.SetReadDeadline(time.Now().Add(time.Second))
		if _, e := reader.ReadByte(); e == nil {
			t.Fatal("invalid client frame stayed open", bad)
		}
		peer.Close()
	}
	for _, path := range []string{"/origin-oversize", "/origin-mask", "/compression"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		peer, e := f.broker.Dial(ctx, testBinding())
		cancel()
		if e != nil {
			t.Fatal(e)
		}
		peer.SetDeadline(time.Now().Add(time.Second))
		r := &http.Request{Method: "GET", URL: &url.URL{Path: path}, Host: testBinding().Hostname, Header: http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Origin": {"https://" + testBinding().Hostname}}}
		apptransport.BindingHeaders(r.Header, testBinding())
		r.Header.Set("X-App-Stream-ID", "test-stream")
		r.Write(peer)
		reader := bufio.NewReader(peer)
		reply, e := http.ReadResponse(reader, r)
		if path == "/compression" {
			if e == nil && reply.StatusCode == 101 {
				t.Fatal("origin compression negotiated")
			}
		} else {
			if e != nil || reply.StatusCode != 101 {
				t.Fatal(path, e)
			}
			if _, e = io.ReadFull(reader, make([]byte, 4)); e != nil {
				t.Fatal("normal initial origin frame", e)
			}
			if _, e = reader.ReadByte(); e == nil {
				t.Fatal("invalid origin frame stayed open", path)
			}
		}
		peer.Close()
	}
}
func frame(fin bool, opcode byte, size int, masked bool) []byte {
	header := []byte{opcode, 0}
	if fin {
		header[0] |= 0x80
	}
	switch {
	case size < 126:
		header[1] = byte(size)
	case size <= 65535:
		header[1] = 126
		header = append(header, byte(size>>8), byte(size))
	default:
		header[1] = 127
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(size))
		header = append(header, n[:]...)
	}
	if masked {
		header[1] |= 0x80
		header = append(header, 0, 0, 0, 0)
	}
	return append(header, make([]byte, size)...)
}

func TestConnectorFullActivePoolBoundAndFastCancellation(t *testing.T) {
	f := fixture(t, false, false, time.Minute)
	var peers []net.Conn
	defer func() {
		for _, p := range peers {
			p.Close()
		}
	}()
	for i := 0; i < 32; i++ {
		peer, response, _ := f.dial("/sse", nil)
		peers = append(peers, peer)
		if _, e := io.ReadFull(response.Body, make([]byte, len("data: ready\n\n"))); e != nil {
			t.Fatal(e)
		}
		s := f.connector.Stats()
		if s.Active > 32 || s.Active+s.Idle+s.Opening > 34 {
			t.Fatal("pool exceeded bound", s)
		}
	}
	eventually(t, time.Second, func() bool { s := f.connector.Stats(); return s.Active == 32 && s.Idle == 2 })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	peer, e := f.broker.Dial(ctx, testBinding())
	cancel()
	if e != nil {
		t.Fatal(e)
	}
	peer.SetDeadline(time.Now().Add(time.Second))
	before := f.requests.Load()
	r := &http.Request{Method: "GET", URL: &url.URL{Path: "/"}, Host: testBinding().Hostname, Header: make(http.Header)}
	apptransport.BindingHeaders(r.Header, testBinding())
	r.Header.Set("X-App-Stream-ID", "over-capacity")
	r.Write(peer)
	if _, e = http.ReadResponse(bufio.NewReader(peer), r); e == nil {
		t.Fatal("33rd active stream reached origin")
	}
	peer.Close()
	if f.requests.Load() != before {
		t.Fatal("capacity refusal touched origin")
	}
	start := time.Now()
	f.cancel()
	select {
	case e = <-f.done:
		f.done <- e
	case <-time.After(time.Second):
		t.Fatal("active pool cancellation hung")
	}
	if s := f.connector.Stats(); s != (ConnectorStats{}) || f.connector.Ready() {
		t.Fatal("pool leaked after cancel", s)
	}
	t.Log("32 active +2 idle pool cancelled", time.Since(start))
}
func TestConnectorRejectsChunkedRequestAndDeclaredOriginBodyLimits(t *testing.T) {
	f := fixture(t, false, false, time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	peer, e := f.broker.Dial(ctx, testBinding())
	cancel()
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	peer.SetDeadline(time.Now().Add(3 * time.Second))
	r := &http.Request{Method: "POST", URL: &url.URL{Path: "/body"}, Host: testBinding().Hostname, Header: make(http.Header), Body: io.NopCloser(io.LimitReader(zeroReader{}, maxBody+1)), ContentLength: -1, TransferEncoding: []string{"chunked"}}
	apptransport.BindingHeaders(r.Header, testBinding())
	r.Header.Set("X-App-Stream-ID", "bounded-upload")
	done := make(chan error, 1)
	go func() { done <- r.Write(peer) }()
	if response, e := http.ReadResponse(bufio.NewReader(peer), r); e == nil && response.StatusCode == 200 {
		t.Fatal("chunked upload over limit succeeded")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("rejected upload writer did not release")
	}
	conn, response, _ := f.dial("/huge-response", nil)
	conn.Close()
	if response.StatusCode != 502 {
		t.Fatal("oversized origin Content-Length accepted", response.StatusCode)
	}
}
func TestConnectorAdmissionBackoffAndWrongProxyIdentityNeverReady(t *testing.T) {
	f := fixture(t, true, false, time.Minute)
	var attempts atomic.Int64
	denied := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { attempts.Add(1); http.Error(w, "refused", 403) }))
	denied.TLS = f.gateway.TLS.Clone()
	denied.Config.ErrorLog = log.New(io.Discard, "", 0)
	denied.StartTLS()
	defer denied.Close()
	o := f.options
	o.ProxyURL = denied.URL
	c, e := NewConnector(o)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2200*time.Millisecond)
	defer cancel()
	if e = c.Run(ctx); e == nil {
		t.Fatal("refused admission succeeded")
	}
	if c.Ready() || c.Stats() != (ConnectorStats{}) || attempts.Load() > 8 || attempts.Load() < 2 {
		t.Fatal("admission flood/leak", attempts.Load(), c.Stats())
	}
	o = f.options
	o.ProxyURL = f.origin.URL
	c, e = NewConnector(o)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	before := f.requests.Load()
	c.Run(ctx)
	if c.Ready() || f.requests.Load() != before {
		t.Fatal("proxy TLS accepted origin IP leaf as fixed server identity")
	}
}

func TestConnectorBlockedReaderKeepsHTTPAvailableAndRevocationReleases(t *testing.T) {
	f := fixture(t, false, false, time.Minute)
	peer, response, _ := f.dial("/blocked", nil)
	defer peer.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	eventually(t, time.Second, func() bool { return f.streamBytes.Load() > 256<<10 })
	time.Sleep(300 * time.Millisecond)
	before := f.streamBytes.Load()
	time.Sleep(300 * time.Millisecond)
	after := f.streamBytes.Load()
	if after >= maxBody || after-before > 256<<10 || f.connector.Stats().Active != 1 {
		t.Fatal("blocked reader did not backpressure bounded origin", before, after, f.connector.Stats())
	}
	conn, r, _ := f.dial("/", nil)
	body, e := io.ReadAll(r.Body)
	conn.Close()
	if e != nil || string(body) != "local Beam app" {
		t.Fatal("blocked stream starved HTTP", e)
	}
	f.allowed.Store(false)
	start := time.Now()
	eventually(t, 5*time.Second, func() bool { return f.connector.Stats().Active == 0 && !f.connector.Ready() })
	t.Log("blocked origin plateau bytes", after, "withdrawal", time.Since(start), "pool", f.connector.Stats())
}

func TestConnectorInformationalResponseAndPendingUpgradeWithdrawal(t *testing.T) {
	f := fixture(t, false, false, time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	peer, e := f.broker.Dial(ctx, testBinding())
	cancel()
	if e != nil {
		t.Fatal(e)
	}
	peer.SetDeadline(time.Now().Add(2 * time.Second))
	r := &http.Request{Method: "POST", URL: &url.URL{Path: "/body"}, Host: testBinding().Hostname, Header: http.Header{"Expect": {"100-continue"}}, Body: io.NopCloser(strings.NewReader("hello")), ContentLength: 5}
	apptransport.BindingHeaders(r.Header, testBinding())
	r.Header.Set("X-App-Stream-ID", "expect-body")
	r.Write(peer)
	response, e := http.ReadResponse(bufio.NewReader(peer), r)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := io.ReadAll(response.Body)
	peer.Close()
	if e != nil || response.StatusCode != 200 || string(raw) != "uploaded" {
		t.Fatal("informational response replaced final response", response.StatusCode, string(raw), e)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	peer, e = f.broker.Dial(ctx, testBinding())
	cancel()
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	r = &http.Request{Method: "GET", URL: &url.URL{Path: "/ws-stall"}, Host: testBinding().Hostname, Header: http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Origin": {"https://" + testBinding().Hostname}}}
	apptransport.BindingHeaders(r.Header, testBinding())
	r.Header.Set("X-App-Stream-ID", "pending-upgrade")
	r.Write(peer)
	eventually(t, time.Second, func() bool { return f.connector.Stats().Active == 1 })
	f.allowed.Store(false)
	start := time.Now()
	eventually(t, 5*time.Second, func() bool { return f.connector.Stats().Active == 0 && !f.connector.Ready() })
	t.Log("pending upgrade authority withdrawal", time.Since(start))
}

func TestConnectorPendingUpgradeEarlyHeadCannotPinRevokedChannel(t *testing.T) {
	f := fixture(t, false, false, time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	peer, e := f.broker.Dial(ctx, testBinding())
	cancel()
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	r := &http.Request{Method: "GET", URL: &url.URL{Path: "/ws-stall"}, Host: testBinding().Hostname, Header: http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Origin": {"https://" + testBinding().Hostname}}}
	apptransport.BindingHeaders(r.Header, testBinding())
	r.Header.Set("X-App-Stream-ID", "early-upgrade-head")
	// Write the complete request and early frame together, so this tests buffered
	// upgrade head, not only a normal post-101 frame.
	var request bytes.Buffer
	r.Write(&request)
	request.Write(frame(true, 1, 1, true))
	peer.Write(request.Bytes())
	eventually(t, time.Second, func() bool { return f.connector.Stats().Active == 1 && f.requests.Load() > 0 })
	f.allowed.Store(false)
	start := time.Now()
	eventually(t, 4*time.Second, func() bool { return f.connector.Stats().Active == 0 && !f.connector.Ready() })
	eventually(t, 500*time.Millisecond, func() bool { return f.upgradeClosed.Load() == 1 })
	t.Log("early-head pending upgrade withdrawal", time.Since(start), "origin sockets released", f.upgradeClosed.Load())
}

func TestConnectorAcceptedWebSocketOutlivesPendingHandshakeBudget(t *testing.T) {
	f := fixture(t, false, false, time.Minute)
	peer, response, reader := f.dial("/ws", http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Origin": {"https://" + testBinding().Hostname}})
	defer peer.Close()
	if response.StatusCode != 101 {
		t.Fatal(response.StatusCode)
	}
	if _, e := io.ReadFull(reader, make([]byte, 4)); e != nil {
		t.Fatal(e)
	}
	time.Sleep(2300 * time.Millisecond)
	if !f.connector.Ready() || f.connector.Stats().Active != 1 {
		t.Fatal("accepted WebSocket inherited pending-handshake deadline", f.connector.Stats())
	}
	if _, e := peer.Write(bytes.Join([][]byte{frame(false, 1, 1, true), frame(true, 9, 0, true), frame(true, 0, 1, true)}, nil)); e != nil {
		t.Fatal("normal fragmented/control frames rejected after upgrade", e)
	}
	conn, r, _ := f.dial("/", nil)
	body, e := io.ReadAll(r.Body)
	conn.Close()
	if e != nil || string(body) != "local Beam app" || f.connector.Stats().Active < 1 {
		t.Fatal("long-lived WebSocket lost service", e, f.connector.Stats())
	}
}
