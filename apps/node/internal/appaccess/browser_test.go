package appaccess

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
	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/packages/apptransport"
	"github.com/tunnexio/tunnex/packages/apptransport/originpolicy"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
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
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"tunnex-app-proxy"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, e := x509.CreateCertificate(rand.Reader, template, ca, pub, caKey)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := x509.MarshalPKCS8PrivateKey(key)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})
	}
	return leaf, caPEM
}
func TestBrowserPoolActualMTLSFormsAssetsSSEWebSocket(t *testing.T) {
	leaf, caPEM := browserCertificates(t)
	serverPEM, serverKey := leaf(4, true)
	serverCert, _ := tls.X509KeyPair(serverPEM, serverKey)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	b := apptransport.Binding{OrgID: "11111111-1111-1111-1111-111111111111", GatewayID: "22222222-2222-2222-2222-222222222222", AppID: "33333333-3333-3333-3333-333333333333", Generation: "44444444-4444-4444-4444-444444444444", Revision: 3, AuthorityVersion: 1, Digest: strings.Repeat("a", 64), Purpose: "browser_proxy", Hostname: "app.apps.test"}
	broker := apptransport.NewBrowserBroker(func(ctx context.Context, actual apptransport.Binding, serial string) (time.Time, error) {
		if actual != b || serial != "2" {
			return time.Time{}, apptransport.ErrUnavailable
		}
		return time.Now().Add(3 * time.Second), nil
	})
	defer broker.Close()
	gateway := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.Version != tls.VersionTLS13 || b.ValidateHeaders(r.Header) != nil {
			http.Error(w, "refused", 403)
			return
		}
		broker.Accept(w, r, b, r.TLS.PeerCertificates[0].SerialNumber.String())
	}))
	gateway.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	gateway.StartTLS()
	defer gateway.Close()
	clientPEM, clientKey := leaf(2, false)
	client, e := control.NewClient(gateway.URL, "tunnex-app-proxy", "node", clientPEM, clientKey, caPEM)
	if e != nil {
		t.Fatal(e)
	}
	_, config, e := client.AppAccessTLSConfig("")
	if e != nil {
		t.Fatal(e)
	}
	var originRequests atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originRequests.Add(1)
		if r.Host != "origin.example" || r.Header.Get("Cookie") != "ordinary=value" || r.Header.Get("X-App-ID") != "" {
			t.Errorf("origin metadata: %s %v", r.Host, r.Header)
		}
		switch r.URL.Path {
		case "/form":
			body, _ := io.ReadAll(r.Body)
			w.Write(body)
		case "/events":
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "data: ready\n\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case "/ws":
			c, rw, _ := w.(http.Hijacker).Hijack()
			defer c.Close()
			echoWebSocket(c, rw, r.Header.Get("Sec-WebSocket-Key"))
		default:
			io.WriteString(w, "asset")
		}
	}))
	defer origin.Close()
	policy, _ := originpolicy.Normalize([]string{"10.1.2.3/32"}, "")
	checker := originpolicy.Checker{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
	}, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "10.1.2.3:80" {
			t.Errorf("nonliteral dial: %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, origin.Listener.Addr().String())
	}}
	pool, e := NewBrowserPool(gateway.URL, config, checker)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer pool.Close()
	pool.Sync(ctx, []BrowserAssignment{{Binding: b, OriginURL: "http://origin.example", Policy: policy}})
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(c context.Context, _, _ string) (net.Conn, error) { return broker.Dial(c, b) }}
	defer transport.CloseIdleConnections()
	request := func(method, path, body string) *http.Request {
		r, _ := http.NewRequest(method, "http://connector.internal"+path, strings.NewReader(body))
		r.Host = b.Hostname
		apptransport.BindingHeaders(r.Header, b)
		r.Header.Set("X-App-Stream-ID", "authorized-stream")
		r.Header.Set("Cookie", "ordinary=value; __Host-tunnex_app_session=secret")
		return r
	}
	// Two concurrent SSE streams must not prevent a third form/asset channel.
	events := []*http.Response{}
	for i := 0; i < 2; i++ {
		response, e := transport.RoundTrip(request("GET", "/events", ""))
		if e != nil {
			t.Fatal(e)
		}
		line, e := bufio.NewReader(response.Body).ReadString('\n')
		if e != nil || line != "data: ready\n" {
			t.Fatal(line, e)
		}
		events = append(events, response)
		defer response.Body.Close()
	}
	for _, tc := range []struct{ method, path, body, want string }{{"POST", "/form", "field=value", "field=value"}, {"GET", "/asset", "", "asset"}} {
		response, e := transport.RoundTrip(request(tc.method, tc.path, tc.body))
		if e != nil {
			t.Fatal(e)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if string(body) != tc.want {
			t.Fatal(string(body))
		}
	}
	r := request("GET", "/ws", "")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	r.Header.Set("Sec-WebSocket-Version", "13")
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	response, e := transport.RoundTrip(r)
	if e != nil || response.StatusCode != 101 {
		t.Fatal(response, e)
	}
	stream, ok := response.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatal("upgrade not bidirectional")
	}
	if response.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatal("invalid websocket handshake")
	}
	for _, text := range []string{"one", "two"} {
		frame := string(append([]byte{0x81, byte(len(text))}, []byte(text)...))
		if _, e = stream.Write(maskedFrame(text)); e != nil {
			t.Fatal(e)
		}
		got := make([]byte, len(frame))
		if _, e = io.ReadFull(stream, got); e != nil || string(got) != frame {
			t.Fatal(got, e)
		}
	}
	defer stream.Close()
	before := originRequests.Load()
	if before != 5 { // Two SSE streams, a form, an asset and a WebSocket.
		t.Fatalf("unexpected origin requests before withdrawal: %d", before)
	}
	pool.Sync(ctx, nil)
	// Cancellation and peer EOF are asynchronous: Dial may hand out an idle
	// channel before it observes closure. Assert actual access is withdrawn,
	// including streams that were already active, rather than handle acquisition.
	short, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	response, e = transport.RoundTrip(request("GET", "/after-withdrawal", "").WithContext(short))
	if e == nil {
		response.Body.Close()
		if response.StatusCode != http.StatusBadGateway {
			t.Fatalf("withdrawn channel forwarded request: HTTP %d", response.StatusCode)
		}
	}
	for _, response := range events {
		closed := make(chan struct{})
		go func() { io.Copy(io.Discard, response.Body); close(closed) }()
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("SSE stream survived withdrawal")
		}
	}
	closed := make(chan error, 1)
	go func() { var one [1]byte; _, e := stream.Read(one[:]); closed <- e }()
	select {
	case e := <-closed:
		if e == nil {
			t.Fatal("WebSocket survived withdrawal")
		}
	case <-time.After(time.Second):
		t.Fatal("WebSocket did not close on withdrawal")
	}
	if got := originRequests.Load(); got != before {
		t.Fatalf("post-withdrawal origin access: got %d requests, want %d", got, before)
	}
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
