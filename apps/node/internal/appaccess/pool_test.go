package appaccess

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

func TestPoolActualOutboundIdentityRotationAndBinding(t *testing.T) {
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
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"fixture"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, e := x509.CreateCertificate(rand.Reader, template, ca, pub, caKey)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := x509.MarshalPKCS8PrivateKey(key)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})
	}
	a := assignment()
	c := check(a)
	c.Deadline = time.Now().Add(20 * time.Second)
	var allowed atomic.Value
	allowed.Store("2")
	var seen atomic.Value
	seen.Store("")
	broker := apptransport.NewBroker(func(ctx context.Context, b apptransport.Binding, serial string) (time.Time, error) {
		if b != binding(a) || serial != allowed.Load().(string) {
			return time.Time{}, apptransport.ErrUnavailable
		}
		return time.Now().Add(4 * time.Second), nil
	})
	defer broker.Close()
	serverCertPEM, serverKey := leaf(4, true)
	serverCert, _ := tls.X509KeyPair(serverCertPEM, serverKey)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.Version != tls.VersionTLS13 {
			t.Error("channel TLS downgrade")
		}
		serial := r.TLS.PeerCertificates[0].SerialNumber.String()
		seen.Store(serial)
		if binding(a).ValidateHeaders(r.Header) != nil {
			http.Error(w, "forged", 403)
			return
		}
		_ = broker.Accept(w, r, binding(a), serial)
	}))
	proxy.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}
	proxy.StartTLS()
	defer proxy.Close()
	clientPEM, clientKey := leaf(2, false)
	client, e := control.NewClient(proxy.URL, "fixture", "node", clientPEM, clientKey, caPEM)
	if e != nil {
		t.Fatal(e)
	}
	channel, e := client.NewAppAccessClient("")
	if e != nil {
		t.Fatal(e)
	}
	var originCalls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originCalls.Add(1)
		if r.Host != "origin.example" {
			t.Errorf("origin Host %s", r.Host)
		}
		w.WriteHeader(401)
	}))
	defer origin.Close()
	p := NewPool(channel, func(ctx context.Context, a control.AppAssignment) originpolicy.Result {
		policy, _ := originpolicy.Normalize(a.AllowedDestinationCIDRs, a.OriginCAPEM)
		return (originpolicy.Checker{Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
		}, Dial: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, origin.Listener.Addr().String())
		}}).Check(ctx, a.OriginURL, policy)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer p.Close()
	p.Sync(ctx, map[string]control.AppAssignment{a.AppID: a}, []control.AppCheck{c})
	result, serial, e := broker.Probe(ctx, binding(a), c.ID)
	if e != nil || result.Status != "ready" || result.HTTPStatus != 401 || serial != "2" || seen.Load().(string) != "2" || originCalls.Load() != 1 {
		t.Fatal(result, serial, e, seen.Load(), originCalls.Load())
	}
	forged := binding(a)
	forged.Digest = strings.Repeat("b", 64)
	short, stop := context.WithTimeout(ctx, 50*time.Millisecond)
	_, _, e = broker.Probe(short, forged, c.ID)
	stop()
	if e == nil || originCalls.Load() != 1 {
		t.Fatal("forged assignment reached origin", e)
	}
	newPEM, newKey := leaf(3, false)
	allowed.Store("3")
	if e = client.AdoptCredentials(newPEM, newKey); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(10 * time.Second)
	for seen.Load().(string) != "3" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	c = check(a)
	c.Deadline = time.Now().Add(10 * time.Second)
	p.Sync(ctx, map[string]control.AppAssignment{a.AppID: a}, []control.AppCheck{c})
	rotated := false
	for time.Now().Before(deadline) {
		probe, stop := context.WithTimeout(ctx, time.Second)
		value, s, e := broker.Probe(probe, binding(a), c.ID)
		stop()
		if e == nil && s == "3" && value.Status == "ready" {
			rotated = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !rotated {
		t.Fatal("rotating certificate not used")
	}
	p.Sync(ctx, map[string]control.AppAssignment{}, nil)
	short, stop = context.WithTimeout(ctx, 100*time.Millisecond)
	_, _, e = broker.Probe(short, binding(a), c.ID)
	stop()
	if e == nil {
		t.Fatal("withdrawn assignment available")
	}
}

func TestCONNECTResponseHeaderBoundAndBufferedBytes(t *testing.T) {
	req := &http.Request{Method: "CONNECT"}
	huge := &handshakeReader{reader: strings.NewReader("HTTP/1.1 200 OK\r\nX-Huge: " + strings.Repeat("a", 40<<10) + "\r\n\r\n"), remaining: 32 << 10, limited: true}
	if _, e := http.ReadResponse(bufio.NewReader(huge), req); e == nil {
		t.Fatal("unbounded header accepted")
	}
	reader := &handshakeReader{reader: strings.NewReader("HTTP/1.1 200 OK\r\n\r\nnextbytes"), remaining: 32 << 10, limited: true}
	buffer := bufio.NewReader(reader)
	if _, e := http.ReadResponse(buffer, req); e != nil {
		t.Fatal(e)
	}
	reader.limited = false
	rest, e := io.ReadAll(buffer)
	if e != nil || string(rest) != "nextbytes" {
		t.Fatal(string(rest), e)
	}
}
func TestFixedProbeRejectsBodyAndAmbiguousIdentity(t *testing.T) {
	b := binding(assignment())
	makeReq := func() *http.Request {
		req, _ := http.NewRequest("GET", "http://logical.app/__app_access/check", nil)
		apptransport.BindingHeaders(req.Header, b)
		req.Header.Set("X-App-Check-ID", "check")
		return req
	}
	if !validCheckRequest(makeReq(), b) {
		t.Fatal("valid probe refused")
	}
	for _, kind := range []string{"chunked", "body", "duplicate", "query", "method"} {
		req := makeReq()
		switch kind {
		case "chunked":
			req.TransferEncoding = []string{"chunked"}
			req.ContentLength = -1
		case "body":
			req.Body = io.NopCloser(strings.NewReader("body"))
		case "duplicate":
			req.Header.Add("X-App-Check-ID", "check")
		case "query":
			req.URL.ForceQuery = true
		case "method":
			req.Method = "CONNECT"
		}
		if validCheckRequest(req, b) {
			t.Fatal(kind)
		}
	}
}

func TestAppChannelTLS13RejectsLegacyServer(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("downgraded request reached server") }))
	server.TLS = &tls.Config{MaxVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	certificate := server.TLS.Certificates[0]
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})
	raw, e := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})
	client, e := control.NewClient(server.URL, "example.com", "node", certPEM, key, certPEM)
	if e != nil {
		t.Fatal(e)
	}
	app, e := client.NewAppAccessClient("")
	if e != nil {
		t.Fatal(e)
	}
	if app.Capability(t.Context()) == nil {
		t.Fatal("TLS12 channel accepted")
	}
}
