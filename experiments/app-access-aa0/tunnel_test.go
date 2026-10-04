package spike

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func setup(t *testing.T, h http.Handler) (*Broker, string, *tls.Config, *url.URL) {
	t.Helper()
	b := NewBroker(Binding{"org", "gateway", "app", "1"}, 2)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gateway", OrganizationalUnit: []string{"org"}}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, IsCA: true, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	b.Identities = map[string]Binding{"1": b.Binding}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert, _ := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	s := httptest.NewUnstartedServer(b)
	s.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13}
	s.StartTLS()
	origin := httptest.NewServer(h)
	u, _ := url.Parse(origin.URL)
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	cfg := &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}, ServerName: "example.com", MinVersion: tls.VersionTLS13}
	t.Cleanup(func() { b.Close(); s.Close(); origin.Close() })
	return b, strings.TrimPrefix(s.URL, "https://"), cfg, u
}
func TestHTTPReconnectSSECancel(t *testing.T) {
	cancelled := make(chan struct{}, 1)
	b, addr, cfg, origin := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sse" {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "data: approved\n\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			cancelled <- struct{}{}
			return
		}
		io.WriteString(w, "approved-origin-bytes")
	}))
	p := httptest.NewServer(b.Proxy(origin))
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < 2; i++ {
		go Connect(ctx, addr, cfg, b.Binding, origin)
		r, err := http.Get(p.URL)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if string(body) != "approved-origin-bytes" {
			t.Fatalf("bytes %q", body)
		}
	}
	go Connect(ctx, addr, cfg, b.Binding, origin)
	r, err := http.Get(p.URL + "/sse")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := r.Body.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "approved") {
		t.Fatalf("SSE %q %v", buf[:n], err)
	}
	r.Body.Close()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("cancellation")
	}
}
func TestForgedBindingCapacity(t *testing.T) {
	b, addr, cfg, origin := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, binding := range []Binding{{"org", "gateway", "foreign", "1"}, {"org", "gateway", "app", "old"}} {
		if err := Connect(ctx, addr, cfg, binding, origin); err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatalf("forgery: %v", err)
		}
	}
	for i := 0; i < 2; i++ {
		go Connect(ctx, addr, cfg, b.Binding, origin)
	}
	deadline := time.Now().Add(time.Second)
	for len(b.slots) != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if err := Connect(ctx, addr, cfg, b.Binding, origin); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("capacity: %v", err)
	}
}

func TestWrongCertificateScope(t *testing.T) {
	for _, field := range []string{"org", "gateway"} {
		t.Run(field, func(t *testing.T) {
			b, addr, cfg, origin := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			if field == "org" {
				b.Binding.Org = "other"
			} else {
				b.Binding.Gateway = "other"
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := Connect(ctx, addr, cfg, b.Binding, origin); err == nil || !strings.Contains(err.Error(), "403") {
				t.Fatalf("certificate scope accepted %v", err)
			}
		})
	}
}

func TestWebSocketMultiFrame(t *testing.T) {
	originClosed := make(chan struct{})
	b, addr, cfg, origin := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer close(originClosed)
		defer c.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
		rw.Flush()
		for i := 0; i < 2; i++ {
			frame := make([]byte, 7)
			if _, err := io.ReadFull(rw, frame); err != nil {
				return
			}
			c.Write([]byte{0x81, 1, frame[6] ^ frame[2]})
		}
		one := make([]byte, 1)
		rw.Read(one)
	}))
	p := httptest.NewServer(b.Proxy(origin))
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go Connect(ctx, addr, cfg, b.Binding, origin)
	c, err := net.Dial("tcp", strings.TrimPrefix(p.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(c, "GET /ws HTTP/1.1\r\nHost: example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	reader := bufio.NewReader(c)
	response, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	if err != nil || response.StatusCode != 101 {
		t.Fatalf("upgrade %v %v", response, err)
	}
	for _, v := range []byte{'a', 'b'} {
		c.Write([]byte{0x81, 0x81, 1, 2, 3, 4, v ^ 1})
		got := make([]byte, 3)
		if _, err := io.ReadFull(reader, got); err != nil || got[2] != v {
			t.Fatalf("frame %v %v", got, err)
		}
	}
	c.Close()
	select {
	case <-originClosed:
	case <-time.After(time.Second):
		t.Fatal("websocket origin did not close on browser cancellation")
	}
}

func TestSlowReaderBoundedLifetime(t *testing.T) {
	stopped := make(chan struct{})
	b, addr, cfg, origin := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(stopped)
		block := make([]byte, 32<<10)
		for {
			if _, err := w.Write(block); err != nil {
				return
			}
		}
	}))
	p := httptest.NewUnstartedServer(b.Proxy(origin))
	p.Config.WriteTimeout = 3 * time.Second
	p.Start()
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go Connect(ctx, addr, cfg, b.Binding, origin)
	c, err := net.Dial("tcp", strings.TrimPrefix(p.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET /large HTTP/1.1\r\nHost: example\r\n\r\n")
	select {
	case <-stopped:
	case <-time.After(4 * time.Second):
		t.Fatal("slow reader failed bounded origin termination")
	}
}

func TestHTTPSOriginTrust(t *testing.T) {
	for _, trusted := range []bool{true, false} {
		t.Run(fmt.Sprint(trusted), func(t *testing.T) {
			b, addr, cfg, _ := setup(t, http.NotFoundHandler())
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "verified-private-https") }))
			defer origin.Close()
			u, _ := url.Parse(origin.URL)
			var roots *x509.CertPool
			if trusted {
				roots = x509.NewCertPool()
				roots.AddCert(origin.Certificate())
			}
			p := httptest.NewServer(b.Proxy(u))
			defer p.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			go connectWithTrust(ctx, addr, cfg, b.Binding, u, roots)
			r, err := http.Get(p.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Body.Close()
			body, _ := io.ReadAll(r.Body)
			if trusted && (r.StatusCode != 200 || string(body) != "verified-private-https") {
				t.Fatalf("HTTPS %d %q", r.StatusCode, body)
			}
			if !trusted && r.StatusCode != 502 {
				t.Fatalf("untrusted TLS accepted %d", r.StatusCode)
			}
		})
	}
}

func TestUnrecognizedSerialAndBrowserCONNECT(t *testing.T) {
	b, addr, cfg, origin := setup(t, http.NotFoundHandler())
	b.Identities = map[string]Binding{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := Connect(ctx, addr, cfg, b.Binding, origin); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("unknown serial %v", err)
	}
	p := httptest.NewServer(b.Proxy(origin))
	defer p.Close()
	request, _ := http.NewRequest("CONNECT", p.URL, nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 405 {
		t.Fatalf("browser CONNECT %d", response.StatusCode)
	}
}
func TestPOSTPayload(t *testing.T) {
	payload := strings.Repeat("approved-upload", 4096)
	b, addr, cfg, origin := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		data, _ := io.ReadAll(io.LimitReader(r.Body, 128<<10))
		w.Write(data)
	}))
	p := httptest.NewServer(b.Proxy(origin))
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go Connect(ctx, addr, cfg, b.Binding, origin)
	r, err := http.Post(p.URL, "application/octet-stream", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	data, _ := io.ReadAll(r.Body)
	if string(data) != payload {
		t.Fatalf("POST payload length %d", len(data))
	}
}
func TestInternalMethodPathAndMissingCertificate(t *testing.T) {
	b, addr, cfg, _ := setup(t, http.NotFoundHandler())
	for _, test := range []struct{ method, path string }{{"GET", "/channel"}, {"CONNECT", "/wrong"}} {
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: time.Second}
		request, _ := http.NewRequest(test.method, "https://"+addr+test.path, nil)
		r, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != 403 {
			t.Fatalf("internal route %d", r.StatusCode)
		}
	}
	without := cfg.Clone()
	without.Certificates = nil
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: without}, Timeout: time.Second}
	if r, err := client.Get("https://" + addr + "/channel"); err == nil {
		r.Body.Close()
		t.Fatal("missing cert accepted")
	}
	_ = b
}
