package appaccess

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/packages/apptransport"
	"github.com/tunnexio/tunnex/packages/apptransport/originpolicy"
)

func TestProxyModeFromEnv(t *testing.T) {
	for value, want := range map[string]ProxyMode{"": ProxyFollow, "  ": ProxyFollow, "off": ProxyOff, "https://tunnex-app-proxy:8444": ProxyURL, "not a url": ProxyURL} {
		if got, _ := ProxyModeFromEnv(value); got != want {
			t.Errorf("%q = %s, want %s", value, got, want)
		}
	}
	if _, u := ProxyModeFromEnv(" https://10.70.0.2:8444 "); u != "https://10.70.0.2:8444" {
		t.Fatalf("override = %q", u)
	}
}

func TestEndpointURL(t *testing.T) {
	for _, tc := range []struct {
		agent string
		e     control.AppProxyEndpoint
		want  string
	}{
		{"cp.example.test", control.AppProxyEndpoint{Enabled: true, Port: 8444}, "https://cp.example.test:8444"},
		{"cp.example.test", control.AppProxyEndpoint{Enabled: true, Port: 8444, Host: "10.70.0.2"}, "https://10.70.0.2:8444"},
		{"cp.example.test", control.AppProxyEndpoint{Enabled: true, Port: 9444, Host: "fd00::2"}, "https://[fd00::2]:9444"},
		{"203.0.113.10", control.AppProxyEndpoint{Enabled: true, Port: 8444}, "https://203.0.113.10:8444"},
		{"cp.example.test", control.AppProxyEndpoint{Enabled: true, Port: 0}, ""},
		{"cp.example.test", control.AppProxyEndpoint{Enabled: true, Port: 70000}, ""},
		{"", control.AppProxyEndpoint{Enabled: true, Port: 8444}, ""},
		{"cp.example.test", control.AppProxyEndpoint{Enabled: true, Port: 8444, Host: "evil.example/x"}, ""},
		{"cp.example.test", control.AppProxyEndpoint{Enabled: true, Port: 8444, Host: "user@evil.example"}, ""},
		{"cp.example.test", control.AppProxyEndpoint{Enabled: true, Port: 8444, Host: "evil.example:1"}, ""},
	} {
		got, err := EndpointURL(tc.agent, tc.e)
		if (tc.want == "") != (err != nil) || got != tc.want {
			t.Errorf("%q %+v = %q, %v; want %q", tc.agent, tc.e, got, err, tc.want)
		}
	}
}

type fakeProxyControl struct {
	mu      sync.Mutex
	answer  control.AppProxyEndpoint
	err     error
	starts  []string
	running map[string]bool
	polled  chan struct{}
}

func (f *fakeProxyControl) set(answer control.AppProxyEndpoint, err error) {
	f.mu.Lock()
	f.answer, f.err = answer, err
	f.mu.Unlock()
}
func (f *fakeProxyControl) poll(context.Context) (control.AppProxyEndpoint, error) {
	f.mu.Lock()
	a, e := f.answer, f.err
	f.mu.Unlock()
	select {
	case f.polled <- struct{}{}:
	default:
	}
	return a, e
}
func (f *fakeProxyControl) start(ctx context.Context, endpoint string) (func(), error) {
	f.mu.Lock()
	f.starts = append(f.starts, endpoint)
	f.running[endpoint] = true
	f.mu.Unlock()
	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		f.mu.Lock()
		delete(f.running, endpoint)
		f.mu.Unlock()
		close(done)
	}()
	return func() { <-done }, nil
}
func (f *fakeProxyControl) state() ([]string, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var running []string
	for k := range f.running {
		running = append(running, k)
	}
	return append([]string(nil), f.starts...), running
}

// Start, keep, restart on a changed endpoint, keep across errors and an old
// control plane's 404, stop when delivery turns off, and stop on shutdown.
func TestFollowProxyStartsStopsAndKeepsStateWithoutRestart(t *testing.T) {
	f := &fakeProxyControl{running: map[string]bool{}, polled: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() { FollowProxy(ctx, time.Millisecond, "cp.example.test", f.poll, f.start, logger); close(done) }()
	settle := func() {
		for range 3 {
			<-f.polled
		}
	}
	expect := func(step string, starts int, running ...string) {
		t.Helper()
		settle()
		s, r := f.state()
		if len(s) != starts || len(r) != len(running) || (len(running) == 1 && r[0] != running[0]) {
			t.Fatalf("%s: starts=%v running=%v; want %d starts, running %v", step, s, r, starts, running)
		}
	}
	expect("off at first", 0)
	f.set(control.AppProxyEndpoint{Enabled: true, Port: 8444}, nil)
	expect("enabled, agent host", 1, "https://cp.example.test:8444")
	expect("unchanged endpoint is not restarted", 1, "https://cp.example.test:8444")
	f.set(control.AppProxyEndpoint{}, errors.New("control plane unreachable"))
	expect("unreachable keeps running", 1, "https://cp.example.test:8444")
	f.set(control.AppProxyEndpoint{}, control.ErrProxyEndpointUnsupported)
	expect("old control plane keeps running", 1, "https://cp.example.test:8444")
	f.set(control.AppProxyEndpoint{Enabled: true, Port: 8444, Host: "10.70.0.2"}, nil)
	expect("override host restarts", 2, "https://10.70.0.2:8444")
	f.set(control.AppProxyEndpoint{Enabled: true, Port: 8444, Host: "bad/host"}, nil)
	expect("invalid delivery stops", 2)
	f.set(control.AppProxyEndpoint{Enabled: true, Port: 8444, Host: "10.70.0.2"}, nil)
	expect("valid again starts", 3, "https://10.70.0.2:8444")
	f.set(control.AppProxyEndpoint{Enabled: false}, nil)
	expect("disabled stops", 3)
	f.set(control.AppProxyEndpoint{Enabled: true, Port: 8444}, nil)
	expect("enabled again", 4, "https://cp.example.test:8444")
	cancel()
	<-done
	if _, r := f.state(); len(r) != 0 {
		t.Fatalf("shutdown left %v running", r)
	}
}

// G1, with a real TLS listener: a pool built exactly as the supervisor builds
// it, dialling an IP address, completes the mutual TLS handshake against a
// "tunnex-app-proxy" leaf from the enrollment CA. No hosts entry is involved.
// A leaf with any other name, or from another CA, is refused.
func TestBrowserPoolDialsIPWithPinnedServerName(t *testing.T) {
	ca, caKey, caPEM := testCA(t, "enrollment CA")
	otherCA, otherKey, _ := testCA(t, "other CA")
	clientPEM, clientKeyPEM := testLeaf(t, ca, caKey, "node", x509.ExtKeyUsageClientAuth)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	for _, tc := range []struct {
		name   string
		issuer *x509.Certificate
		key    *ecdsa.PrivateKey
		san    string
		ok     bool
	}{
		{"pinned name, enrollment CA", ca, caKey, "tunnex-app-proxy", true},
		{"other name", ca, caKey, "cp.example.test", false},
		{"other CA", otherCA, otherKey, "tunnex-app-proxy", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certPEM, keyPEM := testLeaf(t, tc.issuer, tc.key, tc.san, x509.ExtKeyUsageServerAuth)
			serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				t.Fatal(err)
			}
			ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			handshake := make(chan error, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					handshake <- err
					return
				}
				defer c.Close()
				err = c.(*tls.Conn).Handshake()
				handshake <- err
				if err == nil {
					_, _ = io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
				}
			}()
			endpoint, err := EndpointURL("127.0.0.1", control.AppProxyEndpoint{Enabled: true, Port: ln.Addr().(*net.TCPAddr).Port})
			if err != nil {
				t.Fatal(err)
			}
			client, err := control.NewClient("https://127.0.0.1:1", "tunnex-control", "node", clientPEM, clientKeyPEM, caPEM)
			if err != nil {
				t.Fatal(err)
			}
			_, config, err := client.AppAccessTLSConfig(endpoint)
			if err != nil {
				t.Fatal(err)
			}
			pool, err := NewBrowserPool(endpoint, config, originpolicy.Checker{})
			if err != nil {
				t.Fatal(err)
			}
			if !containsHost(pool.checker.ControlHosts, "127.0.0.1") {
				t.Fatal("dialled host is not refused as an origin (G2)")
			}
			b := apptransport.Binding{OrgID: "11111111-1111-1111-1111-111111111111", GatewayID: "22222222-2222-2222-2222-222222222222", AppID: "33333333-3333-3333-3333-333333333333", Generation: "44444444-4444-4444-4444-444444444444", Revision: 1, AuthorityVersion: 1, Digest: strings.Repeat("a", 64), Purpose: "browser_proxy", Hostname: "app.apps.test"}
			serveErr := pool.serve(context.Background(), BrowserAssignment{Binding: b, OriginURL: "https://origin.example"}, func() {})
			if tc.ok {
				if err := <-handshake; err != nil {
					t.Fatalf("server handshake: %v", err)
				}
				// The handshake passed; the fake proxy then refused the channel.
				if !errors.Is(serveErr, apptransport.ErrUnavailable) {
					t.Fatalf("serve after handshake = %v", serveErr)
				}
				return
			}
			var verify *tls.CertificateVerificationError
			if !errors.As(serveErr, &verify) {
				t.Fatalf("serve = %v, want a certificate verification failure", serveErr)
			}
		})
	}
}

func containsHost(hosts []string, want string) bool {
	for _, h := range hosts {
		if h == want {
			return true
		}
	}
	return false
}

func testCA(t *testing.T, name string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func testLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, san string, usage x509.ExtKeyUsage) ([]byte, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: san}, DNSNames: []string{san}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})
}
