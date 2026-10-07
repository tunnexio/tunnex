package beamreadiness

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func configured() Config {
	return Config{BaseDomain: "beam.example.net", ProxyURL: "https://connector.example.net:8443", PortalURL: "https://console.example.com", Asserted: true}
}
func TestProbeConfigurationAndVersionFailClosed(t *testing.T) {
	p := New()
	calls := 0
	p.lookup = func(context.Context, string) ([]net.IPAddr, error) { calls++; return nil, nil }
	c := configured()
	v, reason := p.Check(context.Background(), c, "stale")
	if reason != "stale" || v.CheckedAt != nil || calls != 0 {
		t.Fatal("stale probe performed network work")
	}
	c.ProxyURL = "https://connector.example.net/path"
	v, reason = p.Check(context.Background(), c, Version(c))
	if reason != "" || v.Passed || len(v.Checks) != 1 || calls != 0 {
		t.Fatal("invalid configuration was probed")
	}
	c = configured()
	c.BaseDomain = "beam.example.com"
	v = p.probe(context.Background(), c)
	if v.Passed || len(v.Checks) != 1 {
		t.Fatal("unsafe console sibling was accepted")
	}
}
func TestSnapshotDoesNotLeakInvalidEndpointCredentials(t *testing.T) {
	c := configured()
	c.ProxyURL = "https://user:private-password@connector.example.net/?token=private-token"
	c.ConnectorCA = []byte("PRIVATE TRUST BYTES")
	data, e := json.Marshal(Snapshot(c))
	if e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{"private-password", "private-token", "PRIVATE TRUST BYTES"} {
		if strings.Contains(string(data), secret) {
			t.Fatal("operator snapshot leaked invalid configured credentials")
		}
	}
}
func testCertificate(t *testing.T, names []string, expired bool, deadlines ...time.Time) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	after := time.Now().Add(time.Hour)
	if len(deadlines) > 0 {
		after = deadlines[0]
	}
	before := time.Now().Add(-time.Minute)
	if expired {
		before = time.Now().Add(-2 * time.Hour)
		after = time.Now().Add(-time.Hour)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: before, NotAfter: after, DNSNames: names, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, cert
}
func TestRealTLSWildcardHostAndUnknownHostDenial(t *testing.T) {
	for _, tc := range []struct {
		name                                              string
		status                                            int
		cookie, redirect, expired, wrongName, shortExpiry bool
	}{
		{name: "unknown403", status: 403}, {name: "unknown404", status: 404}, {name: "certificateDeadline", status: 404, shortExpiry: true}, {name: "unknown421", status: 421}, {name: "wrongDNSdestination200", status: 200}, {name: "redirect302", status: 302, redirect: true}, {name: "denialwithcookie", status: 403, cookie: true}, {name: "denialwithredirect", status: 404, redirect: true}, {name: "expiredwildcard", status: 404, expired: true}, {name: "wronghostname", status: 404, wrongName: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := ""
			public := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				host = r.Host
				if tc.redirect {
					w.Header().Set("Location", "https://foreign.example/")
				}
				if tc.cookie {
					w.Header().Set("Set-Cookie", "unexpected=value")
				}
				w.WriteHeader(tc.status)
			}))
			names := []string{"*.beam.example.net"}
			if tc.wrongName {
				names = []string{"other.example.net"}
			}
			var deadlines []time.Time
			if tc.shortExpiry {
				deadlines = []time.Time{time.Now().Add(75 * time.Second)}
			}
			publicKey, publicCert := testCertificate(t, names, tc.expired, deadlines...)
			public.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{publicKey}}
			public.StartTLS()
			defer public.Close()
			roots := x509.NewCertPool()
			roots.AddCert(publicCert)
			purposeKey, purposeCert := testCertificate(t, []string{"tunnex-beam-proxy"}, false)
			connectorRoots := x509.NewCertPool()
			connectorRoots.AddCert(purposeCert)
			connector := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("readiness sent a credentialed HTTP request to connector")
			}))
			connector.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{purposeKey}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: connectorRoots}
			connector.StartTLS()
			defer connector.Close()
			c := configured()
			c.ConnectorCA = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: purposeCert.Raw})
			p := New()
			p.roots = roots
			p.allowLoopback = true
			p.lookup = func(context.Context, string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
			}
			p.dial = func(ctx context.Context, n, a string) (net.Conn, error) {
				target := public.Listener.Addr().String()
				if strings.HasSuffix(a, ":8443") {
					target = connector.Listener.Addr().String()
				}
				return (&net.Dialer{}).DialContext(ctx, n, target)
			}
			v := p.probe(context.Background(), c)
			want := tc.status != 200 && !tc.cookie && !tc.redirect && !tc.expired && !tc.wrongName
			if tc.shortExpiry && (v.ExpiresAt == nil || !v.ExpiresAt.Equal(publicCert.NotAfter)) {
				t.Fatal("readiness evidence survived certificate expiry")
			}
			if v.Passed != want {
				t.Fatalf("wrong readiness: %#v", v)
			}
			if !tc.expired && !tc.wrongName && (!strings.HasSuffix(host, ".beam.example.net") || !strings.HasPrefix(host, "p-") || len(strings.Split(host, ".")[0]) != 34) {
				t.Fatal("exact allocated-host shape not preserved")
			}
			if len(v.Checks) != 5 || !v.Checks[4].Passed {
				t.Fatalf("real purpose connector certificate failed: %#v", v.Checks)
			}
		})
	}
}
func TestProbeBoundsUnsafeDNSAndEvidenceExpiry(t *testing.T) {
	p := New()
	p.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("169.254.169.254")}, {IP: net.ParseIP("::1")}}, nil
	}
	p.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("unsafe address dialed")
		return nil, nil
	}
	c := configured()
	v, reason := p.Check(context.Background(), c, Version(c))
	if reason != "" || v.Passed || v.Checks[1].Passed {
		t.Fatal("unsafe DNS became ready")
	}
	cached, _ := p.Check(context.Background(), c, Version(c))
	if !cached.CheckedAt.Equal(*v.CheckedAt) {
		t.Fatal("cooldown should reuse evidence")
	}
	old := time.Now().Add(-time.Second)
	p.last.Passed = true
	p.last.ExpiresAt = &old
	if p.Get(c).Passed {
		t.Fatal("expired evidence remained passed")
	}
	c.ProxyURL = "https://new.example.net"
	if p.Get(c).CheckedAt != nil {
		t.Fatal("new configuration reused old evidence")
	}
	if strings.Contains(Version(c), "CERTIFICATE") {
		t.Fatal("configuration fingerprint leaked CA")
	}
}
func TestProbeCancellation(t *testing.T) {
	p := New()
	p.lookup = func(ctx context.Context, _ string) ([]net.IPAddr, error) { <-ctx.Done(); return nil, ctx.Err() }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	v := p.probe(ctx, configured())
	if v.Passed || time.Since(start) > time.Second {
		t.Fatal("cancelled request continued probes")
	}
}

func TestConcurrentProbeSingleFlight(t *testing.T) {
	p := New()
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	p.lookup = func(ctx context.Context, _ string) ([]net.IPAddr, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-release:
			return nil, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	c := configured()
	done := make(chan struct{})
	go func() { defer close(done); p.Check(context.Background(), c, Version(c)) }()
	<-entered
	if _, reason := p.Check(context.Background(), c, Version(c)); reason != "busy" {
		t.Fatal("overlapping network probe accepted")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("probe did not finish after resolver returned")
	}
}
func TestExplicitDevelopmentTrustFactory(t *testing.T) {
	_, cert := testCertificate(t, []string{"*.beam.example.net"}, false)
	trusted := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if _, e := NewConfigured(false, trusted); e == nil {
		t.Fatal("production mode accepted development public trust")
	}
	for _, bad := range [][]byte{[]byte("not PEM"), []byte(strings.Repeat(" ", 65537)), append(trusted, []byte("PRIVATE KEY MATERIAL")...)} {
		if _, e := NewConfigured(true, bad); e == nil {
			t.Fatal("invalid development trust accepted")
		}
	}
	p, e := NewConfigured(true, trusted)
	if e != nil || !p.allowLoopback || p.roots == nil {
		t.Fatal("explicit valid development fixture trust rejected")
	}
	other, _ := NewConfigured(true, nil)
	if other.ProbeFingerprint() == p.ProbeFingerprint() {
		t.Fatal("development trust changes did not change probe fingerprint")
	}
	c := configured()
	before := Version(c)
	c.ProbeFingerprint = p.ProbeFingerprint()
	if Version(c) == before {
		t.Fatal("persisted config version did not bind probe trust")
	}
}
