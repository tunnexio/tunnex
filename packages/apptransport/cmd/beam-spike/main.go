// beam-spike is a loopback-only, injected-authority development fixture.
// It is not a deployable Beam control plane or an authentication endpoint.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport"
	"github.com/tunnexio/tunnex/packages/apptransport/beam"
)

func randomHex(n int) string {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	return hex.EncodeToString(raw)
}

func identity(ca *x509.Certificate, caKey *ecdsa.PrivateKey, serial int64, client bool) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Beam local fixture"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	if client {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), nil
}

func newFixtureViewer(certificate tls.Certificate, reviewToken string, next http.Handler) *httptest.Server {
	viewer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_beam/fixture-signin" {
			http.SetCookie(w, &http.Cookie{Name: "beam_fixture_review", Value: reviewToken, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		cookie, err := r.Cookie("beam_fixture_review")
		if err != nil || cookie.Value != reviewToken {
			http.Error(w, "Fixture reviewer denied", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}))
	viewer.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
	viewer.StartTLS()
	return viewer
}

func run() error {
	dir := flag.String("fixture-dir", "", "private directory for ephemeral fixture keys and metadata")
	ttl := flag.Duration("ttl", 10*time.Minute, "fixture authority lifetime")
	flag.Parse()
	if *dir == "" || *ttl <= 0 || *ttl > time.Hour {
		return errors.New("fixture directory and TTL required")
	}
	if err := os.MkdirAll(*dir, 0700); err != nil {
		return err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	serverCert, serverKey, err := identity(ca, caKey, 2, false)
	if err != nil {
		return err
	}
	clientCert, clientKey, err := identity(ca, caKey, 11, true)
	if err != nil {
		return err
	}
	foreignCert, foreignKey, err := identity(ca, caKey, 12, true)
	if err != nil {
		return err
	}
	for name, content := range map[string][]byte{"ca.pem": caPEM, "connector.pem": clientCert, "connector-key.pem": clientKey, "foreign.pem": foreignCert, "foreign-key.pem": foreignKey} {
		if err := os.WriteFile(filepath.Join(*dir, name), content, 0600); err != nil {
			return err
		}
	}
	certificate, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		return err
	}
	trust := x509.NewCertPool()
	trust.AppendCertsFromPEM(caPEM)
	digest := sha256.Sum256([]byte("Beam local fixture target revision 1"))
	binding := apptransport.Binding{OrgID: "10000000-0000-4000-8000-000000000001", GatewayID: "20000000-0000-4000-8000-000000000002", AppID: "30000000-0000-4000-8000-000000000003", Generation: "40000000-0000-4000-8000-000000000004", Revision: 1, Digest: hex.EncodeToString(digest[:]), Purpose: beam.Purpose, Hostname: "p-" + randomHex(16) + ".beam.example", AuthorityVersion: 1}
	expires := time.Now().Add(*ttl)
	var revoked, unavailable atomic.Bool
	authority := func(ctx context.Context, b apptransport.Binding, serial string) (time.Time, error) {
		if ctx.Err() != nil || revoked.Load() || unavailable.Load() || !time.Now().Before(expires) || b != binding || serial != "b" {
			return time.Time{}, errors.New("fixture authority denied")
		}
		deadline := time.Now().Add(4 * time.Second)
		if expires.Before(deadline) {
			deadline = expires
		}
		return deadline, nil
	}
	broker, gateway, err := beam.NewGateway(binding, authority)
	if err != nil {
		return err
	}
	defer broker.Close()
	proxy := httptest.NewUnstartedServer(gateway)
	proxy.EnableHTTP2 = false
	proxy.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, ClientCAs: trust, ClientAuth: tls.VerifyClientCertIfGiven, MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
	proxy.StartTLS()
	defer proxy.Close()

	reviewToken, controlToken := randomHex(32), randomHex(32)
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 32 << 10, ResponseHeaderTimeout: 5 * time.Second, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return broker.Dial(ctx, binding) }}
	defer transport.CloseIdleConnections()
	logical, _ := url.Parse("http://" + binding.Hostname)
	viewerURL := ""
	forward := &httputil.ReverseProxy{Transport: transport, FlushInterval: -1, Rewrite: func(p *httputil.ProxyRequest) {
		p.SetURL(logical)
		p.Out.Host = binding.Hostname
		apptransport.StripCredentials(p.Out.Header)
		// Local fixture origin only; production cross-origin behavior is not
		// qualified by this rewrite.
		if p.In.Header.Get("Origin") == viewerURL {
			p.Out.Header.Set("Origin", "https://"+binding.Hostname)
		}
		p.Out.Header.Del("Cookie")
		for _, cookie := range p.In.Cookies() {
			// Preserve application cookies, but neither fixture login nor reserved
			// Tunnex credentials may reach the local application.
			if cookie.Name != "beam_fixture_review" {
				p.Out.AddCookie(cookie)
			}
		}
		apptransport.StripCredentials(p.Out.Header)
		apptransport.BindingHeaders(p.Out.Header, binding)
		p.Out.Header.Set("X-App-Stream-ID", randomHex(16))
	}, ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "Beam fixture unavailable", http.StatusServiceUnavailable)
	}}
	viewer := newFixtureViewer(certificate, reviewToken, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := authority(r.Context(), binding, "b"); err != nil {
			http.Error(w, "Fixture authority withdrawn", http.StatusForbidden)
			return
		}
		if _, err := apptransport.RelativeTarget(r.URL); err != nil || r.Method == "CONNECT" || r.Method == "TRACE" {
			http.Error(w, "Fixture request refused", http.StatusForbidden)
			return
		}
		forward.ServeHTTP(w, r)
	}))
	defer viewer.Close()
	viewerURL = viewer.URL
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/status" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"capacity": broker.Capacity(), "revoked": revoked.Load(), "authorityUnavailable": unavailable.Load(), "expiresAt": expires.UTC(), "viewerUrl": viewerURL, "hostname": binding.Hostname})
			return
		}
		if r.URL.Path == "/" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprintf(w, `<!doctype html><html><meta name="viewport" content="width=device-width"><title>Tunnex Beam local development</title><style>body{font:16px system-ui;background:#101820;color:#e8eef4;margin:0;padding:32px}main{max-width:680px;margin:auto}h1{font-size:34px}a{color:#9cf}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#182630;padding:18px;border-radius:12px}.tag{color:#8bd9b7}button{background:#92dfbd;color:#12251c;border:0;border-radius:8px;padding:12px;cursor:pointer}</style><main><p class="tag">Local development · BM-0 transport spike</p><h1>Tunnex Beam</h1><p>A real outbound desktop connector serving one fixed loopback app. VPN and privileged helper are unused.</p><p>This fixture uses synthetic authority. Production account login, audience policy and secure public domains are later stories.</p><p><a href="%s/_beam/fixture-signin" target="_blank" rel="noopener">Open the local review app</a></p><pre id="state">Checking connector…</pre><button id="stop">Withdraw fixture authority</button></main><script>async function refresh(){const r=await fetch('/status');document.getElementById('state').textContent=JSON.stringify(await r.json(),null,2)}refresh();setInterval(refresh,1000);document.getElementById('stop').onclick=async()=>{await fetch('/revoke',{method:'POST',headers:{'X-Beam-Fixture-Control':%q}});refresh()}</script></html>`, viewerURL, controlToken)
			return
		}
		if r.Method != http.MethodPost || r.Header.Get("X-Beam-Fixture-Control") != controlToken {
			http.Error(w, "Fixture control denied", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/revoke":
			revoked.Store(true)
		case "/authority-down":
			unavailable.Store(true)
		default:
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer control.Close()
	metadata := map[string]any{"proxyUrl": proxy.URL, "viewerUrl": viewerURL, "controlUrl": control.URL, "reviewToken": reviewToken, "controlToken": controlToken, "expiresAt": expires.UTC(), "binding": map[string]any{"orgId": binding.OrgID, "connectorId": binding.GatewayID, "shareId": binding.AppID, "generation": binding.Generation, "revision": binding.Revision, "targetDigest": binding.Digest, "hostname": binding.Hostname, "authorityVersion": binding.AuthorityVersion}}
	raw, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*dir, "metadata.json"), raw, 0600); err != nil {
		return err
	}
	_, _ = fmt.Printf("Beam fixture ready; local dashboard: %s; metadata: %s\n", control.URL, filepath.Join(*dir, "metadata.json"))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	return nil
}

func main() {
	if err := run(); err != nil {
		// Report safe failures, never PEMs, fixture tokens or request content.
		fmt.Fprintln(os.Stderr, strings.TrimSpace(err.Error()))
		os.Exit(1)
	}
}
