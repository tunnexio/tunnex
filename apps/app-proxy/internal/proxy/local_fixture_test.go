package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/tunnexio/tunnex/packages/apptransport/restorebarrier"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestOwnedLocalProxyFixture is opt-in nonshipping qualification only. Its
// network and trust seams are hard-coded to the parent's owned local topology.
// The normal command exposes no private-origin/public-TLS bypass configuration.
func TestOwnedLocalProxyFixture(t *testing.T) {
	if os.Getenv("APP_ACCESS_PROXY_FIXTURE") != "1" {
		t.Skip("owned local fixture only")
	}
	if os.Getenv("APP_ACCESS_OWNED_PROJECT") != "tunnex-app-access-aa0-1003" || os.Getenv("APP_ACCESS_OWNED_CHECKOUT") != "/Users/pawangupta/tunnex/tests/app-access-local" {
		t.Fatal("owned fixture project/checkout mismatch")
	}
	if os.Getenv("TUNNEX_APP_ACCESS_RESTORE_MARKER") != "/owned-app-restore/app-access.pending.json" {
		t.Fatal("owned restore barrier configuration mismatch")
	}
	if err := restorebarrier.Check(os.Getenv("TUNNEX_APP_ACCESS_RESTORE_MARKER")); err != nil {
		t.Fatal(err)
	}
	const directory = "/owned-aa6-proxy"
	const base = "apps.127.0.0.1.nip.io"
	const appHost = "payroll.apps.127.0.0.1.nip.io"
	ca, err := os.ReadFile(filepath.Join(directory, "ca-cert.pem"))
	if err != nil {
		t.Fatal("owned CA missing")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("owned CA invalid")
	}
	path := filepath.Join(directory, "proxy-credential")
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		t.Fatal("owned credential file missing/private permission invalid")
	}
	token, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("owned credential unreadable")
	}
	authority, err := NewClient("https://tunnex-app-authority:18448", strings.TrimSpace(string(token)), &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "tunnex-app-authority"})
	if err != nil {
		t.Fatal("owned authority client invalid")
	}
	console, err := ownedFixtureConsole(os.Getenv("APP_ACCESS_PROXY_FIXTURE_CONSOLE"), base)
	if err != nil {
		t.Fatal("owned console domain isolation invalid")
	}
	broker, gatewayHandler := NewGateway(base, authority)
	defer broker.Close()
	publicHandler := NewHandler(base, authority, broker)
	publicHandler.Console = console
	readiness, err := NewReadinessWorker(base, authority, broker)
	if err != nil {
		t.Fatal(err)
	}
	publicHandler.Readiness = readiness
	readiness.PublicProbe = func(parent context.Context, host, id, challenge, hash string) (string, string, string) {
		if host != appHost {
			return "failed", "pending", "public_dns_failed"
		}
		ctx, cancel := context.WithTimeout(parent, 5*time.Second)
		defer cancel()
		return probePublicAddresses(ctx, host, id, challenge, hash, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: host}, (&net.Dialer{Timeout: 5 * time.Second}).DialContext)
	}
	publicCert, err := tls.LoadX509KeyPair(filepath.Join(directory, "app-cert.pem"), filepath.Join(directory, "app-key.pem"))
	if err != nil {
		t.Fatal("owned public leaf invalid")
	}
	gatewayCert, err := tls.LoadX509KeyPair(filepath.Join(directory, "gateway-proxy-cert.pem"), filepath.Join(directory, "gateway-proxy-key.pem"))
	if err != nil {
		t.Fatal("owned gateway leaf invalid")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	failures := make(chan error, 2)
	var servers []*http.Server
	for _, entry := range []struct {
		address string
		handler http.Handler
		config  *tls.Config
		header  time.Duration
	}{
		{":443", publicHandler, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{publicCert}, NextProtos: []string{"http/1.1"}}, 10 * time.Second},
		{":18449", gatewayHandler, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{gatewayCert}, NextProtos: []string{"http/1.1"}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}, 5 * time.Second},
	} {
		listener, err := net.Listen("tcp", entry.address)
		if err != nil {
			t.Fatal("owned proxy bind failed")
		}
		server := &http.Server{Handler: entry.handler, ReadHeaderTimeout: entry.header, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 32 << 10, ConnContext: ConnectionContext}
		servers = append(servers, server)
		go func() { failures <- server.Serve(tls.NewListener(listener, entry.config)) }()
	}
	defer func() {
		for _, server := range servers {
			_ = server.Close()
		}
	}()
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); readiness.Run(ctx) }()
	defer func() { cancel(); <-workerDone }()
	t.Log("owned proxy fixture ready public443 gateway18449; strict production handlers with explicit local public-probe trust/network seam")
	select {
	case <-ctx.Done():
	case err := <-failures:
		t.Fatal("owned listener stopped", err)
	}
}

func ownedFixtureConsole(override, base string) (*url.URL, error) {
	if override == "" {
		return ConsoleURL("https://console.127.0.0.1.sslip.io:15180", base)
	}
	if override != "https://sso-console.127.0.0.1.sslip.io:15190" {
		return nil, ErrDenied
	}
	return ConsoleURL(override, base)
}

func TestOwnedFixtureConsoleOverrideIsExactAndNonshipping(t *testing.T) {
	base := "apps.127.0.0.1.nip.io"
	for _, value := range []string{"", "https://sso-console.127.0.0.1.sslip.io:15190"} {
		if _, err := ownedFixtureConsole(value, base); err != nil {
			t.Fatal("owned console refused")
		}
	}
	for _, value := range []string{"https://other.example.com", "http://sso-console.127.0.0.1.sslip.io:15190", "https://sso-console.127.0.0.1.sslip.io:15190/path", "https://sso-console.127.0.0.1.sslip.io:15190/", "https://sso-console.127.0.0.1.sslip.io:15191"} {
		if _, err := ownedFixtureConsole(value, base); err == nil {
			t.Fatal("arbitrary fixture console accepted")
		}
	}
}
