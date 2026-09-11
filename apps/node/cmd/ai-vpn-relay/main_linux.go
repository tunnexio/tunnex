//go:build linux

// ai-vpn-relay terminates HTTPS ONLY on the configured WireGuard interface.
// It shares the node agent's network namespace and read-only certificate state.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/aivpn"
	"golang.org/x/sys/unix"
)

func main() {
	iface := flag.String("interface", "wg0", "verified VPN ingress interface")
	addr := flag.String("listen", "", "VPN IPv4 address:443 (required)")
	host := flag.String("hostname", "", "existing control-plane DNS hostname")
	control := flag.String("control", "", "mTLS control URL, e.g. https://api:8443")
	controlName := flag.String("control-server-name", "", "control-channel TLS server name")
	state := flag.String("node-state", "/var/lib/tunnex-node", "node mTLS credential directory")
	cert := flag.String("tls-cert", "", "HTTPS certificate path")
	key := flag.String("tls-key", "", "HTTPS private key path")
	webURL := flag.String("web-upstream", "", "HTTPS web upstream using normal DNS (not VPN DNS)")
	flag.Parse()
	bindIP, _, err := net.SplitHostPort(*addr)
	if err != nil || net.ParseIP(bindIP) == nil || net.ParseIP(bindIP).IsUnspecified() || *host == "" || *controlName == "" {
		log.Fatal("explicit VPN listen address, hostname and control server name required")
	}
	cp, err := url.Parse(*control)
	if err != nil || cp.Scheme != "https" || cp.Host == "" || cp.User != nil || cp.Path != "" || cp.RawQuery != "" {
		log.Fatal("invalid mTLS control URL")
	}
	upstream, err := url.Parse(*webURL)
	if err != nil || upstream.Scheme != "https" || upstream.Host == "" || upstream.User != nil {
		log.Fatal("HTTPS web upstream required")
	}
	ca, err := os.ReadFile(filepath.Join(*state, "ca.pem"))
	if err != nil {
		log.Fatal("read node CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		log.Fatal("invalid node CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: *controlName,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			c, err := tls.LoadX509KeyPair(filepath.Join(*state, "cert.pem"), filepath.Join(*state, "key.pem"))
			return &c, err
		}}, ResponseHeaderTimeout: 30 * time.Second, MaxConnsPerHost: 16, MaxIdleConnsPerHost: 4}
	// Disable connection reuse so each request authenticates with current node cert.
	transport.DisableKeepAlives = true
	web := httputil.NewSingleHostReverseProxy(upstream)
	web.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: *host}, ResponseHeaderTimeout: 30 * time.Second, MaxConnsPerHost: 16}
	web.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) { http.Error(w, "web unavailable", 502) }
	peers := func(ctx context.Context) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "wg", "show", *iface, "allowed-ips").Output()
		return string(out), err
	}
	handler := aivpn.Handler(*host, cp, transport, peers, web)
	// SO_BINDTODEVICE limits accepted traffic by ingress interface, not by a
	// forgeable HTTP header or source-address range. Failure is fatal.
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, *iface)
		})
		if err != nil {
			return err
		}
		return sockErr
	}}
	listener, err := lc.Listen(context.Background(), "tcp4", *addr)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 35 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName != *host {
				return nil, fmt.Errorf("unexpected SNI")
			}
			c, err := tls.LoadX509KeyPair(*cert, *key)
			return &c, err
		}}}
	log.Printf("VPN AI relay listening on %s via %s", *addr, *iface)
	log.Fatal(srv.ServeTLS(listener, "", ""))
}
