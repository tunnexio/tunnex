// beam-proxy is the opt-in Beam browser and desktop channel serving process.
// It reuses the bounded App Access HTTP engine with a separate authority audience.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tunnexio/tunnex/apps/app-proxy/internal/proxy"
	"github.com/tunnexio/tunnex/packages/apptransport/restorebarrier"
)

func required(suffix string) string {
	value := os.Getenv("TUNNEX_BEAM_PROXY_" + suffix)
	if value == "" {
		log.Fatal("missing Beam configuration: " + suffix)
	}
	return value
}
func roots(path string) *x509.CertPool {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatal("cannot read Beam trust roots")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		log.Fatal("invalid Beam trust roots")
	}
	return pool
}
func main() {
	if os.Getenv("TUNNEX_BEAM_PROXY_PUBLIC_ADDR") == "" && os.Getenv("TUNNEX_BEAM_PROXY_CONNECTOR_ADDR") == "" {
		log.Print("Beam proxy disabled")
		return
	}
	marker := required("RESTORE_MARKER")
	if !filepath.IsAbs(marker) || restorebarrier.Check(marker) != nil {
		log.Fatal("Beam restore barrier unverified or active")
	}
	cert, err := tls.LoadX509KeyPair(required("TLS_CERT_FILE"), required("TLS_KEY_FILE"))
	if err != nil {
		log.Fatal("invalid Beam serving certificate")
	}
	connectorCert, err := tls.LoadX509KeyPair(required("CONNECTOR_TLS_CERT_FILE"), required("CONNECTOR_TLS_KEY_FILE"))
	if err != nil {
		log.Fatal("invalid Beam connector serving certificate")
	}
	credentialPath := required("CREDENTIAL_FILE")
	info, err := os.Stat(credentialPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		log.Fatal("Beam authority credential must be a private regular file")
	}
	credential, err := os.ReadFile(credentialPath)
	if err != nil {
		log.Fatal("cannot read Beam authority credential")
	}
	authority, err := proxy.NewBeamClient(required("AUTHORITY_URL"), strings.TrimSpace(string(credential)), &tls.Config{ServerName: required("AUTHORITY_SERVER_NAME"), RootCAs: roots(required("AUTHORITY_CA_FILE"))})
	if err != nil {
		log.Fatal("invalid Beam authority configuration")
	}
	base := required("BASE_DOMAIN")
	console, err := proxy.ConsoleURL(required("CONSOLE_BASE_URL"), base)
	if err != nil {
		log.Fatal("invalid Beam console domain isolation")
	}
	broker, channel, err := proxy.NewBeamGateway(authority)
	if err != nil {
		log.Fatal("cannot initialize Beam broker")
	}
	defer broker.Close()
	browser := proxy.NewBeamHandler(base, authority, broker)
	browser.Console = console
	var certDeadline time.Time
	for _, servingCert := range []tls.Certificate{cert, connectorCert} {
		leaf, parseErr := x509.ParseCertificate(servingCert.Certificate[0])
		if parseErr != nil {
			log.Fatal("invalid Beam serving certificate")
		}
		if certDeadline.IsZero() || leaf.NotAfter.Before(certDeadline) {
			certDeadline = leaf.NotAfter
		}
	}
	operational := &proxy.Operational{Handler: browser, CertificateExpiresAt: certDeadline, AuthorityReady: func() bool {
		ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		_, err := authority.Domains(ctx)
		return err == nil && ctx.Err() == nil
	}}
	signalCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	servingCtx, cancel := context.WithCancel(signalCtx)
	defer cancel()
	failures := make(chan error, 3)
	var servers []*http.Server
	for _, entry := range []struct {
		address   string
		handler   http.Handler
		connector bool
		capacity  int
	}{
		{required("PUBLIC_ADDR"), browser, false, 256},
		{required("CONNECTOR_ADDR"), channel, true, 128},
	} {
		config := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}}
		if entry.connector {
			config.Certificates = []tls.Certificate{connectorCert}
			config.ClientAuth = tls.RequireAndVerifyClientCert
			config.ClientCAs = roots(required("CONNECTOR_CA_FILE"))
		}
		listener, err := net.Listen("tcp", entry.address)
		if err != nil {
			log.Fatal("cannot bind Beam listener")
		}
		bounded := &limitListener{Listener: listener, slots: make(chan struct{}, entry.capacity), done: make(chan struct{})}
		server := &http.Server{Handler: entry.handler, TLSConfig: config, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 32 << 10, BaseContext: func(net.Listener) context.Context { return servingCtx }, ConnContext: proxy.ConnectionContext}
		servers = append(servers, server)
		go func() { failures <- server.Serve(tls.NewListener(bounded, config)) }()
	}
	if address := os.Getenv("TUNNEX_BEAM_PROXY_ADMIN_ADDR"); address != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
		mux.Handle("GET /readyz", operational)
		mux.Handle("GET /livez", operational)
		mux.Handle("GET /metrics", operational)
		listener, err := net.Listen("tcp", address)
		if err != nil {
			log.Fatal("cannot bind Beam operator listener")
		}
		server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8 << 10}
		servers = append(servers, server)
		go func() {
			failures <- server.Serve(&limitListener{Listener: listener, slots: make(chan struct{}, 32), done: make(chan struct{})})
		}()
	}
	log.Print("Beam proxy listeners started")
	select {
	case <-signalCtx.Done():
	case err = <-failures:
	}
	operational.Draining.Store(true)
	cancel()
	_ = broker.Close()
	ctx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	for _, server := range servers {
		if server.Shutdown(ctx) != nil {
			_ = server.Close()
		}
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal("Beam listener failed")
	}
}

type limitListener struct {
	net.Listener
	slots chan struct{}
	done  chan struct{}
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitConn{Conn: conn, release: func() { <-l.slots }}, nil
}
func (l *limitListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return l.Listener.Close()
}

type limitConn struct {
	net.Conn
	release func()
	once    sync.Once
}

// Conn can be closed by the stream deadline and server concurrently.
func (c *limitConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
