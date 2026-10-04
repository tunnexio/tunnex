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

func required(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatal("missing required configuration: " + key)
	}
	return v
}
func roots(path string) *x509.CertPool {
	data, e := os.ReadFile(path)
	if e != nil {
		log.Fatal("cannot read trust roots")
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(data) {
		log.Fatal("invalid trust roots")
	}
	return p
}
func validateRestoreMarker(path string) error {
	if path == "" || !filepath.IsAbs(path) || strings.ContainsRune(path, 0) {
		return errors.New("App Access proxy requires an absolute external restore barrier")
	}
	return restorebarrier.Check(path)
}

func main() {
	public := os.Getenv("TUNNEX_APP_PROXY_PUBLIC_ADDR")
	gateway := os.Getenv("TUNNEX_APP_PROXY_GATEWAY_ADDR")
	if public == "" && gateway == "" {
		log.Print("App Access proxy disabled")
		return
	}
	if err := validateRestoreMarker(os.Getenv("TUNNEX_APP_ACCESS_RESTORE_MARKER")); err != nil {
		log.Fatal(err)
	}
	if public == "" || gateway == "" {
		log.Fatal("both listener addresses required")
	}
	certificate, e := tls.LoadX509KeyPair(required("TUNNEX_APP_PROXY_TLS_CERT_FILE"), required("TUNNEX_APP_PROXY_TLS_KEY_FILE"))
	if e != nil {
		log.Fatal("invalid proxy TLS certificate")
	}
	credentialPath := required("TUNNEX_APP_PROXY_CREDENTIAL_FILE")
	info, e := os.Stat(credentialPath)
	if e != nil || info.Mode().Perm()&0077 != 0 {
		log.Fatal("credential file must be private")
	}
	credential, e := os.ReadFile(credentialPath)
	if e != nil {
		log.Fatal("cannot read proxy credential")
	}
	name := os.Getenv("TUNNEX_APP_PROXY_AUTHORITY_SERVER_NAME")
	if name == "" {
		name = "tunnex-app-authority"
	}
	authority, e := proxy.NewClient(required("TUNNEX_APP_PROXY_AUTHORITY_URL"), strings.TrimSpace(string(credential)), &tls.Config{ServerName: name, RootCAs: roots(required("TUNNEX_APP_PROXY_AUTHORITY_CA_FILE"))})
	if e != nil {
		log.Fatal("invalid authority configuration")
	}
	base := required("TUNNEX_APP_PROXY_BASE_DOMAIN")
	console, e := proxy.ConsoleURL(required("TUNNEX_APP_PROXY_CONSOLE_BASE_URL"), base)
	if e != nil {
		log.Fatal("invalid console domain isolation")
	}
	broker, handler := proxy.NewGateway(base, authority)
	publicHandler := proxy.NewHandler(base, authority, broker)
	publicHandler.Console = console
	var publicBrowser http.Handler = publicHandler
	if upstream := os.Getenv("TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_URL"); upstream != "" {
		upstreamTLS := &tls.Config{ServerName: os.Getenv("TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_SERVER_NAME")}
		if ca := os.Getenv("TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_CA_FILE"); ca != "" {
			upstreamTLS.RootCAs = roots(ca)
		}
		router, err := proxy.NewConsoleRouter(publicHandler, upstream, upstreamTLS)
		if err != nil {
			log.Fatal("invalid fixed console upstream configuration")
		}
		defer router.CloseIdleConnections()
		publicBrowser = router
	}
	readiness, e := proxy.NewReadinessWorker(base, authority, broker)
	if e != nil {
		log.Fatal("cannot initialize readiness")
	}
	publicHandler.Readiness = readiness
	signalCtx, signalStop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer signalStop()
	workerCtx, workerCancel := context.WithCancel(signalCtx)
	defer workerCancel()
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); readiness.Run(workerCtx) }()
	defer broker.Close()
	publicTLS := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}}
	gatewayCert, e := tls.LoadX509KeyPair(required("TUNNEX_APP_PROXY_GATEWAY_TLS_CERT_FILE"), required("TUNNEX_APP_PROXY_GATEWAY_TLS_KEY_FILE"))
	if e != nil {
		log.Fatal("invalid gateway TLS certificate")
	}
	gatewayTLS := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{gatewayCert}, NextProtos: []string{"http/1.1"}}
	gatewayTLS.ClientAuth = tls.RequireAndVerifyClientCert
	gatewayTLS.ClientCAs = roots(required("TUNNEX_APP_PROXY_AGENT_CA_FILE"))
	failures := make(chan error, 3)
	operational := &proxy.Operational{Handler: publicHandler, Readiness: readiness}
	var servers []*http.Server
	for _, entry := range []struct {
		address       string
		config        *tls.Config
		handler       http.Handler
		limit         int
		headerTimeout time.Duration
	}{{public, publicTLS, publicBrowser, 256, 10 * time.Second}, {gateway, gatewayTLS, handler, 128, 5 * time.Second}} {
		listener, e := net.Listen("tcp", entry.address)
		if e != nil {
			log.Fatal("cannot bind proxy listener")
		}
		bounded := &limitListener{Listener: listener, slots: make(chan struct{}, entry.limit), done: make(chan struct{})}
		server := &http.Server{Handler: entry.handler, TLSConfig: entry.config, ReadHeaderTimeout: entry.headerTimeout, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 32 << 10, BaseContext: func(net.Listener) context.Context { return workerCtx }, ConnContext: proxy.ConnectionContext}
		servers = append(servers, server)
		go func() { failures <- server.Serve(tls.NewListener(bounded, server.TLSConfig)) }()
	}

	if admin := os.Getenv("TUNNEX_APP_PROXY_ADMIN_ADDR"); admin != "" {
		listener, err := net.Listen("tcp", admin)
		if err != nil {
			log.Fatal("cannot bind operator listener")
		}
		bounded := &limitListener{Listener: listener, slots: make(chan struct{}, 32), done: make(chan struct{})}
		server := &http.Server{Handler: operational, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8 << 10}
		servers = append(servers, server)
		go func() { failures <- server.Serve(bounded) }()
	}
	var stopped error
	select {
	case <-signalCtx.Done():
	case stopped = <-failures:
	}
	operational.Draining.Store(true)
	workerCancel()
	_ = broker.Close()
	shutdownServers(servers, workerDone, 5*time.Second)
	if stopped != nil && !errors.Is(stopped, http.ErrServerClosed) {
		log.Fatal("proxy listener stopped")
	}

}

// shutdownServers enforces one shared grace budget, including worker completion.
func shutdownServers(servers []*http.Server, workerDone <-chan struct{}, budget time.Duration) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	var wait sync.WaitGroup
	for _, server := range servers {
		wait.Add(1)
		go func(s *http.Server) {
			defer wait.Done()
			if s.Shutdown(shutdownCtx) != nil {
				_ = s.Close()
			}
		}(server)
	}
	wait.Wait()
	select {
	case <-workerDone:
	case <-shutdownCtx.Done():
	}
}

type limitListener struct {
	net.Listener
	slots chan struct{}
	done  chan struct{}
	once  sync.Once
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, e := l.Listener.Accept()
	if e != nil {
		<-l.slots
		return nil, e
	}
	return &limitConn{Conn: c, release: func() { <-l.slots }}, nil
}

func (l *limitListener) Close() error { l.once.Do(func() { close(l.done) }); return l.Listener.Close() }

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error { e := c.Conn.Close(); c.once.Do(c.release); return e }
