// Nonshipping TLS console adapter for the exact owned browser qualification.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	if os.Getenv("APP_ACCESS_SSO_CONSOLE_FIXTURE") != "1" || os.Getenv("APP_ACCESS_OWNED_PROJECT") != "tunnex-app-access-aa0-1003" || os.Getenv("APP_ACCESS_OWNED_CHECKOUT") != "/Users/pawangupta/tunnex/tests/app-access-local" {
		log.Fatal("owned qualification context required")
	}
	const hostname = "sso-console.127.0.0.1.sslip.io:15190"
	certificate, err := tls.LoadX509KeyPair("/fixture/console-cert.pem", "/fixture/console-key.pem")
	if err != nil {
		log.Fatal("owned console certificate unavailable")
	}
	target, _ := url.Parse("http://aa8-sso-cp-fixture:15189")
	upstream := httputil.NewSingleHostReverseProxy(target)
	original := upstream.Director
	upstream.Director = func(r *http.Request) {
		original(r)
		r.Host = hostname
		// This adapter is the authenticated immediate proxy peer in the owned fixture.
		r.Header.Del("Forwarded")
		r.Header.Del("X-Forwarded-Host")
		r.Header.Del("X-Forwarded-For")
		r.Header.Set("X-Forwarded-Proto", "https")
	}
	upstream.Transport = &http.Transport{Proxy: nil, MaxIdleConns: 32, MaxIdleConnsPerHost: 16, ResponseHeaderTimeout: 10 * time.Second, IdleConnTimeout: 30 * time.Second}
	upstream.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "Owned API unavailable", http.StatusBadGateway)
	}
	files := http.FileServer(http.Dir("/web"))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != hostname {
			http.Error(w, "Unknown console host", http.StatusMisdirectedRequest)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			upstream.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Method unavailable", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/healthz" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"ready","provenance":"owned TLS console fixture"}`))
			return
		}
		path := filepath.Join("/web", filepath.Clean("/"+r.URL.Path))
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			http.ServeFile(w, r, "/web/index.html")
			return
		}
		files.ServeHTTP(w, r)
	})
	server := &http.Server{Addr: ":15190", Handler: handler, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}}, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		bounded, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(bounded)
	}()
	log.Print("owned console TLS adapter ready on 15190")
	if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal("owned console listener stopped")
	}
}
