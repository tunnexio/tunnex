// consoleprobe runs app-proxy's real public path for the console: the
// optional edge-token PROXY v2 listener and the console router forwarding to
// the fixed upstream. Built only by tests/console-client-ip/walk.sh.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/tunnexio/tunnex/apps/app-proxy/internal/proxy"
	"github.com/tunnexio/tunnex/packages/apptransport/proxyproto"
)

func main() {
	console, _ := url.Parse(os.Getenv("CONSOLE"))
	ca, err := os.ReadFile(os.Getenv("UPSTREAM_CA"))
	if err != nil {
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	h := proxy.NewHandler("apps.test", nil, nil)
	h.Console = console
	router, err := proxy.NewConsoleRouter(h, os.Getenv("UPSTREAM"), &tls.Config{ServerName: console.Hostname(), RootCAs: roots})
	if err != nil {
		log.Fatal(err)
	}
	if pin := os.Getenv("PIN"); pin != "" {
		if err := router.PinDial(pin); err != nil {
			log.Fatal(err)
		}
	}
	cert, err := tls.LoadX509KeyPair(os.Getenv("CERT"), os.Getenv("KEY"))
	if err != nil {
		log.Fatal(err)
	}
	var l net.Listener
	if l, err = net.Listen("tcp", ":443"); err != nil {
		log.Fatal(err)
	}
	if path := os.Getenv("EDGE_TOKEN_FILE"); path != "" {
		token, err := proxyproto.LoadToken(path)
		if err != nil {
			log.Fatal(err)
		}
		if l, err = proxyproto.NewListener(l, token, 5*time.Second); err != nil {
			log.Fatal(err)
		}
	}
	log.Fatal((&http.Server{Handler: router}).Serve(tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{cert}})))
}
