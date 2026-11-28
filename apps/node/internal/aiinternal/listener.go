package aiinternal

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// sourceFilter closes, before any byte is read or written, every accepted connection whose TCP peer
// (after Unmap) is not inside the source ranges. There is no TLS handshake to probe and no response.
// A refused connection never ends Accept, so it cannot stop the server.
type sourceFilter struct {
	net.Listener
	allowed func(netip.Addr) bool
}

func (l sourceFilter) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if peer, ok := tcpPeer(conn); ok && l.allowed(peer) {
			return conn, nil
		}
		_ = conn.Close()
	}
}

func tcpPeer(conn net.Conn) (netip.Addr, bool) {
	if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return tcp.AddrPort().Addr().Unmap(), true
	}
	ap, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}

// Server timeouts, the same as the AI VPN listener's. net/http bounds the TLS handshake by the smallest
// of these (5 s). Reading and writing may last as long as one relayed request (streams run for the
// control plane's stream timeout); the handler bounds the body read separately.
const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = requestDeadline
	writeTimeout      = requestDeadline + time.Minute
	idleTimeout       = 30 * time.Second
	maxHeaderBytes    = 16 << 10
)

// newServer builds the HTTPS server for one listen address. HTTP/2 is disabled (TLSNextProto is a
// non-nil empty map) and server errors (refused handshakes) are not logged.
func newServer(ctx context.Context, handler http.Handler, config *tls.Config) *http.Server {
	return &http.Server{
		Handler:           handler,
		TLSConfig:         config,
		ReadHeaderTimeout: readHeaderTimeout, ReadTimeout: readTimeout, WriteTimeout: writeTimeout,
		IdleTimeout: idleTimeout, MaxHeaderBytes: maxHeaderBytes,
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ErrorLog:     log.New(io.Discard, "", 0),
		BaseContext:  func(net.Listener) context.Context { return ctx },
	}
}

// serve runs srv on raw behind the source filter, with TLS.
func serve(srv *http.Server, raw net.Listener, allowed func(netip.Addr) bool) error {
	return srv.ServeTLS(sourceFilter{Listener: raw, allowed: allowed}, "", "")
}
