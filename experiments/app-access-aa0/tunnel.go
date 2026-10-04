// Package spike qualifies a nonshipping outbound connector topology.
package spike

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"
)

// Binding is server-owned; browser headers never determine it.
type Binding struct{ Org, Gateway, App, Revision string }
type Broker struct {
	Binding    Binding
	Identities map[string]Binding
	ready      chan net.Conn
	slots      chan struct{}
	mu         sync.Mutex
	conns      map[net.Conn]struct{}
}

func NewBroker(b Binding, capacity int) *Broker {
	return &Broker{Binding: b, ready: make(chan net.Conn, capacity), slots: make(chan struct{}, capacity), conns: map[net.Conn]struct{}{}}
}
func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "CONNECT" || r.URL.Path != "/channel" {
		http.Error(w, "denied", 403)
		return
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		http.Error(w, "denied", 403)
		return
	}
	cert := r.TLS.VerifiedChains[0][0]
	identity, known := b.Identities[cert.SerialNumber.String()]
	if !known || identity.Gateway != b.Binding.Gateway || identity.Org != b.Binding.Org || r.Header.Get("X-App") != b.Binding.App || r.Header.Get("X-Revision") != b.Binding.Revision {
		http.Error(w, "denied", 403)
		return
	}
	select {
	case b.slots <- struct{}{}:
	default:
		http.Error(w, "capacity", 503)
		return
	}
	c, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		<-b.slots
		return
	}
	if rw.Reader.Buffered() != 0 {
		c.Close()
		<-b.slots
		return
	}
	rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if rw.Flush() != nil {
		c.Close()
		<-b.slots
		return
	}
	var tracked *trackedConn
	tracked = &trackedConn{Conn: c, closed: make(chan struct{}), done: func() { <-b.slots; b.mu.Lock(); delete(b.conns, tracked); b.mu.Unlock() }}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	b.mu.Lock()
	b.conns[tracked] = struct{}{}
	b.mu.Unlock()
	select {
	case b.ready <- tracked:
		go func() {
			timer := time.NewTimer(15 * time.Second)
			defer timer.Stop()
			select {
			case <-timer.C:
				tracked.Close()
			case <-tracked.closed:
			}
		}()
	default:
		tracked.Close()
	}
}

type trackedConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
	done   func()
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed); c.done() })
	return err
}
func (b *Broker) Close() {
	b.mu.Lock()
	cs := make([]net.Conn, 0, len(b.conns))
	for c := range b.conns {
		cs = append(cs, c)
	}
	b.mu.Unlock()
	for _, c := range cs {
		c.Close()
	}
}
func (b *Broker) Dial(ctx context.Context, _, _ string) (net.Conn, error) {
	for {
		select {
		case c := <-b.ready:
			if tc, ok := c.(*trackedConn); ok {
				select {
				case <-tc.closed:
					continue
				default:
				}
			}
			c.SetDeadline(time.Now().Add(3 * time.Second))
			return c, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Proxy deliberately excludes browser CONNECT and uses only the registered origin.
func (b *Broker) Proxy(origin *url.URL) http.Handler {
	logical := *origin
	logical.Scheme = "http"
	p := httputil.NewSingleHostReverseProxy(&logical)
	p.Transport = &http.Transport{DialContext: b.Dial, DisableKeepAlives: true, ResponseHeaderTimeout: 2 * time.Second, MaxResponseHeaderBytes: 32 << 10}
	p.FlushInterval = -1
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "CONNECT" {
			http.Error(w, "denied", 405)
			return
		}
		p.ServeHTTP(w, r)
	})
}

// Connect authenticates the proxy, advertises a binding and serves exactly one
// HTTP connection on the outbound tunnel. Rotation/reconnect needs a new call.
func Connect(ctx context.Context, address string, config *tls.Config, b Binding, origin *url.URL) error {
	return connectWithTrust(ctx, address, config, b, origin, nil)
}
func connectWithTrust(ctx context.Context, address string, config *tls.Config, b Binding, origin *url.URL, roots *x509.CertPool) error {
	d := tls.Dialer{Config: config}
	c, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(c, "CONNECT /channel HTTP/1.1\r\nHost: %s\r\nX-App: %s\r\nX-Revision: %s\r\n\r\n", address, b.App, b.Revision)
	reader := bufio.NewReader(c)
	resp, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("channel denied: %d", resp.StatusCode)
	}
	c.SetDeadline(time.Time{})
	wrapped := &bufferConn{Conn: c, r: reader}
	listener := &singleListener{conn: wrapped, closed: make(chan struct{})}
	wrapped.done = func() { listener.Close() }
	p := httputil.NewSingleHostReverseProxy(origin)
	p.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, ResponseHeaderTimeout: 2 * time.Second, MaxResponseHeaderBytes: 32 << 10}
	p.FlushInterval = -1
	server := &http.Server{Handler: p, ReadHeaderTimeout: 2 * time.Second, MaxHeaderBytes: 32 << 10, ConnState: func(_ net.Conn, s http.ConnState) {
		if s == http.StateClosed {
			listener.Close()
		}
	}}
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
			listener.Close()
		case <-listener.closed:
		}
	}()
	err = server.Serve(listener)
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

type bufferConn struct {
	net.Conn
	r    io.Reader
	done func()
}

func (c *bufferConn) Close() error {
	err := c.Conn.Close()
	if c.done != nil {
		c.done()
	}
	return err
}
func (c *bufferConn) Read(p []byte) (int, error) { return c.r.Read(p) }

type singleListener struct {
	conn   net.Conn
	mu     sync.Mutex
	closed chan struct{}
	once   sync.Once
}

func (l *singleListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	c := l.conn
	l.conn = nil
	l.mu.Unlock()
	if c != nil {
		return c, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}
func (l *singleListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *singleListener) Addr() net.Addr { return &net.TCPAddr{} }
