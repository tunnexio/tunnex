// Package sniedge lets one public TLS listener serve several components
// without decrypting traffic that is not its own (LS-UX-1 E.1). It reads only
// the ClientHello's SNI (bounded in size and time). Streams for the owner are
// handed to the owner's TLS server unchanged; every other stream is spliced
// as raw TCP to a fixed operator-configured target, prefixed with a PROXY v2
// header carrying the real client address.
package sniedge

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport/proxyproto"
)

// MaxHello bounds the bytes read before a routing decision.
const MaxHello = 16 << 10

// Route sends streams whose SNI matches to Target.
type Route struct {
	Match  func(sni string) bool
	Target string
}

// Config describes the edge. Own decides which SNI the wrapped server
// terminates; Routes are tried in order; Default receives everything else
// (including clients that send no SNI).
type Config struct {
	Own        func(sni string) bool
	Routes     []Route
	Default    string
	Token      []byte
	Timeout    time.Duration
	MaxSplices int
	Dial       func(ctx context.Context, network, address string) (net.Conn, error)
}

// Subdomain matches exactly one DNS label under base (case-insensitive).
func Subdomain(base string) func(string) bool {
	base = strings.ToLower(strings.TrimSuffix(base, "."))
	return func(sni string) bool {
		sni = strings.ToLower(sni)
		label, ok := strings.CutSuffix(sni, "."+base)
		return ok && label != "" && !strings.Contains(label, ".")
	}
}

// Under matches base itself and any name below it.
func Under(base string) func(string) bool {
	base = strings.ToLower(strings.TrimSuffix(base, "."))
	return func(sni string) bool {
		sni = strings.ToLower(sni)
		return sni == base || strings.HasSuffix(sni, "."+base)
	}
}

// Listener yields only the owner's streams.
type Listener struct {
	net.Listener
	cfg    Config
	ready  chan net.Conn
	errs   chan error
	peeks  chan struct{}
	splice chan struct{}
	done   chan struct{}
	once   sync.Once
}

func New(l net.Listener, cfg Config) (*Listener, error) {
	if cfg.Own == nil || cfg.Default == "" || len(cfg.Token) < 16 {
		return nil, errors.New("edge requires an owner, a default target and an edge token")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.MaxSplices <= 0 {
		cfg.MaxSplices = 1024
	}
	if cfg.Dial == nil {
		cfg.Dial = (&net.Dialer{Timeout: 3 * time.Second}).DialContext
	}
	x := &Listener{Listener: l, cfg: cfg, ready: make(chan net.Conn), errs: make(chan error, 1), peeks: make(chan struct{}, 128), splice: make(chan struct{}, cfg.MaxSplices), done: make(chan struct{})}
	go x.loop()
	return x, nil
}

func (l *Listener) loop() {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			select {
			case l.errs <- err:
			case <-l.done:
			}
			return
		}
		select {
		case l.peeks <- struct{}{}:
		case <-l.done:
			c.Close()
			return
		}
		go l.route(c)
	}
}

// recorder feeds crypto/tls the client's bytes, keeps a copy and swallows
// anything the aborted handshake tries to write back.
type recorder struct {
	net.Conn
	buf bytes.Buffer
}

func (r *recorder) Read(p []byte) (int, error) {
	if r.buf.Len() >= MaxHello {
		return 0, errors.New("client hello too large")
	}
	if room := MaxHello - r.buf.Len(); len(p) > room {
		p = p[:room]
	}
	n, err := r.Conn.Read(p)
	r.buf.Write(p[:n])
	return n, err
}
func (*recorder) Write(p []byte) (int, error) { return len(p), nil }

var errPeeked = errors.New("peeked")

// ServerName returns the SNI of the ClientHello read from c and every byte read.
func ServerName(c net.Conn, timeout time.Duration) (string, []byte, error) {
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	defer c.SetReadDeadline(time.Time{})
	rec := &recorder{Conn: c}
	var sni string
	seen := false
	err := tls.Server(rec, &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		sni, seen = h.ServerName, true
		return nil, errPeeked
	}}).Handshake()
	if !seen {
		if err == nil {
			err = errors.New("no client hello")
		}
		return "", rec.buf.Bytes(), err
	}
	return sni, rec.buf.Bytes(), nil
}

type replay struct {
	net.Conn
	r io.Reader
}

func (c *replay) Read(p []byte) (int, error) { return c.r.Read(p) }

func (l *Listener) route(c net.Conn) {
	sni, hello, err := ServerName(c, l.cfg.Timeout)
	<-l.peeks
	if err != nil {
		c.Close()
		return
	}
	if sni != "" && l.cfg.Own(sni) {
		select {
		case l.ready <- &replay{Conn: c, r: io.MultiReader(bytes.NewReader(hello), c)}:
		case <-l.done:
			c.Close()
		}
		return
	}
	target := l.cfg.Default
	for _, r := range l.cfg.Routes {
		if sni != "" && r.Match(sni) {
			target = r.Target
			break
		}
	}
	select {
	case l.splice <- struct{}{}:
	default:
		c.Close()
		return
	}
	defer func() { <-l.splice }()
	l.forward(c, target, hello)
}

func (l *Listener) forward(c net.Conn, target string, hello []byte) {
	defer c.Close()
	src, ok1 := c.RemoteAddr().(*net.TCPAddr)
	dst, ok2 := c.LocalAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	up, err := l.cfg.Dial(ctx, "tcp", target)
	cancel()
	if err != nil {
		return
	}
	defer up.Close()
	header, err := proxyproto.Header(src, dst, l.cfg.Token)
	if err != nil {
		return
	}
	if _, err = up.Write(append(header, hello...)); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	go pipe(up, c)
	go pipe(c, up)
	select {
	case <-done:
		<-done
	case <-l.done:
	}
}

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ready:
		return c, nil
	case err := <-l.errs:
		return nil, err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *Listener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}
