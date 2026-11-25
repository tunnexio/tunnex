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

// Route sends streams whose SNI matches to Target. Token adds the edge token
// TLV to the PROXY header; set it only for targets that verify it, so the
// secret is never handed to components that ignore it.
type Route struct {
	Match  func(sni string) bool
	Target string
	Token  bool
}

// Config describes the edge. Own decides which SNI the wrapped server
// terminates; Routes are tried in order; Default receives everything else
// (including clients that send no SNI).
type Config struct {
	Own          func(sni string) bool
	Routes       []Route
	Default      string
	DefaultToken bool
	Token        []byte
	Timeout      time.Duration
	MaxSplices   int
	// Idle closes a spliced stream with no traffic in either direction.
	Idle time.Duration
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// Per-source bounds: one address can never hold every handshake slot or
// splice, so a flood from one client cannot stop the console for others.
const (
	maxPeeks          = 128
	maxPeeksPerSource = 8
	maxSplicePerSrc   = 256
)

// Subdomain matches exactly one DNS label under base (case-insensitive).
func Subdomain(base string) func(string) bool {
	base = strings.ToLower(strings.TrimSuffix(base, "."))
	return func(sni string) bool {
		sni = strings.ToLower(sni)
		label, ok := strings.CutSuffix(sni, "."+base)
		return ok && label != "" && !strings.Contains(label, ".")
	}
}

// Under matches any name strictly below base. base itself is excluded: it
// can be the console host (App Access portal-parent topology).
func Under(base string) func(string) bool {
	base = strings.ToLower(strings.TrimSuffix(base, "."))
	return func(sni string) bool {
		return strings.HasSuffix(strings.ToLower(sni), "."+base)
	}
}

// Listener yields only the owner's streams.
type Listener struct {
	net.Listener
	cfg     Config
	ready   chan net.Conn
	errs    chan error
	splice  chan struct{}
	done    chan struct{}
	once    sync.Once
	mu      sync.Mutex
	peeks   int
	sources map[string][2]int // in-flight peeks, splices
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
	if cfg.Idle <= 0 {
		cfg.Idle = time.Hour
	}
	if cfg.Dial == nil {
		cfg.Dial = (&net.Dialer{Timeout: 3 * time.Second}).DialContext
	}
	x := &Listener{Listener: l, cfg: cfg, ready: make(chan net.Conn), errs: make(chan error, 1), splice: make(chan struct{}, cfg.MaxSplices), done: make(chan struct{}), sources: map[string][2]int{}}
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
		// Never block accepting: over a bound, the new stream is closed.
		source := sourceOf(c)
		if !l.take(source, 0) {
			c.Close()
			continue
		}
		go l.route(c, source)
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

func sourceOf(c net.Conn) string {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP.String()
	}
	return c.RemoteAddr().String()
}

// take reserves a peek (kind 0) or splice (kind 1) slot for source.
func (l *Listener) take(source string, kind int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := l.sources[source]
	if kind == 0 && (l.peeks >= maxPeeks || n[0] >= maxPeeksPerSource) || kind == 1 && n[1] >= maxSplicePerSrc {
		return false
	}
	if kind == 0 {
		l.peeks++
	}
	n[kind]++
	l.sources[source] = n
	return true
}

func (l *Listener) release(source string, kind int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := l.sources[source]
	n[kind]--
	if kind == 0 {
		l.peeks--
	}
	if n == [2]int{} {
		delete(l.sources, source)
	} else {
		l.sources[source] = n
	}
}

func (l *Listener) route(c net.Conn, source string) {
	sni, hello, err := ServerName(c, l.cfg.Timeout)
	l.release(source, 0)
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
	target, token := l.cfg.Default, l.cfg.DefaultToken
	for _, r := range l.cfg.Routes {
		if sni != "" && r.Match(sni) {
			target, token = r.Target, r.Token
			break
		}
	}
	if !l.take(source, 1) {
		c.Close()
		return
	}
	defer l.release(source, 1)
	select {
	case l.splice <- struct{}{}:
	default:
		c.Close()
		return
	}
	defer func() { <-l.splice }()
	var secret []byte
	if token {
		secret = l.cfg.Token
	}
	l.forward(c, target, hello, secret)
}

// idle extends a read deadline on every read so a silent stream ends.
type idle struct {
	net.Conn
	d time.Duration
}

func (c idle) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.d))
	return c.Conn.Read(p)
}

func (l *Listener) forward(c net.Conn, target string, hello, token []byte) {
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
	header, err := proxyproto.Header(src, dst, token)
	if err != nil {
		return
	}
	if _, err = up.Write(append(header, hello...)); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, idle{src, l.cfg.Idle})
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
