package appaccess

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/packages/apptransport"
	"github.com/tunnexio/tunnex/packages/apptransport/originpolicy"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

type poolWorker struct {
	assignment control.AppAssignment
	cancel     context.CancelFunc
}
type Pool struct {
	target     *url.URL
	tls        *tls.Config
	check      func(context.Context, control.AppAssignment) originpolicy.Result
	mu         sync.Mutex
	workers    map[string]poolWorker
	checks     map[string]control.AppCheck
	wait       sync.WaitGroup
	slots      chan struct{}
	notify     chan struct{}
	consumed   map[string]bool
	checkSlots chan struct{}
	checkQueue chan struct{}
}

func NewPool(client *control.AppAccessClient, check func(context.Context, control.AppAssignment) originpolicy.Result) *Pool {
	target, config := client.ChannelConfig()
	return &Pool{target: target, tls: config, check: check, workers: map[string]poolWorker{}, checks: map[string]control.AppCheck{}, slots: make(chan struct{}, 128), notify: make(chan struct{}), consumed: map[string]bool{}, checkSlots: make(chan struct{}, 8), checkQueue: make(chan struct{}, 32)}
}
func binding(a control.AppAssignment) apptransport.Binding {
	return apptransport.Binding{OrgID: a.OrgID, GatewayID: a.GatewayID, AppID: a.AppID, Generation: a.Generation, Revision: a.Revision, Digest: a.Digest, Purpose: a.Purpose}
}
func (p *Pool) Sync(ctx context.Context, assignments map[string]control.AppAssignment, checks []control.AppCheck) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(assignments) > 64 || len(checks) > 8 {
		assignments = map[string]control.AppAssignment{}
		checks = nil
	}
	close(p.notify)
	p.notify = make(chan struct{})
	p.checks = map[string]control.AppCheck{}
	for _, c := range checks {
		a, ok := assignments[c.AppID]
		if ok && matches(c, a) && (c.Status == "queued" || c.Status == "running") && time.Now().Before(c.Deadline) {
			p.checks[c.ID] = c
		}
	}
	for id := range p.consumed {
		if _, ok := p.checks[id]; !ok {
			delete(p.consumed, id)
		}
	}
	for id, w := range p.workers {
		a, ok := assignments[id]
		if !ok || binding(a) != binding(w.assignment) {
			w.cancel()
			delete(p.workers, id)
		}
	}
	for id, a := range assignments {
		if _, ok := p.workers[id]; ok {
			continue
		}
		workerctx, cancel := context.WithCancel(ctx)
		p.workers[id] = poolWorker{a, cancel}
		for i := 0; i < 2; i++ {
			p.wait.Add(1)
			go func(a control.AppAssignment) { defer p.wait.Done(); p.run(workerctx, a) }(a)
		}
	}
}
func (p *Pool) Close() {
	p.mu.Lock()
	for _, w := range p.workers {
		w.cancel()
	}
	p.workers = map[string]poolWorker{}
	p.checks = map[string]control.AppCheck{}
	p.mu.Unlock()
	p.wait.Wait()
}
func (p *Pool) run(ctx context.Context, a control.AppAssignment) {
	delay := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		started := time.Now()
		e := p.serve(ctx, a)
		if time.Since(started) >= 5*time.Second {
			delay = time.Second
		}
		if ctx.Err() != nil {
			return
		}
		if e == nil {
			delay = time.Second
			continue
		}
		pause := delay + time.Duration(rand.Int64N(int64(delay/4)+1))
		timer := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		delay *= 2
		if delay > 30*time.Second {
			delay = 30 * time.Second
		}
	}
}

type observedConn struct {
	net.Conn
	reader *bufio.Reader
	done   chan struct{}
	once   sync.Once
}

func (c *observedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }
func (c *observedConn) Close() error {
	e := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return e
}

type oneListener struct {
	conn *observedConn
	used bool
	ctx  context.Context
}

func (l *oneListener) Accept() (net.Conn, error) {
	if !l.used {
		l.used = true
		return l.conn, nil
	}
	select {
	case <-l.ctx.Done():
	case <-l.conn.done:
	}
	return nil, net.ErrClosed
}
func (l *oneListener) Close() error   { return l.conn.Close() }
func (l *oneListener) Addr() net.Addr { return l.conn.LocalAddr() }
func (p *Pool) serve(ctx context.Context, a control.AppAssignment) error {
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	case <-ctx.Done():
		return ctx.Err()
	}
	handshake, stop := context.WithTimeout(ctx, 5*time.Second)
	raw, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(handshake, "tcp", p.target.Host)
	if e != nil {
		stop()
		return e
	}
	defer raw.Close()
	conn := tls.Client(raw, p.tls.Clone())
	if e = conn.HandshakeContext(handshake); e != nil {
		stop()
		return e
	}
	stop()
	cancelClose := context.AfterFunc(ctx, func() { conn.Close() })
	defer cancelClose()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: "/agent/app-access/channel"}, Host: p.target.Host, Header: make(http.Header)}
	apptransport.BindingHeaders(req.Header, binding(a))
	if e = req.Write(conn); e != nil {
		return e
	}
	headerReader := &handshakeReader{reader: conn, remaining: 32 << 10, limited: true}
	reader := bufio.NewReaderSize(headerReader, 32<<10)
	response, e := http.ReadResponse(reader, req)
	if e != nil {
		return e
	}
	headerReader.limited = false
	if response.StatusCode != 200 {
		return apptransport.ErrUnavailable
	}
	_ = conn.SetDeadline(time.Time{})
	tracked := &observedConn{Conn: conn, reader: reader, done: make(chan struct{})}
	defer tracked.Close()
	listener := &oneListener{conn: tracked, ctx: ctx}
	server := &http.Server{ReadHeaderTimeout: 15 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 32 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	var consumed atomic.Bool
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		if !validCheckRequest(r, binding(a)) {
			http.Error(w, "check refused", 403)
			return
		}
		id := r.Header.Get("X-App-Check-ID")
		c, ok := p.authorized(r.Context(), a, id)
		if !ok {
			http.Error(w, "check refused", 403)
			return
		}
		consumed.Store(true)
		checkctx, cancel := context.WithDeadline(r.Context(), c.Deadline)
		defer cancel()
		checkctx, totalCancel := context.WithTimeout(checkctx, 10*time.Second)
		defer totalCancel()
		select {
		case p.checkQueue <- struct{}{}:
		default:
			http.Error(w, "check capacity unavailable", 503)
			return
		}
		select {
		case p.checkSlots <- struct{}{}:
			<-p.checkQueue
			defer func() { <-p.checkSlots }()
		case <-checkctx.Done():
			<-p.checkQueue
			http.Error(w, "check deadline exceeded", 504)
			return
		}
		value := p.check(checkctx, a)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(value)
	})
	defer server.Close()
	e = server.Serve(listener)
	if e == http.ErrServerClosed || e == net.ErrClosed || e == io.EOF {
		if consumed.Load() {
			return nil
		}
		return apptransport.ErrUnavailable
	}
	return e
}

func (p *Pool) authorized(ctx context.Context, a control.AppAssignment, id string) (control.AppCheck, bool) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for {
		p.mu.Lock()
		c, ok := p.checks[id]
		w, exists := p.workers[a.AppID]
		notify := p.notify
		if ok && matches(c, a) && time.Now().Before(c.Deadline) {
			if p.consumed[id] {
				p.mu.Unlock()
				return control.AppCheck{}, false
			}
			p.consumed[id] = true
		}
		p.mu.Unlock()
		if !exists || binding(w.assignment) != binding(a) {
			return control.AppCheck{}, false
		}
		if ok {
			return c, matches(c, a) && time.Now().Before(c.Deadline)
		}
		select {
		case <-ctx.Done():
			return control.AppCheck{}, false
		case <-notify:
		}
	}
}

type handshakeReader struct {
	reader    io.Reader
	remaining int
	limited   bool
}

func (r *handshakeReader) Read(p []byte) (int, error) {
	if !r.limited {
		return r.reader.Read(p)
	}
	if r.remaining <= 0 {
		return 0, io.ErrUnexpectedEOF
	}
	if len(p) > r.remaining {
		p = p[:r.remaining]
	}
	n, e := r.reader.Read(p)
	r.remaining -= n
	return n, e
}

func validCheckRequest(r *http.Request, b apptransport.Binding) bool {
	return r.Method == "GET" && r.URL.Path == "/__app_access/check" && r.URL.RawQuery == "" && !r.URL.ForceQuery && r.ContentLength == 0 && len(r.TransferEncoding) == 0 && (r.Body == nil || r.Body == http.NoBody) && len(r.Header.Values("X-App-Check-ID")) == 1 && r.Header.Get("Upgrade") == "" && b.ValidateHeaders(r.Header) == nil
}
