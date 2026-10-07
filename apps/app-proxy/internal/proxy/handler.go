package proxy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport"
)

// Handler never positively caches route or session authority.
type Handler struct {
	BaseDomain           string
	Console              *url.URL
	NonceSource          io.Reader
	Authority            Authority
	Broker               *apptransport.Broker
	Readiness            *ReadinessWorker
	beam                 bool
	mu                   sync.Mutex
	counts               map[string]int
	callbacks            chan struct{}
	terminationCallbacks chan struct{}
	metrics              measurements
}

func NewHandler(base string, a Authority, b *apptransport.Broker) *Handler {
	return &Handler{BaseDomain: base, Authority: a, Broker: b, counts: map[string]int{}, callbacks: make(chan struct{}, 128), terminationCallbacks: make(chan struct{}, 128)}
}

// NewBeamHandler retains the tested HTTP/stream authority enforcement while
// selecting Beam's separate route audience and reserved launch namespace.
func NewBeamHandler(base string, a Authority, b *apptransport.Broker) *Handler {
	h := NewHandler(base, a, b)
	h.beam = true
	return h
}
func (h *Handler) purpose() string {
	if h.beam {
		return "beam_proxy"
	}
	return "browser_proxy"
}
func (h *Handler) reservedPrefix() string {
	if h.beam {
		return "/_beam"
	}
	return "/__tunnex_app"
}
func (h *Handler) bodyLimit() int64 {
	if h.beam {
		return 16 << 20
	}
	return 64 << 20
}

type connectionContextKey struct{}

// ConnectionContext attaches the transport used by the HTTP/1.1-only browser
// listener. Lease expiry must close that transport directly: tls.Conn.Close can
// extend an expired write deadline while trying to send its close-notify alert.
func ConnectionContext(ctx context.Context, conn net.Conn) context.Context {
	if tlsConn, ok := conn.(interface{ NetConn() net.Conn }); ok {
		conn = tlsConn.NetConn()
	}
	return context.WithValue(ctx, connectionContextKey{}, conn)
}
func (h *Handler) reserve(b Binding, token string) func() {
	hash := sha256.Sum256([]byte(token))
	keys := []string{"global", "app:" + b.OrgID + ":" + b.AppID, "gateway:" + b.OrgID + ":" + b.GatewayID, "session:" + hex.EncodeToString(hash[:])}
	limits := []int{256, 32, 128, 16}
	if h.beam {
		keys = append(keys, "org:"+b.OrgID)
		limits = append(limits, 64)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, k := range keys {
		if h.counts[k] >= limits[i] {
			h.metrics.admissionSaturated.Add(1)
			return nil
		}
	}
	for _, k := range keys {
		h.counts[k]++
	}
	return func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		for _, k := range keys {
			h.counts[k]--
			if h.counts[k] == 0 {
				delete(h.counts, k)
			}
		}
	}
}
func validDecision(d Decision, start time.Time) bool {
	return d.StreamID != "" && len(d.StreamID) <= 128 && d.ExpiresAt.After(time.Now()) && !d.ExpiresAt.After(time.Now().Add(4*time.Second)) && start.Add(4*time.Second).After(time.Now())
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(15 * time.Second))
	if h.beam && r.ContentLength > h.bodyLimit() {
		// Reject from headers without draining an unfinished upload. This is a
		// single-use response and must not hold a browser connection for its body.
		w.Header().Set("Connection", "close")
		http.Error(w, "Beam uploads are limited to 16 MiB.", http.StatusRequestEntityTooLarge)
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(10 * time.Second))
	}
	host, e := authorityHost(r.Host, h.BaseDomain, h.Authority)
	target, e2 := apptransport.RelativeTarget(r.URL)
	reserved := strings.HasPrefix(r.URL.Path, h.reservedPrefix())
	if reserved && !r.URL.IsAbs() && r.URL.Host == "" && r.URL.Opaque == "" && r.URL.Fragment == "" {
		target = r.URL.RequestURI()
		e2 = nil
	}
	if e != nil || e2 != nil || r.TLS == nil || len(r.Header.Values("Host")) != 0 || r.Method == "CONNECT" || r.Method == "TRACE" || len(r.Header) > 100 || r.ContentLength < 0 || r.ContentLength > h.bodyLimit() || len(r.TransferEncoding) > 0 {
		h.deny(w)
		return
	}
	for _, name := range []string{"Authorization", "Proxy-Authorization", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User"} {
		if len(r.Header.Values(name)) > 1 {
			h.deny(w)
			return
		}
	}
	bytes := len(r.Host) + len(target) + len(r.Method) + 16
	fields := 1
	for k, values := range r.Header {
		for _, v := range values {
			fields++
			bytes += len(k) + len(v) + 4
		}
	}
	if bytes > 32<<10 || fields > 100 {
		h.deny(w)
		return
	}
	for _, c := range r.Method {
		if c < 'A' || c > 'Z' {
			h.deny(w)
			return
		}
	}
	upgrade := r.Header.Get("Upgrade")
	if upgrade != "" && (!strings.EqualFold(upgrade, "websocket") || len(r.Header.Values("Upgrade")) != 1 || r.Method != "GET") {
		h.deny(w)
		return
	}
	websocket := upgrade != ""
	safe := r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS"
	if (websocket || !safe) && !apptransport.SameOrigin(r, host, websocket) {
		h.deny(w)
		return
	}
	if reserved {
		if r.URL.Path == PublicReadinessPath && h.Readiness != nil {
			h.Readiness.Challenge(w, r, host)
			return
		}
		h.launch(w, r, host)
		return
	}
	token, e := apptransport.AppToken(r)
	if e != nil {
		h.deny(w)
		return
	}
	select {
	case h.callbacks <- struct{}{}:
	default:
		h.metrics.authoritySaturated.Add(1)
		h.deny(w)
		return
	}
	admissionCtx, admissionCancel := context.WithTimeout(r.Context(), 2*time.Second)
	route, e := h.Authority.Lookup(admissionCtx, host)
	if e != nil || route.Binding.Hostname != host || !Binding(route.Binding).validPurpose(h.purpose()) || admissionCtx.Err() != nil {
		admissionCancel()
		<-h.callbacks
		h.deny(w)
		return
	}
	if token == "" {
		admissionCancel()
		<-h.callbacks
		if h.hasConsole() && safe && !websocket && (r.Method == "GET" || r.Method == "HEAD") {
			h.restart(w, r, target)
		} else {
			h.deny(w)
		}
		return
	}
	release := h.reserve(Binding(route.Binding), token)
	if release == nil {
		admissionCancel()
		<-h.callbacks
		h.deny(w)
		return
	}
	defer release()
	start := time.Now()
	decision, e := h.Authority.Authorize(admissionCtx, Binding(route.Binding), token, requestMetadata(r, target))
	admissionErr := admissionCtx.Err()
	admissionCancel()
	<-h.callbacks
	if e != nil || admissionErr != nil || !validDecision(decision, start) {
		if e == ErrAppSession && admissionErr == nil && h.hasConsole() && !websocket && (r.Method == "GET" || r.Method == "HEAD") {
			h.restart(w, r, target)
			return
		}
		h.deny(w)
		return
	}
	if limit := start.Add(4 * time.Second); decision.ExpiresAt.After(limit) {
		decision.ExpiresAt = limit
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	writer := newStreamWriter(w, r)
	defer writer.finish()
	timer := time.AfterFunc(time.Until(decision.ExpiresAt), func() {
		if h.beam {
			h.metrics.authorityLeaseExpired.Add(1)
		}
		cancel()
		writer.close()
	})
	defer timer.Stop()
	go h.renew(ctx, cancel, writer, timer, Binding(route.Binding), decision)
	origin, e := url.Parse(route.OriginURL)
	if e != nil {
		h.deny(w)
		return
	}
	r = r.WithContext(ctx)
	if r.ContentLength > 0 {
		r.Body = http.MaxBytesReader(writer, &deadlineBody{ReadCloser: r.Body, owner: writer, idle: 15 * time.Second}, h.bodyLimit())
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 32 << 10, ResponseHeaderTimeout: 30 * time.Second, DialContext: func(c context.Context, _, _ string) (net.Conn, error) {
		return h.dialConnector(c, Binding(route.Binding))
	}}
	defer transport.CloseIdleConnections()
	reverse := &httputil.ReverseProxy{Transport: observedTransport{base: transport, metrics: &h.metrics}, FlushInterval: -1, Rewrite: func(p *httputil.ProxyRequest) {
		p.Out.URL.Scheme = "http"
		p.Out.URL.Host = "app-connector.internal"
		p.Out.Host = host
		apptransport.StripCredentials(p.Out.Header)
		apptransport.BindingHeaders(p.Out.Header, Binding(route.Binding).Transport())
		p.Out.Header.Set("X-App-Stream-ID", decision.StreamID)
		p.SetXForwarded()
		p.Out.Header.Set("X-Forwarded-Host", host)
		p.Out.Header.Set("X-Forwarded-Proto", "https")
	}, ModifyResponse: func(response *http.Response) error {
		h.observeOriginHeaders(response.Header)
		base := *origin
		base.Path = r.URL.Path
		base.RawPath = r.URL.RawPath
		base.RawQuery = r.URL.RawQuery
		return apptransport.RewriteResponse(response, &base, host)
	}, ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) { h.deny(w) }}
	reverse.ServeHTTP(writer, r)
	writer.mu.Lock()
	expired := writer.closed
	writer.mu.Unlock()
	h.notifyTerminated(Binding(route.Binding), decision.StreamID, expired)
}
func (h *Handler) renew(ctx context.Context, cancel context.CancelFunc, w *streamWriter, timer *time.Timer, b Binding, d Decision) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			select {
			case h.callbacks <- struct{}{}:
			case <-ctx.Done():
				return
			default:
				h.metrics.authoritySaturated.Add(1)
				cancel()
				w.close()
				return
			}
			// Slot remains held until callback returns even when its context is ignored.
			start := time.Now()
			leaseCtx, stop := context.WithDeadline(ctx, d.ExpiresAt)
			next, e := h.Authority.Renew(leaseCtx, b, d.StreamID)
			ended := leaseCtx.Err()
			stop()
			<-h.callbacks
			if e != nil || ended != nil || ctx.Err() != nil || time.Now().After(d.ExpiresAt) || next.StreamID != d.StreamID || !validDecision(next, start) || !timer.Stop() {
				if h.beam && ctx.Err() == nil {
					h.metrics.authorityLeaseFailures.Add(1)
				}
				cancel()
				w.close()
				return
			}
			if limit := start.Add(4 * time.Second); next.ExpiresAt.After(limit) {
				next.ExpiresAt = limit
			}
			timer.Reset(time.Until(next.ExpiresAt))
			d = next
		}
	}
}

// Per-write deadlines allow SSE while bounding a blocked reader. Hijacked
// WebSocket connections are explicitly closed on independent lease expiry.
type streamWriter struct {
	http.ResponseWriter
	mu        sync.Mutex
	conn      net.Conn
	transport net.Conn
	closed    bool
	finished  bool
}

func newStreamWriter(w http.ResponseWriter, r *http.Request) *streamWriter {
	writer := &streamWriter{ResponseWriter: w}
	if r.ProtoMajor == 1 {
		writer.transport, _ = r.Context().Value(connectionContextKey{}).(net.Conn)
	}
	return writer
}

func (w *streamWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *streamWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return 0, net.ErrClosed
	}
	_ = http.NewResponseController(w.ResponseWriter).SetWriteDeadline(time.Now().Add(15 * time.Second))
	w.mu.Unlock()
	return w.ResponseWriter.Write(p)
}
func (w *streamWriter) Flush() { _ = http.NewResponseController(w.ResponseWriter).Flush() }
func (w *streamWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, r, e := http.NewResponseController(w.ResponseWriter).Hijack()
	if e == nil {
		w.mu.Lock()
		if w.closed {
			_ = c.Close()
		} else {
			w.conn = c
		}
		w.mu.Unlock()
		c = &writeDeadlineConn{Conn: c}
	}
	return c, r, e
}
func (w *streamWriter) close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.finished {
		return
	}
	w.closed = true
	if w.transport != nil {
		_ = w.transport.Close()
	}
	_ = http.NewResponseController(w.ResponseWriter).SetWriteDeadline(time.Now())
	_ = http.NewResponseController(w.ResponseWriter).SetReadDeadline(time.Now())
	if w.conn != nil {
		_ = w.conn.Close()
	}
}

func (w *streamWriter) finish() { w.mu.Lock(); w.finished = true; w.mu.Unlock() }

type writeDeadlineConn struct{ net.Conn }

func (c *writeDeadlineConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return c.Conn.Write(p)
}

func requestMetadata(r *http.Request, target string) Request {
	out := Request{Method: r.Method, RelativePath: target, Origin: r.Header.Get("Origin"), Referer: r.Header.Get("Referer")}
	for name, destination := range map[string]**string{"Sec-Fetch-Mode": &out.FetchMode, "Sec-Fetch-Dest": &out.FetchDest, "Sec-Fetch-User": &out.FetchUser} {
		if values := r.Header.Values(name); len(values) == 1 {
			value := values[0]
			*destination = &value
		}
	}
	return out
}

// Only incoming body reads carry an idle deadline. GET/SSE background socket
// reads are not changed. Expiry and completed-response guards dominate resets.
type deadlineBody struct {
	io.ReadCloser
	owner *streamWriter
	idle  time.Duration
}

func (b *deadlineBody) Read(p []byte) (int, error) {
	w := b.owner
	w.mu.Lock()
	if w.closed || w.finished {
		w.mu.Unlock()
		return 0, net.ErrClosed
	}
	_ = http.NewResponseController(w.ResponseWriter).SetReadDeadline(time.Now().Add(b.idle))
	w.mu.Unlock()
	n, e := b.ReadCloser.Read(p)
	if e == io.EOF {
		b.clear()
	}
	return n, e
}
func (b *deadlineBody) clear() {
	w := b.owner
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.closed && !w.finished {
		_ = http.NewResponseController(w.ResponseWriter).SetReadDeadline(time.Time{})
	}
}
func (b *deadlineBody) Close() error { e := b.ReadCloser.Close(); b.clear(); return e }
