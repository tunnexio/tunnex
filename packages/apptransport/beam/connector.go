package beam

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/tunnexio/tunnex/packages/apptransport"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxHeaders = 32 << 10
const maxBody = 16 << 20
const proxyServerName = "tunnex-beam-proxy"

var ErrExpired = errors.New("Beam connector expired")
var errRefused = errors.New("Beam transport refused")

// Target captures a numeric loopback app. CAPEM may pin its development CA.
type Target struct {
	Protocol, Address string
	Port              int
	CAPEM             string
	Routes            []Route
}
type Route struct {
	PathPrefix string
	Target     Target
}
type ConnectorOptions struct {
	ProxyURL, ServerName          string
	Binding                       apptransport.Binding
	Target                        Target
	CertificatePEM, KeyPEM, CAPEM string
	ExpiresAt                     time.Time
}
type ConnectorStats struct{ Opening, Idle, Active int }

// Connector owns only outbound sockets. Keys are never persisted.
type Connector struct {
	options              ConnectorOptions
	proxyAddress         string
	tlsConfig, originTLS *tls.Config
	mu                   sync.Mutex
	stats                ConnectorStats
	notify               chan struct{}
	running              atomic.Bool
}

func validateTarget(t Target) (*tls.Config, error) {
	if (t.Protocol != "http" && t.Protocol != "https") || (t.Address != "127.0.0.1" && t.Address != "::1") || t.Port < 1 || t.Port > 65535 || len(t.CAPEM) > maxHeaders || (t.Protocol == "http" && t.CAPEM != "") {
		return nil, errRefused
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: t.Address, NextProtos: []string{"http/1.1"}}
	if t.CAPEM != "" {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(t.CAPEM)) {
			return nil, errRefused
		}
		config.RootCAs = roots
	}
	return config, nil
}
func NewConnector(o ConnectorOptions) (*Connector, error) {
	originTLS, err := validateTarget(o.Target)
	if routeErr := ValidateTarget(o.Target); routeErr != nil {
		return nil, routeErr
	}
	if err != nil || !validBinding(o.Binding) || o.ServerName != proxyServerName || len(o.CAPEM) > maxHeaders || len(o.CertificatePEM) > maxHeaders || len(o.KeyPEM) > maxHeaders {
		return nil, errRefused
	}
	u, err := url.Parse(o.ProxyURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(o.ProxyURL, "#") {
		return nil, errRefused
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return nil, errRefused
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(o.CAPEM)) {
		return nil, errRefused
	}
	cert, err := tls.X509KeyPair([]byte(o.CertificatePEM), []byte(o.KeyPEM))
	if err != nil || len(cert.Certificate) == 0 {
		return nil, errRefused
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, errRefused
	}
	if o.ExpiresAt.IsZero() || leaf.NotAfter.Before(o.ExpiresAt) {
		o.ExpiresAt = leaf.NotAfter
	}
	if !o.ExpiresAt.After(time.Now()) || leaf.NotBefore.After(time.Now()) {
		return nil, ErrExpired
	}
	o.Target.Routes = append([]Route(nil), o.Target.Routes...)
	return &Connector{options: o, proxyAddress: net.JoinHostPort(u.Hostname(), port), tlsConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{cert}, ServerName: proxyServerName, NextProtos: []string{"http/1.1"}}, originTLS: originTLS, notify: make(chan struct{}, 1)}, nil
}
func (c *Connector) Stats() ConnectorStats { c.mu.Lock(); defer c.mu.Unlock(); return c.stats }
func (c *Connector) Ready() bool {
	s := c.Stats()
	return c.running.Load() && time.Now().Before(c.options.ExpiresAt) && s.Idle+s.Active > 0
}
func (c *Connector) signal() {
	select {
	case c.notify <- struct{}{}:
	default:
	}
}

// Run retains two idle channels, at most 32 active and 34 total reservations.
// Failed admission uses global bounded backoff instead of a connection flood.
func (c *Connector) Run(parent context.Context) error {
	if !c.running.CompareAndSwap(false, true) {
		return errors.New("Beam connector already running")
	}
	defer c.running.Store(false)
	ctx, cancel := context.WithDeadline(parent, c.options.ExpiresAt)
	defer cancel()
	var workers sync.WaitGroup
	var failureMu sync.Mutex
	failures := 0
	retryAt := time.Time{}
	for ctx.Err() == nil {
		failureMu.Lock()
		retry := retryAt
		failureMu.Unlock()
		c.mu.Lock()
		s := c.stats
		launch := s.Opening+s.Idle < 2 && s.Opening+s.Idle+s.Active < 34 && !time.Now().Before(retry)
		if launch {
			c.stats.Opening++
		}
		c.mu.Unlock()
		if launch {
			workers.Add(1)
			go func() {
				defer workers.Done()
				admitted := false
				claimed := false
				defer func() {
					c.mu.Lock()
					if !admitted {
						c.stats.Opening--
					} else if claimed {
						c.stats.Active--
					} else {
						c.stats.Idle--
					}
					c.mu.Unlock()
					c.signal()
				}()
				err := c.channel(ctx, func() bool {
					c.mu.Lock()
					defer c.mu.Unlock()
					if !admitted {
						c.stats.Opening--
						c.stats.Idle++
						admitted = true
						failureMu.Lock()
						failures = 0
						retryAt = time.Time{}
						failureMu.Unlock()
						c.signal()
						return true
					}
					if c.stats.Active >= 32 {
						return false
					}
					c.stats.Idle--
					c.stats.Active++
					claimed = true
					c.signal()
					return true
				})
				if ctx.Err() == nil && err != nil {
					failureMu.Lock()
					failures++
					shift := min(failures-1, 5)
					delay := min(300*time.Millisecond*time.Duration(1<<shift), 10*time.Second)
					retryAt = time.Now().Add(delay + time.Duration(rand.IntN(int(delay/5)+1)))
					failureMu.Unlock()
				}
			}()
			continue
		}
		delay := time.Until(retry)
		if delay <= 0 {
			delay = time.Hour
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
		case <-c.notify:
		case <-timer.C:
		}
		timer.Stop()
	}
	workers.Wait()
	if parent.Err() != nil {
		return parent.Err()
	}
	return ErrExpired
}
func readHeader(r *bufio.Reader) ([]byte, error) {
	header := make([]byte, 0, 1024)
	for len(header) < maxHeaders {
		b, e := r.ReadByte()
		if e != nil {
			return nil, e
		}
		header = append(header, b)
		n := len(header)
		if n >= 4 && bytes.Equal(header[n-4:], []byte("\r\n\r\n")) {
			return header, nil
		}
	}
	return nil, errRefused
}
func readResponse(r *bufio.Reader, request *http.Request) (*http.Response, *bufio.Reader, error) {
	header, e := readHeader(r)
	if e != nil {
		return nil, nil, e
	}
	stream := bufio.NewReader(io.MultiReader(bytes.NewReader(header), r))
	response, e := http.ReadResponse(stream, request)
	return response, stream, e
}

// Informational responses cannot suppress the final application response.
func readFinalResponse(r *bufio.Reader, request *http.Request) (*http.Response, *bufio.Reader, error) {
	for i := 0; i < 8; i++ {
		response, stream, e := readResponse(r, request)
		if e != nil {
			return nil, nil, e
		}
		if response.StatusCode == 101 || response.StatusCode >= 200 {
			return response, stream, nil
		}
		r = stream
	}
	return nil, nil, errRefused
}
func dialOrigin(ctx context.Context, t Target, config *tls.Config) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	address := net.JoinHostPort(t.Address, strconv.Itoa(t.Port))
	if t.Protocol == "https" {
		return (&tls.Dialer{NetDialer: d, Config: config}).DialContext(ctx, "tcp", address)
	}
	return d.DialContext(ctx, "tcp", address)
}
func CheckTarget(ctx context.Context, t Target) error {
	if e := ValidateTarget(t); e != nil {
		return e
	}
	targets := []Target{t}
	for _, route := range t.Routes {
		targets = append(targets, route.Target)
	}
	results := make(chan error, len(targets))
	for _, target := range targets {
		go func() { results <- checkSingleTarget(ctx, target) }()
	}
	var first error
	for range targets {
		if e := <-results; e != nil && first == nil {
			first = e
		}
	}
	return first
}
func checkSingleTarget(ctx context.Context, t Target) error {
	config, e := validateTarget(t)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	peer, e := dialOrigin(ctx, t, config)
	if e != nil {
		return errors.New("Beam local app unavailable")
	}
	defer peer.Close()
	stop := context.AfterFunc(ctx, func() { peer.Close() })
	defer stop()
	request := &http.Request{Method: http.MethodHead, URL: &url.URL{Path: "/"}, Host: net.JoinHostPort(t.Address, strconv.Itoa(t.Port)), Header: make(http.Header), Close: true}
	if e = request.Write(peer); e != nil {
		return e
	}
	response, _, e := readFinalResponse(bufio.NewReader(peer), request)
	if e != nil {
		return errors.New("Beam local app unavailable")
	}
	response.Body.Close()
	return nil
}
func (c *Connector) channel(ctx context.Context, transition func() bool) error {
	ctx, channelCancel := context.WithCancel(ctx)
	defer channelCancel()
	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	peer, e := (&tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: c.tlsConfig}).DialContext(connectCtx, "tcp", c.proxyAddress)
	if e != nil {
		return errRefused
	}
	defer peer.Close()
	stop := context.AfterFunc(ctx, func() { peer.Close() })
	defer stop()
	peer.SetDeadline(time.Now().Add(5 * time.Second))
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: ChannelPath}, Host: c.proxyAddress, Header: make(http.Header)}
	apptransport.BindingHeaders(request.Header, c.options.Binding)
	if e = request.Write(peer); e != nil {
		return e
	}
	response, stream, e := readResponse(bufio.NewReader(peer), request)
	if e != nil || response.StatusCode != 200 {
		return errRefused
	}
	if response.ContentLength > 0 || len(response.TransferEncoding) > 0 {
		return errRefused
	}
	peer.SetDeadline(time.Time{})
	if !transition() {
		return errRefused
	}
	if _, e = stream.Peek(1); e != nil {
		return e
	}
	peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	header, e := readHeader(stream)
	if e != nil {
		return e
	}
	input := bufio.NewReader(io.MultiReader(bytes.NewReader(header), stream))
	r, e := http.ReadRequest(input)
	if e != nil {
		return e
	}
	peer.SetReadDeadline(time.Time{})
	if !transition() {
		return errRefused
	}
	if r.ProtoMajor != 1 || r.Host != c.options.Binding.Hostname || r.Method == http.MethodConnect || r.Method == http.MethodTrace || c.options.Binding.ValidateHeaders(r.Header) != nil {
		refuse(peer, 403)
		return errRefused
	}
	if _, e = apptransport.RelativeTarget(r.URL); e != nil || len(r.Header.Values("X-App-Stream-ID")) != 1 || !validStream(r.Header.Get("X-App-Stream-ID")) {
		refuse(peer, 403)
		return errRefused
	}
	if len(r.Trailer) > 0 {
		refuse(peer, 403)
		return errRefused
	}
	if r.ContentLength > maxBody {
		refuse(peer, 413)
		return errRefused
	}
	upgrade := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
	if r.Header.Get("Upgrade") != "" && !upgrade {
		refuse(peer, 403)
		return errRefused
	}
	if upgrade && (r.Method != "GET" || !apptransport.SameOrigin(r, c.options.Binding.Hostname, true) || r.ContentLength > 0 || len(r.TransferEncoding) > 0) {
		refuse(peer, 403)
		return errRefused
	}
	r.Body = &boundedReadCloser{ReadCloser: r.Body, left: maxBody}
	cleanHeaders(r.Header, upgrade)
	r.Header.Set("X-Forwarded-Host", c.options.Binding.Hostname)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.RequestURI = ""
	r.Close = !upgrade
	// Peek leaves upgrade head bytes in the bounded reader. Until the origin
	// upgrades, a browser ordinarily sends no data; proxy withdrawal must still
	// cancel the pending origin handshake. The client frame copier waits for this
	// peek to finish before reading the same reader.
	var wsPeekDone chan struct{}
	if upgrade {
		wsPeekDone = make(chan struct{})
		go func() {
			defer close(wsPeekDone)
			if _, e := input.Peek(1); e != nil {
				channelCancel()
			}
		}()
		defer func() { peer.Close(); <-wsPeekDone }()
	}
	originContext := ctx
	originDeadline := time.Now().Add(15 * time.Second)
	if upgrade {
		// Early WebSocket head bytes make an EOF peek finish before withdrawal.
		// Bound the entire local dial/upgrade so those bytes cannot pin a revoked
		// channel; clear this deadline only after the actual101 response arrives.
		var cancelUpgrade context.CancelFunc
		originContext, cancelUpgrade = context.WithTimeout(ctx, 2*time.Second)
		defer cancelUpgrade()
		originDeadline, _ = originContext.Deadline()
	}
	target, e := TargetForPath(c.options.Target, r.URL.Path)
	if e != nil {
		refuse(peer, 403)
		return e
	}
	originTLS, e := validateTarget(target)
	if e != nil {
		return e
	}
	origin, e := dialOrigin(originContext, target, originTLS)
	if e != nil {
		refuse(peer, 502)
		return errRefused
	}
	defer origin.Close()
	cancelOrigin := context.AfterFunc(ctx, func() { origin.Close() })
	defer cancelOrigin()
	origin.SetDeadline(originDeadline)
	if !upgrade {
		peer.SetReadDeadline(time.Now().Add(30 * time.Second))
	}
	if e = r.Write(origin); e != nil {
		return e
	}
	peer.SetReadDeadline(time.Time{})
	// A withdrawn proxy channel must close even if the origin's response is idle.
	watchDone := make(chan struct{})
	if !upgrade {
		go func() { defer close(watchDone); _, _ = input.ReadByte(); origin.Close(); channelCancel() }()
		defer func() { peer.Close(); <-watchDone }()
	}
	result, upstream, e := readFinalResponse(bufio.NewReader(origin), r)
	if e != nil {
		refuse(peer, 502)
		return errRefused
	}
	if !upgrade {
		origin.SetDeadline(time.Time{})
	}
	if len(result.Trailer) > 0 {
		refuse(peer, 502)
		return errRefused
	}
	originURL := &url.URL{Scheme: target.Protocol, Host: net.JoinHostPort(target.Address, strconv.Itoa(target.Port)), Path: "/"}
	for _, cookie := range result.Cookies() {
		if strings.HasPrefix(strings.ToLower(cookie.Name), "__host-tunnex_") {
			refuse(peer, 502)
			return errRefused
		}
	}
	if e = apptransport.RewriteResponse(result, originURL, c.options.Binding.Hostname); e != nil {
		refuse(peer, 502)
		return errRefused
	}
	if upgrade {
		if result.StatusCode != 101 || !strings.EqualFold(result.Header.Get("Upgrade"), "websocket") || len(result.Header.Values("Sec-WebSocket-Extensions")) > 0 {
			return errRefused
		}
		origin.SetDeadline(time.Time{})
		cleanHeaders(result.Header, true)
		if e = writeUpgrade(peer, result); e != nil {
			return e
		}
		done := make(chan error, 2)
		go func() { <-wsPeekDone; _, err := copyFrames(origin, input, true); done <- err }()
		go func() { _, err := copyFrames(peer, upstream, false); done <- err }()
		e = <-done
		peer.Close()
		origin.Close()
		<-done
		return e
	}
	if result.StatusCode == 101 {
		return errRefused
	}
	if result.ContentLength > maxBody {
		refuse(peer, 502)
		return errRefused
	}
	cleanHeaders(result.Header, false)
	result.Close = true
	result.Body = &boundedReadCloser{ReadCloser: result.Body, left: maxBody}
	defer result.Body.Close()
	return result.Write(peer)
}
func validStream(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, b := range s {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '-') {
			return false
		}
	}
	return true
}
func refuse(w io.Writer, status int) {
	body := http.StatusText(status)
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", status, body, len(body), body)
}
func cleanHeaders(h http.Header, upgrade bool) {
	nominated := strings.Split(strings.Join(h.Values("Connection"), ","), ",")
	apptransport.StripCredentials(h)
	request := &http.Request{Header: h}
	var cookies []string
	for _, cookie := range request.Cookies() {
		if !strings.HasPrefix(strings.ToLower(cookie.Name), "__host-tunnex_") {
			cookies = append(cookies, cookie.String())
		}
	}
	h.Del("Cookie")
	if len(cookies) > 0 {
		h.Set("Cookie", strings.Join(cookies, "; "))
	}
	for _, auth := range h.Values("Authorization") {
		if strings.HasPrefix(strings.ToLower(auth), "beamconnector ") {
			h.Del("Authorization")
		}
	}
	h.Del("Sec-WebSocket-Extensions")
	for _, name := range nominated {
		name = strings.TrimSpace(name)
		if !upgrade || (!strings.EqualFold(name, "upgrade") && !strings.EqualFold(name, "sec-websocket-protocol")) {
			h.Del(name)
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		if !upgrade || (name != "Connection" && name != "Upgrade") {
			h.Del(name)
		}
	}
	if upgrade {
		h.Set("Connection", "Upgrade")
		h.Set("Upgrade", "websocket")
	}
}

type boundedReadCloser struct {
	io.ReadCloser
	left int64
}

func (r *boundedReadCloser) Read(p []byte) (int, error) {
	if int64(len(p)) > r.left+1 {
		p = p[:r.left+1]
	}
	n, e := r.ReadCloser.Read(p)
	if int64(n) > r.left {
		return 0, errRefused
	}
	r.left -= int64(n)
	return n, e
}
func writeUpgrade(w io.Writer, r *http.Response) error {
	if _, e := io.WriteString(w, "HTTP/1.1 101 Switching Protocols\r\n"); e != nil {
		return e
	}
	if e := r.Header.Write(w); e != nil {
		return e
	}
	_, e := io.WriteString(w, "\r\n")
	return e
}

// Socket ownership handles close; draining a rejected body could wait forever
// for an attacker that declared an upload but never sends its remaining bytes.
func (r *boundedReadCloser) Close() error { return nil }
