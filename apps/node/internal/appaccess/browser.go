package appaccess

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"github.com/google/uuid"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport"
	"github.com/tunnexio/tunnex/packages/apptransport/originpolicy"
)

// BrowserAssignment is separate from draft origin-check authority. Only a
// server-authorized serving desired-state can supply this complete binding.
type BrowserAssignment struct {
	Binding                         apptransport.Binding
	OriginURL                       string
	Policy                          originpolicy.Policy
	Stage                           string
	OperationID, ReadinessRequestID string
	Deadline                        time.Time
}
type BrowserPool struct {
	target         *url.URL
	tls            *tls.Config
	checker        originpolicy.Checker
	mu             sync.Mutex
	workers        map[string]browserWorker
	slots          chan struct{}
	runners        chan struct{}
	wait           sync.WaitGroup
	readinessSlots chan struct{}
}
type browserWorker struct {
	assignment BrowserAssignment
	cancel     context.CancelFunc
}

func NewBrowserPool(endpoint string, config *tls.Config, checker originpolicy.Checker) (*BrowserPool, error) {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || config == nil || config.InsecureSkipVerify || config.GetClientCertificate == nil || config.RootCAs == nil {
		return nil, apptransport.ErrUnavailable
	}
	c := config.Clone()
	c.MinVersion = tls.VersionTLS13
	c.NextProtos = []string{"http/1.1"}
	c.ServerName = "tunnex-app-proxy"
	checker.ControlHosts = append(checker.ControlHosts, u.Hostname())
	return &BrowserPool{target: u, tls: c, checker: checker, workers: map[string]browserWorker{}, slots: make(chan struct{}, 128), runners: make(chan struct{}, 128), readinessSlots: make(chan struct{}, 8)}, nil
}

// browserKey keeps active and staged generations independent. Reusing a
// generation with changed immutable configuration invalidates the snapshot.
func browserKey(b apptransport.Binding) string { return b.OrgID + "/" + b.AppID + "/" + b.Generation }
func (p *BrowserPool) Sync(ctx context.Context, assignments []BrowserAssignment) {
	p.mu.Lock()
	defer p.mu.Unlock()
	desired := map[string]BrowserAssignment{}
	valid := len(assignments) <= 64
	var org, gateway string
	generations := map[string]int{}
	for _, a := range assignments {
		b := a.Binding
		if a.Stage != "" && a.Stage != "active" && a.Stage != "pending" {
			valid = false
		}
		if a.Stage == "pending" {
			for _, id := range []string{a.OperationID, a.ReadinessRequestID} {
				parsed, e := uuid.Parse(id)
				if e != nil || parsed == uuid.Nil {
					valid = false
				}
			}
			if !a.Deadline.After(time.Now()) || a.Deadline.After(time.Now().Add(60*time.Second)) {
				valid = false
			}
		}
		for _, id := range []string{b.OrgID, b.GatewayID, b.AppID, b.Generation} {
			parsed, e := uuid.Parse(id)
			if e != nil || parsed == uuid.Nil {
				valid = false
			}
		}
		digest, e := hex.DecodeString(b.Digest)
		if e != nil || len(digest) != 32 {
			valid = false
		}
		if b.Purpose != "browser_proxy" || b.Hostname == "" || b.AuthorityVersion < 1 || b.Revision < 1 {
			valid = false
		}
		if _, e := apptransport.ExactHost(b.Hostname, ""); e != nil {
			valid = false
		}
		if org == "" {
			org = b.OrgID
			gateway = b.GatewayID
		} else if org != b.OrgID || gateway != b.GatewayID {
			valid = false
		}
		key := browserKey(b)
		generations[b.AppID]++
		if generations[b.AppID] > 2 {
			valid = false
		}
		if _, duplicate := desired[key]; duplicate {
			valid = false
		}
		policy, e := originpolicy.Normalize(a.Policy.AllowedDestinationCIDRs, a.Policy.OriginCAPEM)
		if e != nil || policy.OriginCADigest != a.Policy.OriginCADigest {
			valid = false
		}
		if old, ok := p.workers[key]; ok && (old.assignment.Binding != a.Binding || old.assignment.OriginURL != a.OriginURL || !reflect.DeepEqual(old.assignment.Policy, a.Policy)) {
			valid = false
		}
		desired[key] = a
	}
	if !valid {
		desired = map[string]BrowserAssignment{}
	}
	for id, w := range p.workers {
		a, ok := desired[id]
		if !ok || !reflect.DeepEqual(a, w.assignment) {
			w.cancel()
			delete(p.workers, id)
		}
	}
	for id, a := range desired {
		if _, ok := p.workers[id]; ok {
			continue
		}
		workerCtx, cancel := context.WithCancel(ctx)
		p.workers[id] = browserWorker{a, cancel}
		local := make(chan struct{}, 32)
		if !p.spawn(workerCtx, a, local) {
			cancel()
			delete(p.workers, id)
		}
	}
}
func (p *BrowserPool) Close() {
	p.mu.Lock()
	for _, w := range p.workers {
		w.cancel()
	}
	p.workers = map[string]browserWorker{}
	p.mu.Unlock()
	p.wait.Wait()
}
func (p *BrowserPool) spawn(ctx context.Context, a BrowserAssignment, local chan struct{}) bool {
	if ctx.Err() != nil {
		return false
	}
	select {
	case p.runners <- struct{}{}:
	default:
		return false
	}
	select {
	case local <- struct{}{}:
	default:
		<-p.runners
		return false
	}
	p.wait.Add(1)
	go func() { defer p.wait.Done(); defer func() { <-local; <-p.runners }(); p.run(ctx, a, local) }()
	return true
}
func (p *BrowserPool) run(ctx context.Context, a BrowserAssignment, local chan struct{}) {
	delay := time.Second
	for ctx.Err() == nil {
		var replenished atomic.Bool
		e := p.serve(ctx, a, func() {
			if p.spawn(ctx, a, local) {
				replenished.Store(true)
			}
		})
		if replenished.Load() {
			return
		}
		if e == nil {
			delay = time.Second
			continue
		}
		timer := time.NewTimer(delay + time.Duration(rand.Int64N(int64(delay/4)+1)))
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
func (p *BrowserPool) serve(ctx context.Context, a BrowserAssignment, claimed func()) error {
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	case <-ctx.Done():
		return ctx.Err()
	}
	handshake, cancel := context.WithTimeout(ctx, 5*time.Second)
	raw, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(handshake, "tcp", p.target.Host)
	if e != nil {
		cancel()
		return e
	}
	defer raw.Close()
	conn := tls.Client(raw, p.tls.Clone())
	if e = conn.HandshakeContext(handshake); e != nil {
		cancel()
		return e
	}
	cancel()
	closeOnCancel := context.AfterFunc(ctx, func() { conn.Close() })
	defer closeOnCancel()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	request := &http.Request{Method: "CONNECT", URL: &url.URL{Opaque: "/app-access/channel"}, Host: p.target.Host, Header: make(http.Header)}
	apptransport.BindingHeaders(request.Header, a.Binding)
	request.Header.Set("X-App-Org-ID", a.Binding.OrgID)
	request.Header.Set("X-App-Gateway-ID", a.Binding.GatewayID)
	if e = request.Write(conn); e != nil {
		return e
	}
	limit := &handshakeReader{reader: conn, remaining: 32 << 10, limited: true}
	reader := bufio.NewReaderSize(limit, 32<<10)
	response, e := http.ReadResponse(reader, request)
	if e != nil {
		return e
	}
	limit.limited = false
	if response.StatusCode != 200 {
		return apptransport.ErrUnavailable
	}
	_ = conn.SetDeadline(time.Time{})
	tracked := &observedConn{Conn: conn, reader: reader, done: make(chan struct{})}
	defer tracked.Close()
	listener := &oneListener{conn: tracked, ctx: ctx}
	forward := apptransport.BrowserOrigin(a.Binding, &originpolicy.Transport{Checker: p.checker, Origin: a.OriginURL, Policy: a.Policy})
	if a.Stage == "pending" {
		forward = apptransport.BrowserReadiness(a.Binding, a.OperationID, a.ReadinessRequestID, a.Deadline, func(ctx context.Context) originpolicy.Result { return p.checkPending(ctx, a) }, p.readinessSlots)
	}
	var once sync.Once
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { once.Do(claimed); forward.ServeHTTP(w, r) }), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 32 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	// Hijacked WebSockets retain the outbound connection until broker closure.
	server.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateHijacked {
			go func() { <-tracked.done; _ = server.Close() }()
		}
	}
	defer server.Close()
	e = server.Serve(listener)
	if e == net.ErrClosed || e == http.ErrServerClosed {
		return nil
	}
	return e
}
