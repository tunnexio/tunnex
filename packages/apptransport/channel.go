// Package apptransport implements bounded outbound HTTP/1 CONNECT channels.
// Callers supply current authority; headers and TLS certificate names never grant it.
package apptransport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type Binding struct {
	OrgID, GatewayID, AppID, Generation, Digest, Purpose string
	Revision                                             int64
	Hostname                                             string
	AuthorityVersion                                     int64
}
type Authorize func(context.Context, Binding, string) (time.Time, error)

var ErrUnavailable = errors.New("app channel unavailable")

type Broker struct {
	mu                 sync.Mutex
	authorize          Authorize
	connections        map[*channel]bool
	closed             bool
	notify             chan struct{}
	pending            map[Binding]int
	pendingCount       int
	authoritySlots     chan struct{}
	purpose            string
	admissionSaturated atomic.Uint64
}
type channel struct {
	net.Conn
	broker            *Broker
	binding           Binding
	serial            string
	credentialExpires time.Time
	expires           time.Time
	idle              bool
	claimed           bool
	activeDeadline    time.Time
	activeTimer       *time.Timer
	leaseTimer        *time.Timer
	closed            bool
	monitorDone       chan struct{}
	done              chan struct{}
	once              sync.Once
	ctx               context.Context
	cancel            context.CancelFunc
}

func NewBroker(authorize Authorize) *Broker {
	return &Broker{authorize: authorize, connections: map[*channel]bool{}, notify: make(chan struct{}), pending: map[Binding]int{}, authoritySlots: make(chan struct{}, 128), purpose: "origin_check"}
}

// NewBrowserBroker is a separate authority/pool; check channels cannot enter it.
func NewBrowserBroker(authorize Authorize) *Broker {
	b := NewBroker(authorize)
	b.purpose = "browser_proxy"
	return b
}
func (b *Broker) signal() { close(b.notify); b.notify = make(chan struct{}) }
func (c *channel) Close() error {
	var e error
	c.once.Do(func() {
		b := c.broker
		b.mu.Lock()
		c.closed = true
		if c.leaseTimer != nil {
			c.leaseTimer.Stop()
		}
		if c.activeTimer != nil {
			c.activeTimer.Stop()
		}
		delete(b.connections, c)
		b.signal()
		b.mu.Unlock()
		c.cancel()
		close(c.done)
		e = c.Conn.Close()
	})
	return e
}
func (b *Broker) Close() error {
	b.mu.Lock()
	b.closed = true
	all := make([]*channel, 0, len(b.connections))
	for c := range b.connections {
		all = append(all, c)
	}
	b.signal()
	b.mu.Unlock()
	for _, c := range all {
		c.Close()
	}
	return nil
}
func (b *Broker) Accept(w http.ResponseWriter, r *http.Request, binding Binding, serial string) error {
	if r.Method != http.MethodConnect || r.URL.Path != b.channelPath() || r.ProtoMajor != 1 || binding.Purpose != b.purpose || b.authorize == nil {
		http.Error(w, "channel refused", http.StatusForbidden)
		return ErrUnavailable
	}
	b.mu.Lock()
	idle := b.pending[binding]
	for c := range b.connections {
		if c.binding == binding && !c.claimed && !c.closed {
			idle++
		}
	}
	if b.closed || len(b.connections)+b.pendingCount >= 128 || idle >= 2 {
		if !b.closed {
			b.admissionSaturated.Add(1)
		}
		b.mu.Unlock()
		http.Error(w, "channel capacity unavailable", http.StatusServiceUnavailable)
		return ErrUnavailable
	}
	b.pending[binding]++
	b.pendingCount++
	b.mu.Unlock()
	reserved := true
	release := func() {
		b.pendingCount--
		b.pending[binding]--
		if b.pending[binding] == 0 {
			delete(b.pending, binding)
		}
	}
	defer func() {
		if reserved {
			b.mu.Lock()
			release()
			b.mu.Unlock()
		}
	}()
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	lease, e := b.authorizeBound(ctx, binding, serial)
	issuedLease := lease
	credentialExpires := authenticatedCertificateExpiry(r)
	lease = capCredentialLease(lease, credentialExpires)
	expired := ctx.Err() != nil
	deadline, _ := ctx.Deadline()
	expired = expired || !time.Now().Before(deadline)
	cancel()
	if e != nil || expired || !lease.After(time.Now()) || issuedLease.After(time.Now().Add(b.maxLease())) {
		http.Error(w, "channel refused", http.StatusForbidden)
		return ErrUnavailable
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		http.Error(w, "channel unavailable", http.StatusServiceUnavailable)
		return ErrUnavailable
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		b.mu.Unlock()
		http.Error(w, "HTTP/1 channel required", http.StatusServiceUnavailable)
		return ErrUnavailable
	}
	conn, rw, e := hijacker.Hijack()
	if e != nil {
		b.mu.Unlock()
		return e
	}
	if rw.Reader.Buffered() != 0 {
		b.mu.Unlock()
		conn.Close()
		return ErrUnavailable
	}
	channelctx, channelcancel := context.WithCancel(context.Background())
	c := &channel{Conn: conn, broker: b, binding: binding, serial: serial, expires: lease, credentialExpires: credentialExpires, idle: false, monitorDone: make(chan struct{}), done: make(chan struct{}), ctx: channelctx, cancel: channelcancel}
	release()
	reserved = false
	b.connections[c] = true
	c.leaseTimer = time.AfterFunc(time.Until(lease), func() { c.Close() })
	b.mu.Unlock()
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, e = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); e == nil {
		e = rw.Flush()
	}
	_ = conn.SetWriteDeadline(time.Time{})
	if e != nil {
		c.Close()
		return e
	}
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	go c.monitor()
	go c.renew()
	b.mu.Lock()
	c.idle = true
	b.signal()
	b.mu.Unlock()
	return nil
}
func (c *channel) monitor() {
	defer close(c.monitorDone)
	var one [1]byte
	_, e := c.Conn.Read(one[:])
	b := c.broker
	b.mu.Lock()
	claimed := c.claimed
	b.mu.Unlock()
	var netError net.Error
	if !claimed || e == nil || !errors.As(e, &netError) || !netError.Timeout() {
		c.Close()
	}
}
func (c *channel) renew() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			c.broker.mu.Lock()
			activeUntil := c.activeDeadline
			c.broker.mu.Unlock()
			if !activeUntil.IsZero() && !time.Now().Before(activeUntil) {
				c.Close()
				return
			}
			ctx, cancel := context.WithDeadline(c.ctx, c.expires)
			lease, e := c.broker.authorizeBound(ctx, c.binding, c.serial)
			issuedLease := lease
			lease = capCredentialLease(lease, c.credentialExpires)
			cancel()
			now := time.Now()
			if e != nil || !now.Before(c.expires) || !lease.After(now) || issuedLease.After(now.Add(c.broker.maxLease())) {
				c.Close()
				return
			}
			c.broker.mu.Lock()
			if c.closed || !time.Now().Before(c.expires) || !c.leaseTimer.Stop() {
				c.broker.mu.Unlock()
				c.Close()
				return
			}
			c.expires = lease
			c.leaseTimer.Reset(time.Until(lease))
			c.broker.mu.Unlock()
		}
	}
}

// TLS validates certificate lifetimes at handshake, not throughout an existing
// connection. An admitted credential cannot renew a channel past that lifetime.
func authenticatedCertificateExpiry(r *http.Request) time.Time {
	var expiry time.Time
	if r.TLS == nil {
		return expiry
	} // Explicit nonshipping injected-authority fixtures.
	if len(r.TLS.VerifiedChains) == 0 {
		return time.Now()
	}
	for _, chain := range r.TLS.VerifiedChains {
		for _, cert := range chain {
			if cert == nil || cert.NotAfter.IsZero() {
				return time.Now()
			}
			if expiry.IsZero() || cert.NotAfter.Before(expiry) {
				expiry = cert.NotAfter
			}
		}
	}
	if expiry.IsZero() {
		return time.Now()
	}
	return expiry
}
func capCredentialLease(lease, expiry time.Time) time.Time {
	if !expiry.IsZero() && lease.After(expiry) {
		return expiry
	}
	return lease
}
func (b *Broker) Dial(ctx context.Context, binding Binding) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			return nil, ErrUnavailable
		}
		var selected *channel
		for c := range b.connections {
			if c.binding == binding && c.idle && !c.closed {
				c.idle = false
				c.claimed = true
				if b.purpose == "origin_check" {
					c.activeDeadline = time.Now().Add(10 * time.Second)
					c.activeTimer = time.AfterFunc(10*time.Second, func() { c.Close() })
				}
				selected = c
				break
			}
		}
		notify := b.notify
		b.mu.Unlock()
		if selected != nil {
			_ = selected.Conn.SetReadDeadline(time.Now())
			select {
			case <-selected.monitorDone:
			case <-ctx.Done():
				selected.Close()
				return nil, ctx.Err()
			}
			if b.purpose == "origin_check" {
				_ = selected.Conn.SetDeadline(time.Now().Add(10 * time.Second))
			} else {
				_ = selected.Conn.SetDeadline(time.Time{})
			}
			b.mu.Lock()
			closed := selected.closed
			b.mu.Unlock()
			if closed {
				continue
			}
			return selected, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-notify:
		}
	}
}
func BindingHeaders(h http.Header, b Binding) {
	h.Set("X-App-ID", b.AppID)
	h.Set("X-App-Revision", strconv.FormatInt(b.Revision, 10))
	h.Set("X-App-Digest", b.Digest)
	h.Set("X-App-Generation", b.Generation)
	h.Set("X-App-Purpose", b.Purpose)
	if b.Purpose == "browser_proxy" {
		h.Set("X-App-Org-ID", b.OrgID)
		h.Set("X-App-Gateway-ID", b.GatewayID)
		h.Set("X-App-Hostname", b.Hostname)
		h.Set("X-App-Authority-Version", strconv.FormatInt(b.AuthorityVersion, 10))
	}
}
func (b Binding) ValidateHeaders(h http.Header) error {
	expected := make(http.Header)
	BindingHeaders(expected, b)
	for k, v := range expected {
		values := h.Values(k)
		if len(values) != 1 || values[0] != v[0] {
			return fmt.Errorf("channel binding refused")
		}
	}
	return nil
}

// DialAuthenticated returns the actual certificate serial admitted on the selected
// stream. A caller must recheck that identity when recording check completion.
func (b *Broker) DialAuthenticated(ctx context.Context, binding Binding) (net.Conn, string, error) {
	conn, e := b.Dial(ctx, binding)
	if e != nil {
		return nil, "", e
	}
	return conn, conn.(*channel).serial, nil
}

func (b *Broker) authorizeBound(ctx context.Context, binding Binding, serial string) (time.Time, error) {
	if ctx.Err() != nil {
		return time.Time{}, ctx.Err()
	}
	select {
	case b.authoritySlots <- struct{}{}:
		defer func() { <-b.authoritySlots }()
	case <-ctx.Done():
		return time.Time{}, ctx.Err()
	}
	if ctx.Err() != nil {
		return time.Time{}, ctx.Err()
	}
	return b.authorize(ctx, binding, serial)
}

func (b *Broker) channelPath() string {
	if b.purpose == "browser_proxy" {
		return "/app-access/channel"
	}
	return "/agent/app-access/channel"
}
func (b *Broker) maxLease() time.Duration {
	if b.purpose == "browser_proxy" {
		return 4 * time.Second
	}
	return 5 * time.Second
}
