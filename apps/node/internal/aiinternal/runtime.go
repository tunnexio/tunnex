package aiinternal

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/control"
)

// Error codes the gateway reports in ai_internal_endpoint_error. They are fixed strings: never a
// response body, a key, a path or anything else learned at run time.
const (
	ErrCodeInvalidDesired     = "invalid_desired_state"
	ErrCodeDesiredUnavailable = "desired_state_unavailable"
	ErrCodeCertificate        = "certificate_unavailable"
	ErrCodeCustomCertificate  = "custom_certificate_unavailable"
	ErrCodeCustomKeyMode      = "custom_key_permissions"
	ErrCodeCustomNotCovering  = "custom_certificate_not_covering"
	ErrCodeAddressNotOwned    = "address_not_owned"
	ErrCodeBindFailed         = "bind_failed"
)

const (
	// PollInterval is how often the gateway fetches the desired state; a watch kick fetches sooner.
	PollInterval = 15 * time.Second
	// transientGrace is how long the listener keeps serving the last good configuration while the
	// control plane cannot be reached. A definitive answer (404, refusal, invalid document) stops it at once.
	transientGrace = 60 * time.Second
	controlTimeout = 10 * time.Second
)

// Control is the agent-channel surface the runtime needs (control.Client implements it).
type Control interface {
	AIInternalDesiredState(context.Context) (control.AIInternalDesired, error)
	AIInternalSign(context.Context, string) (control.AIInternalCertificate, error)
}

// Config wires the runtime. Notify and Serving must not block.
type Config struct {
	Control   Control
	Target    *url.URL
	Transport http.RoundTripper
	// Notify is called whenever the reported status changes.
	Notify func()
	// Serving is called with the configured addresses and port while an endpoint is configured, and
	// with (nil, 0) when it is not; the in-cluster input chain follows it.
	Serving func([]netip.Addr, int)
	Logger  *slog.Logger

	// Test seams; nil selects the platform implementation and the defaults.
	Owned        func(netip.Addr) error
	Listen       func(context.Context, string) (net.Listener, error)
	CertDir      string
	Now          func() time.Time
	PollInterval time.Duration
}

// Status is what the gateway reports about the listener.
type Status struct {
	Ready        bool
	Addresses    []string
	Port         int
	Revision     int64
	Error        string
	CertNotAfter string
	CertSHA256   string
}

func (s Status) equal(o Status) bool {
	return s.Ready == o.Ready && slices.Equal(s.Addresses, o.Addresses) && s.Port == o.Port && s.Revision == o.Revision &&
		s.Error == o.Error && s.CertNotAfter == o.CertNotAfter && s.CertSHA256 == o.CertSHA256
}

type binding struct {
	server   *http.Server
	listener net.Listener
}

// Runtime owns the internal AI endpoint listener. It listens with tcp4 on each configured address
// without SO_BINDTODEVICE (VPN and site traffic to a LAN address arrives on the tunnel interface), only
// while the address is on an active non-loopback interface and a usable certificate is loaded, and
// closes on any doubt.
type Runtime struct {
	cfg  Config
	kick chan struct{}

	mu        sync.Mutex
	closed    bool
	desired   *Endpoint
	handler   http.Handler
	tlsConf   *tls.Config
	lastGood  time.Time
	pollErr   string
	caCert    *served
	custom    *served
	certErr   string
	bindErr   string
	bindings  map[netip.Addr]*binding
	published Status

	caServing atomic.Pointer[served]
}

// NewRuntime builds the runtime. It does nothing until Run.
func NewRuntime(cfg Config) *Runtime {
	if cfg.Owned == nil {
		cfg.Owned = ownedAddress
	}
	if cfg.Listen == nil {
		cfg.Listen = listenTCP4
	}
	if cfg.CertDir == "" {
		cfg.CertDir = CustomCertDir
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = PollInterval
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Runtime{cfg: cfg, kick: make(chan struct{}, 1), bindings: map[netip.Addr]*binding{}}
}

// Kick asks for a desired-state fetch now. It never blocks.
func (r *Runtime) Kick() {
	if r == nil {
		return
	}
	select {
	case r.kick <- struct{}{}:
	default:
	}
}

// Run polls the desired state every PollInterval (and on Kick) and reconciles the sockets every second.
func (r *Runtime) Run(ctx context.Context) {
	defer r.Close()
	go func() {
		ticker := time.NewTicker(r.cfg.PollInterval)
		defer ticker.Stop()
		for {
			r.Poll(ctx)
			r.Reconcile(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-r.kick:
			}
		}
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.Reconcile(ctx)
		}
	}
}

// Poll fetches and applies the desired state, then makes sure a certificate is available.
func (r *Runtime) Poll(ctx context.Context) {
	pollCtx, cancel := context.WithTimeout(ctx, controlTimeout)
	doc, err := r.cfg.Control.AIInternalDesiredState(pollCtx)
	cancel()
	if ctx.Err() != nil {
		return
	}
	now := r.cfg.Now()
	switch {
	case err != nil && errors.Is(err, control.ErrAIInternalOff):
		r.apply(nil, "")
	case err != nil:
		r.mu.Lock()
		keep := r.desired != nil && now.Sub(r.lastGood) <= transientGrace
		r.mu.Unlock()
		if keep {
			r.setPollError(ErrCodeDesiredUnavailable)
		} else {
			r.apply(nil, ErrCodeDesiredUnavailable)
		}
	default:
		ep, perr := ParseDesired(doc)
		if perr != nil {
			r.apply(nil, ErrCodeInvalidDesired)
			break
		}
		r.mu.Lock()
		r.lastGood = now
		r.mu.Unlock()
		r.apply(ep, "")
	}
	r.refreshCertificate(ctx)
}

func (r *Runtime) setPollError(code string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pollErr = code
	r.publishLocked()
}

// apply installs a new configuration. Any change to what is served closes every socket; the next
// reconcile binds again with the new configuration.
func (r *Runtime) apply(ep *Endpoint, pollErr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.pollErr = pollErr
	if !sameServing(r.desired, ep) {
		r.closeAllLocked()
		r.desired = ep
		r.handler, r.tlsConf = nil, nil
		r.bindErr = ""
		if ep == nil {
			r.caCert, r.custom, r.certErr = nil, nil, ""
			r.caServing.Store(nil)
			r.serving(nil, 0)
		} else {
			if ep.TLSMode != TLSModeTunnexCA {
				r.caCert = nil
				r.caServing.Store(nil)
			}
			if ep.TLSMode != TLSModeCustom {
				r.custom = nil
			}
			r.certErr = ""
			r.handler = Handler(r.cfg.Target, r.cfg.Transport, ep.Sources)
			r.tlsConf = tlsConfig(ep.DNSName, r.certificateFor(ep.TLSMode))
			r.serving(slices.Clone(ep.Addresses), ep.Port)
		}
	}
	r.publishLocked()
}

func (r *Runtime) serving(addrs []netip.Addr, port int) {
	if r.cfg.Serving != nil {
		r.cfg.Serving(addrs, port)
	}
}

// certificateFor returns the handshake's certificate source: the in-memory Tunnex-CA leaf, or the
// operator's files read on each handshake.
func (r *Runtime) certificateFor(mode string) func() (*tls.Certificate, error) {
	if mode == TLSModeCustom {
		return func() (*tls.Certificate, error) {
			s, err := loadCustom(r.cfg.CertDir, r.cfg.Now())
			if err != nil {
				return nil, errors.New("certificate unavailable")
			}
			return s.cert, nil
		}
	}
	return func() (*tls.Certificate, error) {
		s := r.caServing.Load()
		if s == nil {
			return nil, errors.New("certificate unavailable")
		}
		return s.cert, nil
	}
}

// refreshCertificate loads the custom files, or issues the Tunnex-CA leaf when there is none, it does not
// cover the configuration, or a third of its life is left. A failed renewal keeps a leaf that is still
// valid and still covers the configuration.
func (r *Runtime) refreshCertificate(ctx context.Context) {
	r.mu.Lock()
	ep, current := r.desired, r.caCert
	r.mu.Unlock()
	if ep == nil {
		return
	}
	now := r.cfg.Now()
	if ep.TLSMode == TLSModeCustom {
		s, err := loadCustom(r.cfg.CertDir, now)
		code := ""
		switch {
		case errors.Is(err, errKeyPermissions):
			code = ErrCodeCustomKeyMode
		case err != nil:
			code = ErrCodeCustomCertificate
		}
		r.mu.Lock()
		if sameServing(r.desired, ep) {
			r.custom, r.certErr = s, code
			r.publishLocked()
		}
		r.mu.Unlock()
		return
	}
	if !needsIssue(current, ep, now) {
		return
	}
	issued, err := r.issue(ctx, ep, now)
	r.mu.Lock()
	defer r.mu.Unlock()
	if !sameServing(r.desired, ep) {
		return
	}
	if err != nil {
		if ctx.Err() == nil {
			r.cfg.Logger.Warn("ai_internal_certificate_unavailable")
		}
		r.certErr = ErrCodeCertificate
		r.publishLocked()
		return
	}
	r.caCert, r.certErr = issued, ""
	r.caServing.Store(issued)
	r.cfg.Logger.Info("ai_internal_certificate_issued", "not_after", issued.notAfter.UTC().Format(time.RFC3339))
	r.publishLocked()
}

func (r *Runtime) issue(ctx context.Context, ep *Endpoint, now time.Time) (*served, error) {
	key, csr, err := newCSR(ep)
	if err != nil {
		return nil, err
	}
	signCtx, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	resp, err := r.cfg.Control.AIInternalSign(signCtx, csr)
	if err != nil {
		return nil, err
	}
	return verifyIssued(key, resp, ep, now)
}

// usableLocked returns the certificate the listener may serve now, or nil.
func (r *Runtime) usableLocked(now time.Time) *served {
	if r.desired == nil {
		return nil
	}
	s := r.caCert
	if r.desired.TLSMode == TLSModeCustom {
		s = r.custom
	} else if s != nil && !covers(s.leaf, r.desired) {
		return nil
	}
	if s == nil || now.Before(s.leaf.NotBefore) || !now.Before(s.leaf.NotAfter) {
		return nil
	}
	return s
}

// Reconcile binds each configured address that is on an active non-loopback interface and closes every
// socket whose address left, whose configuration changed, or when no usable certificate is loaded.
func (r *Runtime) Reconcile(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	defer r.publishLocked()
	if r.closed || ctx.Err() != nil || r.desired == nil || r.usableLocked(r.cfg.Now()) == nil {
		r.closeAllLocked()
		return
	}
	ep := r.desired
	bindErr := ""
	for _, addr := range ep.Addresses {
		if err := r.cfg.Owned(addr); err != nil {
			r.closeLocked(addr)
			bindErr = ErrCodeAddressNotOwned
			continue
		}
		if r.bindings[addr] != nil {
			continue
		}
		listener, err := r.cfg.Listen(ctx, net.JoinHostPort(addr.String(), strconv.Itoa(ep.Port)))
		if err != nil {
			bindErr = ErrCodeBindFailed
			continue
		}
		// Fail closed if the address left while the socket was created.
		if r.cfg.Owned(addr) != nil || ctx.Err() != nil {
			_ = listener.Close()
			bindErr = ErrCodeAddressNotOwned
			continue
		}
		b := &binding{listener: listener, server: newServer(ctx, r.handler, r.tlsConf)}
		r.bindings[addr] = b
		r.cfg.Logger.Info("ai_internal_listener_ready", "address", addr.String(), "port", ep.Port)
		sources := ep.Sources
		go func() {
			serveErr := serve(b.server, listener, func(peer netip.Addr) bool { return allows(sources, peer) })
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.bindings[addr] == b {
				delete(r.bindings, addr)
				_ = b.server.Close()
				if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
					r.cfg.Logger.Warn("ai_internal_listener_stopped", "address", addr.String())
				}
				r.publishLocked()
			}
		}()
	}
	if bindErr != r.bindErr && bindErr != "" {
		r.cfg.Logger.Warn("ai_internal_bind_unavailable", "reason", bindErr)
	}
	r.bindErr = bindErr
}

// Status is the reported listener state. Ready means every configured address is listening with a
// usable certificate.
func (r *Runtime) Status() Status {
	if r == nil {
		return Status{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.statusLocked()
}

func (r *Runtime) statusLocked() Status {
	s := Status{Addresses: []string{}, Error: r.pollErr}
	ep := r.desired
	if ep == nil {
		return s
	}
	s.Port, s.Revision = ep.Port, ep.Revision
	for _, addr := range ep.Addresses {
		if r.bindings[addr] != nil {
			s.Addresses = append(s.Addresses, addr.String())
		}
	}
	usable := r.usableLocked(r.cfg.Now())
	s.Ready = usable != nil && len(s.Addresses) == len(ep.Addresses)
	cert := r.caCert
	if ep.TLSMode == TLSModeCustom {
		cert = r.custom
	}
	if cert != nil {
		s.CertNotAfter = cert.notAfter.UTC().Format(time.RFC3339)
		s.CertSHA256 = cert.sha256
	}
	switch {
	case s.Error != "":
	case r.certErr != "":
		s.Error = r.certErr
	case usable == nil:
		s.Error = ErrCodeCertificate
		if ep.TLSMode == TLSModeCustom {
			s.Error = ErrCodeCustomCertificate
		}
	case r.bindErr != "":
		s.Error = r.bindErr
	case ep.TLSMode == TLSModeCustom && !covers(usable.leaf, ep):
		s.Error = ErrCodeCustomNotCovering
	}
	return s
}

// publishLocked calls Notify when the reported status changed.
func (r *Runtime) publishLocked() {
	s := r.statusLocked()
	if s.equal(r.published) {
		return
	}
	r.published = s
	if r.cfg.Notify != nil {
		r.cfg.Notify()
	}
}

// Close stops every socket for good.
func (r *Runtime) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		r.closeAllLocked()
		r.serving(nil, 0)
		r.publishLocked()
	}
}

func (r *Runtime) closeLocked(addr netip.Addr) {
	if b := r.bindings[addr]; b != nil {
		delete(r.bindings, addr)
		// Close the raw listener too: Serve may not yet have registered it.
		_ = b.listener.Close()
		_ = b.server.Close()
	}
}

func (r *Runtime) closeAllLocked() {
	for addr := range r.bindings {
		r.closeLocked(addr)
	}
}
