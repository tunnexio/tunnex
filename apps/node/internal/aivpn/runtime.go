package aivpn

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

const HTTPPort = "8083"

// Runtime owns the automatic inference-only listener. It has no host-published
// port, DNS dependency, provider credential or independent node identity.
type Runtime struct {
	mu        sync.Mutex
	iface     string
	desired   netip.Addr
	current   *binding
	closed    bool
	healthy   func() bool
	notify    func()
	logger    *slog.Logger
	target    *url.URL
	transport http.RoundTripper
	observe   func(context.Context, string, netip.Addr) (int, error)
	listen    func(context.Context, string, string) (net.Listener, error)
	peers     func(context.Context, string) (string, error)
}

type binding struct {
	index    int
	address  netip.Addr
	server   *http.Server
	listener net.Listener
}

func NewRuntime(iface string, target *url.URL, transport http.RoundTripper, healthy func() bool, notify func(), logger *slog.Logger) *Runtime {
	return &Runtime{iface: iface, target: target, transport: transport, healthy: healthy,
		notify: notify, logger: logger, observe: observeInterface, listen: listenInterface, peers: kernelPeers}
}

// SetDesired accepts only an actual private IPv4 gateway address from the
// ownership-projected desired state. There is no default pool/address fallback.
func (r *Runtime) SetDesired(prefix string) {
	address := privateGatewayIPv4(prefix)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.desired != address {
		r.desired = address
		r.closeLocked()
	}
}

// Status is local listener readiness, independent of whether HTTP is currently
// allowed or any user is granted a model; those checks run on every request.
func (r *Runtime) Status() (bool, string) {
	if r == nil {
		return false, ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current == nil {
		return false, ""
	}
	return true, r.current.address.String()
}

func (r *Runtime) Run(ctx context.Context) {
	defer r.Close()
	r.Reconcile(ctx)
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

// Reconcile closes on any unreadable interface state rather than keeping a
// stale listener. Interface index changes also require a new SO_BINDTODEVICE
// socket, even if the replacement interface reuses the same name and address.
func (r *Runtime) Reconcile(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || ctx.Err() != nil || !r.desired.IsValid() || !r.healthy() {
		r.closeLocked()
		return
	}
	index, err := r.observe(ctx, r.iface, r.desired)
	if err != nil || index <= 0 {
		r.closeLocked()
		return
	}
	if r.current != nil && r.current.index == index && r.current.address == r.desired {
		return
	}
	r.closeLocked()
	addr := r.desired
	listener, err := r.listen(ctx, r.iface, net.JoinHostPort(addr.String(), HTTPPort))
	if err != nil {
		r.logger.Warn("ai_vpn_bind_unavailable")
		return
	}
	// Fail closed if the interface was replaced or lost during socket creation.
	readback, err := r.observe(ctx, r.iface, addr)
	if err != nil || readback != index || ctx.Err() != nil || !r.healthy() {
		_ = listener.Close()
		return
	}
	b := &binding{index: index, address: addr, listener: listener}
	b.server = &http.Server{
		Handler:           HTTPHandler(addr.String(), r.target, r.transport, func(ctx context.Context) (string, error) { return r.peers(ctx, r.iface) }),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 35 * time.Second,
		WriteTimeout: 40 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	r.current = b
	r.changed()
	r.logger.Info("ai_vpn_listener_ready", "interface", r.iface, "address", addr.String())
	go func() {
		serveErr := b.server.Serve(listener)
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.current == b {
			r.current = nil
			_ = b.server.Close()
			r.changed()
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				r.logger.Warn("ai_vpn_listener_stopped")
			}
		}
	}()
}

func (r *Runtime) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.closeLocked()
}

// The native backend accepts comma-separated dual-stack interface addresses.
// Select its one private IPv4 host address, preserving the host bits; an invalid
// address list or multiple IPv4 candidates must not produce a guessed endpoint.
func privateGatewayIPv4(addresses string) netip.Addr {
	var selected netip.Addr
	for _, raw := range strings.Split(addresses, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || prefix.Addr().Is4In6() {
			return netip.Addr{}
		}
		if prefix.Addr().Is4() {
			if selected.IsValid() || !prefix.Addr().IsPrivate() {
				return netip.Addr{}
			}
			selected = prefix.Addr()
		}
	}
	return selected
}

func (r *Runtime) closeLocked() {
	if r.current != nil {
		b := r.current
		r.current = nil
		// Close the raw listener too: Server.Serve may not yet have registered
		// it when withdrawal races the new serving goroutine.
		_ = b.listener.Close()
		_ = b.server.Close() // also cancels in-flight requests on withdrawal
		r.changed()
	}
}

// notify must be non-blocking; production coalesces readiness changes into the
// existing capability-report kick channel.
func (r *Runtime) changed() {
	if r.notify != nil {
		r.notify()
	}
}
