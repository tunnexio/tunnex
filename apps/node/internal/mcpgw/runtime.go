package mcpgw

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/aivpn"
	"github.com/tunnexio/tunnex/packages/apptransport/mcpwire"
)

// Runtime owns the gateway's MCP listener and the discovery of the MCP servers behind it.
//
// The listener has the AI listener's lifecycle (aivpn.NewListenerRuntime): bound with SO_BINDTODEVICE to
// the WireGuard interface on the gateway's own private tunnel address, TCP mcpwire.ListenerPort, present
// only while that address is the projected one and the kernel WireGuard device is live, and closed on
// any doubt. It has no host-published port and no setting: it exists whenever the gateway runs the
// kernel WireGuard backend. Discovery runs only while the listener is bound, since the control plane
// sends MCP through this gateway only then.
type Runtime struct {
	listener *aivpn.Runtime
	discover *discoverer
	interval time.Duration
	passes   chan struct{} // test hook: one value per finished discovery pass, never blocking
}

// NewRuntime builds the runtime for the WireGuard interface. notify must not block; it is called when
// listener readiness changes so the capability report follows it.
func NewRuntime(iface string, control Control, healthy func() bool, notify func(), logger *slog.Logger) *Runtime {
	return newRuntime(aivpn.ListenerConfig{Interface: iface, Healthy: healthy, Notify: notify, Logger: logger}, control, NewUpstreamTransport())
}

func newRuntime(cfg aivpn.ListenerConfig, control Control, upstream http.RoundTripper) *Runtime {
	cfg.Port = strconv.Itoa(mcpwire.ListenerPort)
	cfg.Name = "mcp_gateway"
	cfg.ReadTimeout = 35 * time.Second
	// The answer to a tool call may be a stream; the relay bounds a call at maxCallDuration itself.
	cfg.WriteTimeout = maxCallDuration + 10*time.Second
	logger := cfg.Logger
	cfg.Handler = func(address string, peers aivpn.KernelPeers) http.Handler {
		return Handler(address, control, upstream, peers, logger)
	}
	return &Runtime{
		listener: aivpn.NewListenerRuntime(cfg),
		discover: &discoverer{control: control, upstream: upstream, logger: logger},
		interval: DiscoveryInterval,
	}
}

// SetDesired takes the ownership-projected interface address; anything else withdraws the listener.
func (r *Runtime) SetDesired(prefix string) {
	if r != nil {
		r.listener.SetDesired(prefix)
	}
}

// Status is the capability the gateway reports: ready only while the listener is actually bound, and
// then the IPv4 tunnel address it is bound to (without the port).
func (r *Runtime) Status() (bool, string) {
	if r == nil {
		return false, ""
	}
	return r.listener.Status()
}

// Run serves until ctx ends: the listener reconciles every second, and a discovery pass runs as soon as
// the listener is bound and then every interval while it stays bound.
func (r *Runtime) Run(ctx context.Context) {
	go r.listener.Run(ctx)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var next time.Time
	for {
		if ready, _ := r.Status(); ready && !time.Now().Before(next) {
			r.discover.pass(ctx)
			next = time.Now().Add(r.interval)
			if r.passes != nil {
				select {
				case r.passes <- struct{}{}:
				default:
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Close withdraws the listener for good.
func (r *Runtime) Close() {
	if r != nil {
		r.listener.Close()
	}
}
