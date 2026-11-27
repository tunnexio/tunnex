package mcpgw

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/aivpn"
	"github.com/tunnexio/tunnex/packages/apptransport/mcpwire"
)

type idleListener struct {
	closed chan struct{}
	once   sync.Once
}

func (l *idleListener) Accept() (net.Conn, error) { <-l.closed; return nil, net.ErrClosed }
func (l *idleListener) Close() error              { l.once.Do(func() { close(l.closed) }); return nil }
func (*idleListener) Addr() net.Addr              { return &net.TCPAddr{IP: net.ParseIP("10.99.0.1"), Port: 8084} }

type runtimeHarness struct {
	r       *Runtime
	control *fakeControl
	mu      sync.Mutex
	bindErr error
	bound   []string
	changes chan struct{}
}

func newRuntimeHarness(t *testing.T) *runtimeHarness {
	t.Helper()
	h := &runtimeHarness{control: newFakeControl(nil), changes: make(chan struct{}, 16)}
	h.r = newRuntime(aivpn.ListenerConfig{
		Interface: "wg-test", Healthy: func() bool { return true }, Logger: quiet,
		Notify:  func() { h.changes <- struct{}{} },
		Observe: func(context.Context, string, netip.Addr) (int, error) { return 7, nil },
		Peers:   func(context.Context, string) (string, error) { return peer + "\t" + agentIP + "/32", nil },
		Listen: func(_ context.Context, iface, address string) (net.Listener, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			if h.bindErr != nil {
				return nil, h.bindErr
			}
			h.bound = append(h.bound, iface+" "+address)
			return &idleListener{closed: make(chan struct{})}, nil
		},
	}, h.control, NewUpstreamTransport())
	t.Cleanup(h.r.Close)
	return h
}

// The capability is true only while the listener is actually bound: to the WireGuard interface, on the
// projected tunnel address, on the contract's port.
func TestRuntimeIsReadyOnlyWhileTheListenerIsBound(t *testing.T) {
	if mcpwire.ListenerPort != 8084 {
		t.Fatalf("listener port %d", mcpwire.ListenerPort)
	}
	h := newRuntimeHarness(t)
	if ready, address := h.r.Status(); ready || address != "" {
		t.Fatal("ready before any address was projected")
	}
	h.bindErr = errors.New("bind failed")
	h.r.SetDesired("10.99.0.1/24")
	h.r.listener.Reconcile(t.Context())
	if ready, address := h.r.Status(); ready || address != "" {
		t.Fatal("ready although the bind failed")
	}
	h.bindErr = nil
	h.r.listener.Reconcile(t.Context())
	if ready, address := h.r.Status(); !ready || address != "10.99.0.1" {
		t.Fatalf("ready=%v address=%q", ready, address)
	}
	if len(h.bound) != 1 || h.bound[0] != "wg-test 10.99.0.1:8084" {
		t.Fatalf("bound: %v", h.bound)
	}
	h.r.SetDesired("")
	h.r.listener.Reconcile(t.Context())
	if ready, address := h.r.Status(); ready || address != "" {
		t.Fatal("ready after the address was withdrawn")
	}
	// A public or ambiguous address is never bound.
	for _, prefix := range []string{"203.0.113.4/24", "10.99.0.1/24,10.88.0.1/24", "fd99::1/64"} {
		h.r.SetDesired(prefix)
		h.r.listener.Reconcile(t.Context())
		if ready, _ := h.r.Status(); ready {
			t.Fatalf("bound to %s", prefix)
		}
	}
	var none *Runtime
	none.SetDesired("10.99.0.1/24")
	none.Close()
	if ready, address := none.Status(); ready || address != "" {
		t.Fatal("an absent runtime reports the capability")
	}
}

// Discovery runs once the listener is bound, and not before.
func TestRuntimeDiscoversOnlyWhileBound(t *testing.T) {
	server := newFakeMCP(t, func(f *fakeMCP) { f.pages = map[string]string{"": twoTools} })
	h := newRuntimeHarness(t)
	h.control.targets = []mcpwire.Target{{DeviceID: "agent-a", VPNIP: agentIP, Endpoint: server.server.URL}}
	h.r.passes = make(chan struct{}, 4)
	h.r.interval = time.Hour
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { h.r.Run(ctx); close(done) }()
	select {
	case <-h.r.passes:
		t.Fatal("discovery ran with no listener")
	case <-time.After(1500 * time.Millisecond):
	}
	if server.count("initialize") != 0 {
		t.Fatal("the MCP server was contacted with no listener")
	}
	h.r.SetDesired("10.99.0.1/24")
	select {
	case <-h.r.passes:
	case <-time.After(5 * time.Second):
		t.Fatal("no discovery pass after the listener was bound")
	}
	h.control.mu.Lock()
	reports := append([]mcpwire.InventoryReport(nil), h.control.reports...)
	h.control.mu.Unlock()
	if len(reports) != 1 || reports[0].DeviceID != "agent-a" || reports[0].Status != statusHealthy || len(reports[0].Tools) != 2 {
		t.Fatalf("reports: %+v", reports)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the runtime did not stop")
	}
}
