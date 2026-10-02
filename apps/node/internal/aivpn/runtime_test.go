package aivpn

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"testing"
	"time"
)

type testListener struct {
	closed chan struct{}
	once   sync.Once
}

func newTestListener() *testListener              { return &testListener{closed: make(chan struct{})} }
func (l *testListener) Accept() (net.Conn, error) { <-l.closed; return nil, net.ErrClosed }
func (l *testListener) Close() error              { l.once.Do(func() { close(l.closed) }); return nil }
func (*testListener) Addr() net.Addr              { return &net.TCPAddr{IP: net.ParseIP("10.77.0.9"), Port: 8083} }
func (l *testListener) isClosed() bool {
	select {
	case <-l.closed:
		return true
	default:
		return false
	}
}

type runtimeHarness struct {
	r          *Runtime
	healthy    bool
	index      int
	observeErr error
	bindErr    error
	listeners  []*testListener
	changes    chan struct{}
}

func newRuntimeHarness(t *testing.T) *runtimeHarness {
	t.Helper()
	h := &runtimeHarness{healthy: true, index: 7, changes: make(chan struct{}, 20)}
	target, _ := url.Parse("https://control.test:8443")
	h.r = NewRuntime("vpn-test", target, roundTrip(func(*http.Request) (*http.Response, error) { return nil, errors.New("no request expected") }), func() bool { return h.healthy }, func() { h.changes <- struct{}{} }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.r.observe = func(_ context.Context, iface string, addr netip.Addr) (int, error) {
		if iface != "vpn-test" || addr != netip.MustParseAddr("10.77.0.9") {
			t.Fatalf("untrusted interface/address: %s %s", iface, addr)
		}
		return h.index, h.observeErr
	}
	h.r.listen = func(_ context.Context, iface, addr string) (net.Listener, error) {
		if iface != "vpn-test" || addr != "10.77.0.9:8083" {
			t.Fatalf("untrusted bind: %s %s", iface, addr)
		}
		if h.bindErr != nil {
			return nil, h.bindErr
		}
		l := newTestListener()
		h.listeners = append(h.listeners, l)
		return l, nil
	}
	t.Cleanup(h.r.Close)
	return h
}
func requireStatus(t *testing.T, r *Runtime, want bool) {
	t.Helper()
	ready, address := r.Status()
	if ready != want || (want && address != "10.77.0.9") || (!want && address != "") {
		t.Fatalf("readiness=%v address=%q, want ready=%v", ready, address, want)
	}
}

func TestRuntimeRequiresDesiredHealthyLiveInterfaceAndActualBind(t *testing.T) {
	h := newRuntimeHarness(t)
	h.r.Reconcile(t.Context())
	requireStatus(t, h.r, false)
	if len(h.listeners) != 0 {
		t.Fatal("guessed a default address")
	}
	h.r.SetDesired("10.77.0.9/24, fd77::9/64")
	h.healthy = false
	h.r.Reconcile(t.Context())
	requireStatus(t, h.r, false)
	h.healthy = true
	h.observeErr = errors.New("missing interface")
	h.r.Reconcile(t.Context())
	requireStatus(t, h.r, false)
	h.observeErr = nil
	h.bindErr = errors.New("interface bind failed")
	h.r.Reconcile(t.Context())
	requireStatus(t, h.r, false)
	h.bindErr = nil
	h.r.Reconcile(t.Context())
	requireStatus(t, h.r, true)
	h.r.Reconcile(t.Context())
	if len(h.listeners) != 1 {
		t.Fatal("stable listener was needlessly replaced")
	}
}

func TestRuntimeWithdrawsOnAddressInterfaceAndHealthLoss(t *testing.T) {
	for _, cause := range []string{"address removed", "interface unreadable", "unhealthy", "interface replaced"} {
		t.Run(cause, func(t *testing.T) {
			h := newRuntimeHarness(t)
			h.r.SetDesired("10.77.0.9/24")
			h.r.Reconcile(t.Context())
			requireStatus(t, h.r, true)
			switch cause {
			case "address removed":
				h.r.SetDesired("")
			case "interface unreadable":
				h.observeErr = errors.New("cannot read interface")
			case "unhealthy":
				h.healthy = false
			case "interface replaced":
				h.index = 8
			}
			h.r.Reconcile(t.Context())
			if !h.listeners[0].isClosed() {
				t.Fatal("old interface socket retained")
			}
			requireStatus(t, h.r, cause == "interface replaced")
			if cause == "interface replaced" && len(h.listeners) != 2 {
				t.Fatal("replacement interface needs a new device-bound socket")
			}
		})
	}
}

func TestRuntimeFailsClosedWhenInterfaceChangesDuringBind(t *testing.T) {
	h := newRuntimeHarness(t)
	h.r.SetDesired("10.77.0.9/24")
	listen := h.r.listen
	h.r.listen = func(ctx context.Context, iface, addr string) (net.Listener, error) {
		l, err := listen(ctx, iface, addr)
		h.index++
		return l, err
	}
	h.r.Reconcile(t.Context())
	requireStatus(t, h.r, false)
	if len(h.listeners) != 1 || !h.listeners[0].isClosed() {
		t.Fatal("socket survived an interface-generation mismatch")
	}
}

func TestRuntimeClosePermanentlyPreventsRebind(t *testing.T) {
	h := newRuntimeHarness(t)
	h.r.SetDesired("10.77.0.9/24")
	h.r.Reconcile(t.Context())
	h.r.Close()
	h.r.SetDesired("fd77::9/64,10.77.0.9/24")
	h.r.Reconcile(t.Context())
	requireStatus(t, h.r, false)
	if len(h.listeners) != 1 || !h.listeners[0].isClosed() {
		t.Fatal("closed runtime reopened a listener")
	}
}

func TestRuntimeServeFailureWithdrawsThenCanRecover(t *testing.T) {
	h := newRuntimeHarness(t)
	h.r.SetDesired("10.77.0.9/24")
	h.r.Reconcile(t.Context())
	<-h.changes // first bind
	_ = h.listeners[0].Close()
	select {
	case <-h.changes:
	case <-time.After(3 * time.Second):
		t.Fatal("serve exit did not withdraw readiness")
	}
	requireStatus(t, h.r, false)
	h.r.Reconcile(t.Context())
	requireStatus(t, h.r, true)
	if len(h.listeners) != 2 {
		t.Fatal("serve failure was not recoverable")
	}
}

func TestRuntimeContextCancellationClosesListener(t *testing.T) {
	h := newRuntimeHarness(t)
	h.r.SetDesired("10.77.0.9/24")
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { h.r.Run(ctx); close(done) }()
	select {
	case <-h.changes:
	case <-time.After(3 * time.Second):
		t.Fatal("listener did not start")
	}
	requireStatus(t, h.r, true)
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("listener did not stop")
	}
	requireStatus(t, h.r, false)
	h.r.Reconcile(t.Context())
	if len(h.listeners) != 1 || !h.listeners[0].isClosed() {
		t.Fatal("canceled runtime retained/reopened a socket")
	}
}

func TestGatewayAddressSelectionIsPrivateUnambiguousAndDualStack(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"10.77.0.9/24", "10.77.0.9"},
		{"10.77.0.9/24,fd77::9/64", "10.77.0.9"},
		{" fd77::9/64, 10.77.0.9/24 ", "10.77.0.9"},
		{"", ""}, {"fd77::9/64", ""}, {"13.48.70.248/32", ""}, {"0.0.0.0/0", ""},
		{"10.77.0.9/24,10.88.0.1/24", ""}, {"10.77.0.9/24,10.77.0.9/24", ""},
		{"10.77.0.9/24,broken", ""}, {"::ffff:10.77.0.9/128", ""},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got := privateGatewayIPv4(tc.input)
			if tc.want == "" {
				if got.IsValid() {
					t.Fatalf("accepted %s", got)
				}
			} else if got.String() != tc.want {
				t.Fatalf("selected=%s want=%s", got, tc.want)
			}
		})
	}
}
