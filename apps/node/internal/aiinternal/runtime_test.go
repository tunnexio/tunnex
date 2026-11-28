package aiinternal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/control"
)

type fakeChannel struct {
	t       *testing.T
	ca      *testCA
	mu      sync.Mutex
	doc     control.AIInternalDesired
	err     error
	signErr error
	csrs    []string
}

func (f *fakeChannel) AIInternalDesiredState(context.Context) (control.AIInternalDesired, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.doc, f.err
}

func (f *fakeChannel) AIInternalSign(_ context.Context, csr string) (control.AIInternalCertificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.csrs = append(f.csrs, csr)
	if f.signErr != nil {
		return control.AIInternalCertificate{}, f.signErr
	}
	return f.ca.sign(f.t, csr), nil
}

func (f *fakeChannel) set(doc control.AIInternalDesired, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.doc, f.err = doc, err
}

type harness struct {
	rt       *Runtime
	ch       *fakeChannel
	mu       sync.Mutex
	owned    map[netip.Addr]bool
	now      time.Time
	listens  []string
	sockets  map[string]net.Listener
	serving  [][]netip.Addr
	ports    []int
	notifies int
}

func newHarness(t *testing.T, mutate func(*Config)) *harness {
	t.Helper()
	h := &harness{ch: &fakeChannel{t: t, ca: newTestCA(t), doc: validDoc()}, now: time.Now(), sockets: map[string]net.Listener{},
		owned: map[netip.Addr]bool{netip.MustParseAddr("10.123.0.1"): true, netip.MustParseAddr("192.168.10.5"): true}}
	cfg := Config{
		Control: h.ch, Target: &url.URL{Scheme: "https", Host: "control.test"}, Transport: http.DefaultTransport,
		Notify: func() { h.mu.Lock(); h.notifies++; h.mu.Unlock() },
		Serving: func(addrs []netip.Addr, port int) {
			h.mu.Lock()
			h.serving, h.ports = append(h.serving, addrs), append(h.ports, port)
			h.mu.Unlock()
		},
		Owned: func(a netip.Addr) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			if !h.owned[a] {
				return errors.New("not owned")
			}
			return nil
		},
		Listen: func(_ context.Context, address string) (net.Listener, error) {
			l, err := net.Listen("tcp4", "127.0.0.1:0")
			if err == nil {
				h.mu.Lock()
				h.listens = append(h.listens, address)
				h.sockets[address] = l
				h.mu.Unlock()
			}
			return l, err
		},
		Now: func() time.Time { h.mu.Lock(); defer h.mu.Unlock(); return h.now },
	}
	if mutate != nil {
		mutate(&cfg)
	}
	h.rt = NewRuntime(cfg)
	t.Cleanup(h.rt.Close)
	return h
}

func (h *harness) step(t *testing.T) Status {
	t.Helper()
	h.rt.Poll(t.Context())
	h.rt.Reconcile(t.Context())
	return h.rt.Status()
}

func (h *harness) setOwned(a string, owned bool) {
	h.mu.Lock()
	h.owned[netip.MustParseAddr(a)] = owned
	h.mu.Unlock()
}

func (h *harness) advance(d time.Duration) {
	h.mu.Lock()
	h.now = h.now.Add(d)
	h.mu.Unlock()
}

// socketOpen reports whether the socket the runtime bound for address still accepts connections.
func (h *harness) socketOpen(t *testing.T, address string) bool {
	t.Helper()
	h.mu.Lock()
	l := h.sockets[address]
	h.mu.Unlock()
	if l == nil {
		return false
	}
	conn, err := net.DialTimeout("tcp4", l.Addr().String(), time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func TestRuntimeServesTheConfiguredEndpointWithAnIssuedLeaf(t *testing.T) {
	h := newHarness(t, nil)
	s := h.step(t)
	if !s.Ready || !slices.Equal(s.Addresses, []string{"10.123.0.1", "192.168.10.5"}) || s.Port != 9443 || s.Revision != 3 || s.Error != "" {
		t.Fatalf("status: %+v", s)
	}
	if s.CertSHA256 == "" || len(s.CertSHA256) != 64 || s.CertNotAfter == "" {
		t.Fatalf("certificate status: %+v", s)
	}
	if _, err := time.Parse(time.RFC3339, s.CertNotAfter); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(h.listens, []string{"10.123.0.1:9443", "192.168.10.5:9443"}) {
		t.Fatalf("listened on %v", h.listens)
	}
	if len(h.serving) != 1 || len(h.serving[0]) != 2 || h.ports[0] != 9443 {
		t.Fatalf("serving: %v %v", h.serving, h.ports)
	}
	if h.notifies == 0 {
		t.Fatal("readiness did not notify")
	}
	if len(h.ch.csrs) != 1 {
		t.Fatalf("%d CSRs", len(h.ch.csrs))
	}
	// A steady state neither re-issues nor rebinds nor notifies.
	notifies := h.notifies
	h.step(t)
	if len(h.ch.csrs) != 1 || len(h.listens) != 2 || h.notifies != notifies {
		t.Fatalf("steady state changed: csrs=%d listens=%d notifies=%d", len(h.ch.csrs), len(h.listens), h.notifies)
	}
}

func TestRuntimeClosesWhenTheAddressLeavesTheInterface(t *testing.T) {
	h := newHarness(t, nil)
	h.step(t)
	if !h.socketOpen(t, "192.168.10.5:9443") {
		t.Fatal("not listening")
	}
	h.setOwned("192.168.10.5", false)
	h.rt.Reconcile(t.Context())
	s := h.rt.Status()
	if s.Ready || !slices.Equal(s.Addresses, []string{"10.123.0.1"}) || s.Error != ErrCodeAddressNotOwned {
		t.Fatalf("status: %+v", s)
	}
	if h.socketOpen(t, "192.168.10.5:9443") {
		t.Fatal("the socket outlived its address")
	}
	if !h.socketOpen(t, "10.123.0.1:9443") {
		t.Fatal("the other address was closed too")
	}
	h.setOwned("192.168.10.5", true)
	h.rt.Reconcile(t.Context())
	if s := h.rt.Status(); !s.Ready || len(s.Addresses) != 2 {
		t.Fatalf("not rebound: %+v", s)
	}
}

func TestRuntimeStopsOnADefinitiveAnswer(t *testing.T) {
	for name, set := range map[string]func(*fakeChannel){
		"404 (an older control plane)": func(f *fakeChannel) {
			f.set(control.AIInternalDesired{}, fmt.Errorf("%w: status 404", control.ErrAIInternalOff))
		},
		"refused node": func(f *fakeChannel) {
			f.set(control.AIInternalDesired{}, fmt.Errorf("%w: status 403", control.ErrAIInternalOff))
		},
		"endpoint removed":    func(f *fakeChannel) { f.set(control.AIInternalDesired{Version: 1}, nil) },
		"invalid document":    func(f *fakeChannel) { d := validDoc(); d.Endpoint.Port = 8083; f.set(d, nil) },
		"unknown version":     func(f *fakeChannel) { d := validDoc(); d.Version = 2; f.set(d, nil) },
		"public source range": func(f *fakeChannel) { d := validDoc(); d.Endpoint.SourceCIDRs = []string{"0.0.0.0/0"}; f.set(d, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, nil)
			if s := h.step(t); !s.Ready {
				t.Fatalf("not serving first: %+v", s)
			}
			set(h.ch)
			s := h.step(t)
			if s.Ready || len(s.Addresses) != 0 || s.Port != 0 || s.Revision != 0 || s.CertSHA256 != "" {
				t.Fatalf("still serving: %+v", s)
			}
			if h.socketOpen(t, "10.123.0.1:9443") || h.socketOpen(t, "192.168.10.5:9443") {
				t.Fatal("a socket outlived the endpoint")
			}
			last := len(h.serving) - 1
			if h.serving[last] != nil || h.ports[last] != 0 {
				t.Fatalf("the input chain still accepts: %v %v", h.serving, h.ports)
			}
			wantErr := ""
			if name == "invalid document" || name == "unknown version" || name == "public source range" {
				wantErr = ErrCodeInvalidDesired
			}
			if s.Error != wantErr {
				t.Fatalf("error=%q want %q", s.Error, wantErr)
			}
		})
	}
}

func TestRuntimeNeverListensWithoutAnEndpoint(t *testing.T) {
	h := newHarness(t, nil)
	h.ch.set(control.AIInternalDesired{}, fmt.Errorf("%w: status 404", control.ErrAIInternalOff))
	s := h.step(t)
	if s.Ready || len(h.listens) != 0 || len(h.ch.csrs) != 0 || s.Addresses == nil {
		t.Fatalf("status=%+v listens=%v csrs=%d", s, h.listens, len(h.ch.csrs))
	}
}

func TestRuntimeKeepsServingThroughAShortOutageOnly(t *testing.T) {
	h := newHarness(t, nil)
	h.step(t)
	h.ch.set(control.AIInternalDesired{}, errors.New("dial tcp: connection refused"))
	h.advance(30 * time.Second)
	s := h.step(t)
	if !s.Ready || s.Error != ErrCodeDesiredUnavailable {
		t.Fatalf("a short outage stopped the listener: %+v", s)
	}
	h.advance(31 * time.Second)
	s = h.step(t)
	if s.Ready || len(s.Addresses) != 0 || s.Error != ErrCodeDesiredUnavailable {
		t.Fatalf("a long outage kept the listener: %+v", s)
	}
	h.ch.set(validDoc(), nil)
	if s := h.step(t); !s.Ready || s.Error != "" {
		t.Fatalf("not back after the outage: %+v", s)
	}
}

func TestRuntimeDoesNotListenWithoutACertificate(t *testing.T) {
	h := newHarness(t, nil)
	h.ch.signErr = errors.New("internal AI certificate status 409")
	s := h.step(t)
	if s.Ready || len(h.listens) != 0 || s.Error != ErrCodeCertificate {
		t.Fatalf("status=%+v listens=%v", s, h.listens)
	}
}

func TestRuntimeReissuesWhenTheRevisionChangesTheSANs(t *testing.T) {
	h := newHarness(t, nil)
	first := h.step(t)
	d := validDoc()
	d.Endpoint.Revision = 4
	d.Endpoint.ListenAddresses = []string{"10.123.0.1"}
	h.ch.set(d, nil)
	s := h.step(t)
	if len(h.ch.csrs) != 1 || !s.Ready || s.Revision != 4 || !slices.Equal(s.Addresses, []string{"10.123.0.1"}) || s.CertSHA256 != first.CertSHA256 {
		t.Fatalf("a narrower address set must keep the covering leaf: csrs=%d %+v", len(h.ch.csrs), s)
	}
	if h.socketOpen(t, "192.168.10.5:9443") {
		t.Fatal("the removed address still listens")
	}
	d.Endpoint.Revision = 5
	d.Endpoint.DNSName = "gw.internal.example"
	h.ch.set(d, nil)
	s = h.step(t)
	if len(h.ch.csrs) != 2 || !s.Ready || s.Revision != 5 || s.CertSHA256 == first.CertSHA256 {
		t.Fatalf("a new name did not re-issue: csrs=%d %+v", len(h.ch.csrs), s)
	}
}

func TestRuntimeRenewsWithAThirdOfTheLifeLeft(t *testing.T) {
	h := newHarness(t, nil)
	first := h.step(t)
	h.advance(15 * 24 * time.Hour)
	h.rt.Poll(t.Context())
	if len(h.ch.csrs) != 1 {
		t.Fatal("renewed at half life")
	}
	h.advance(6 * 24 * time.Hour) // 21 of 30 days gone: less than a third left
	// A refused renewal keeps the leaf that is still valid and reports the problem.
	h.ch.signErr = errors.New("internal AI certificate status 503")
	s := h.step(t)
	if len(h.ch.csrs) != 2 || !s.Ready || s.CertSHA256 != first.CertSHA256 || s.Error != ErrCodeCertificate {
		t.Fatalf("a failed renewal: csrs=%d %+v", len(h.ch.csrs), s)
	}
	h.ch.signErr = nil
	s = h.step(t)
	if len(h.ch.csrs) != 3 || !s.Ready || s.CertSHA256 == first.CertSHA256 || s.Error != "" {
		t.Fatalf("no renewal with a third left: csrs=%d %+v", len(h.ch.csrs), s)
	}
	// The listener keeps its sockets across a renewal; the next handshake gets the new leaf.
	if len(h.listens) != 2 {
		t.Fatalf("a renewal rebound the sockets: %v", h.listens)
	}
	h.rt.mu.Lock()
	conf := h.rt.tlsConf
	h.rt.mu.Unlock()
	cert, err := conf.GetCertificate(&tls.ClientHelloInfo{ServerName: "ai.internal.example"})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.Certificate[0])
	if hex.EncodeToString(sum[:]) != s.CertSHA256 {
		t.Fatal("the handshake serves another leaf than the one reported")
	}
	if _, err := conf.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example"}); err == nil {
		t.Fatal("the runtime served an unexpected SNI")
	}
}

func TestRuntimeCustomModeReadsTheOperatorFiles(t *testing.T) {
	dir := t.TempDir()
	h := newHarness(t, func(c *Config) { c.CertDir = dir })
	d := validDoc()
	d.Endpoint.TLSMode = TLSModeCustom
	h.ch.set(d, nil)
	if s := h.step(t); s.Ready || s.Error != ErrCodeCustomCertificate || len(h.listens) != 0 {
		t.Fatalf("listening without files: %+v", s)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	ips := []net.IP{net.ParseIP("10.123.0.1"), net.ParseIP("192.168.10.5")}
	writeCustom(t, dir, h.ch.ca.leaf(t, &key.PublicKey, ips, []string{"ai.internal.example"}, now.Add(-time.Minute), now.Add(time.Hour)), key, 0o644)
	if s := h.step(t); s.Ready || s.Error != ErrCodeCustomKeyMode {
		t.Fatalf("a world-readable key was served: %+v", s)
	}
	writeCustom(t, dir, h.ch.ca.leaf(t, &key.PublicKey, ips, []string{"ai.internal.example"}, now.Add(-time.Minute), now.Add(time.Hour)), key, 0o600)
	s := h.step(t)
	if !s.Ready || s.Error != "" || s.CertSHA256 == "" || len(h.ch.csrs) != 0 {
		t.Fatalf("custom: %+v csrs=%d", s, len(h.ch.csrs))
	}
	writeCustom(t, dir, h.ch.ca.leaf(t, &key.PublicKey, ips[:1], nil, now.Add(-time.Minute), now.Add(time.Hour)), key, 0o600)
	if s := h.step(t); !s.Ready || s.Error != ErrCodeCustomNotCovering {
		t.Fatalf("a non-covering custom certificate is reported, not refused: %+v", s)
	}
	_ = os.Remove(dir + "/" + customKeyFile)
	if s := h.step(t); s.Ready || len(s.Addresses) != 0 {
		t.Fatalf("serving after the key was removed: %+v", s)
	}
}

func TestRuntimeCloseWithdrawsTheInputChain(t *testing.T) {
	h := newHarness(t, nil)
	h.step(t)
	h.rt.Close()
	if s := h.rt.Status(); s.Ready || len(s.Addresses) != 0 {
		t.Fatalf("status after close: %+v", s)
	}
	if h.serving[len(h.serving)-1] != nil {
		t.Fatal("close left the input chain open")
	}
	h.rt.Reconcile(t.Context())
	h.rt.Poll(t.Context())
	if s := h.rt.Status(); s.Ready || len(s.Addresses) != 0 {
		t.Fatalf("rebound after close: %+v", s)
	}
}

func TestRuntimeKickNeverBlocksAndNilIsSafe(t *testing.T) {
	var nilRuntime *Runtime
	nilRuntime.Kick()
	nilRuntime.Close()
	if s := nilRuntime.Status(); s.Ready {
		t.Fatal("a nil runtime is ready")
	}
	h := newHarness(t, nil)
	for i := 0; i < 5; i++ {
		h.rt.Kick()
	}
}
