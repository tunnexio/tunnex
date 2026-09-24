package ipsec

import (
	"bytes"
	"context"
	"errors"
	"github.com/google/uuid"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var ErrRuntimeProbe = errors.New("IPsec platform probe unavailable")

type runtimeClock struct{ Boot, Monotonic time.Duration }

// RuntimePlatformQualification records actual current-process observations.
// It is not packet qualification, installation authority, or a capability flag.
// Resume/clock discontinuity permanently invalidates this receipt.
type RuntimePlatformQualification struct {
	mu            sync.Mutex
	namespace     string
	baseline      runtimeClock
	last          runtimeClock
	readNamespace func() (string, error)
	readClock     func() (runtimeClock, error)
	alive         func() bool
	invalid       bool
}

func (q *RuntimePlatformQualification) current() bool {
	if q == nil {
		return false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.invalid || q.readNamespace == nil || q.readClock == nil || q.alive == nil {
		return false
	}
	ns, e := q.readNamespace()
	reading, ce := q.readClock()
	delta := (reading.Boot - reading.Monotonic) - (q.baseline.Boot - q.baseline.Monotonic)
	if e != nil || ce != nil || ns != q.namespace || !validKernelNamespace(ns) || !q.alive() || reading.Boot < q.baseline.Boot || reading.Monotonic < q.baseline.Monotonic || reading.Boot < q.last.Boot || reading.Monotonic < q.last.Monotonic || delta > 100*time.Millisecond || delta < -100*time.Millisecond {
		q.invalid = true
		return false
	}
	q.last = reading
	return true
}

type runtimePlatformProbe struct {
	namespace                                                   func() (string, error)
	clock                                                       func() (runtimeClock, error)
	alive                                                       func() bool
	packaged, daemon, kernel, xfrm, environment, nft, privilege func(context.Context) error
}

func (p runtimePlatformProbe) probe(ctx context.Context) (*RuntimePlatformQualification, error) {
	if p.namespace == nil || p.clock == nil || p.alive == nil || ctx.Err() != nil {
		return nil, ErrRuntimeProbe
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ns, e := p.namespace()
	clock, ce := p.clock()
	if e != nil || ce != nil || !validKernelNamespace(ns) || !p.alive() {
		return nil, ErrRuntimeProbe
	}
	for _, step := range []func(context.Context) error{p.privilege, p.packaged, p.daemon, p.kernel, p.xfrm, p.environment, p.nft} {
		if step == nil || step(ctx) != nil || ctx.Err() != nil {
			return nil, ErrRuntimeProbe
		}
	}
	receipt := &RuntimePlatformQualification{namespace: ns, baseline: clock, readNamespace: p.namespace, readClock: p.clock, alive: p.alive}
	if !receipt.current() {
		return nil, ErrRuntimeProbe
	}
	return receipt, nil
}

// ProbeRuntimePlatform performs bounded read-only observation and nft check-mode
// validation. The check transaction is never installed. Actual guarded controller
// apply/readback and native packet qualification remain separate prerequisites.
func ProbeRuntimePlatform(ctx context.Context, ipPath, nftPath string, daemon *DaemonClient, alive func() bool) (*RuntimePlatformQualification, error) {
	p, e := newRuntimePlatformProbe(ipPath, nftPath, daemon, alive)
	if e != nil {
		return nil, e
	}
	return p.probe(ctx)
}
func newRuntimePlatformProbe(ipPath, nftPath string, daemon *DaemonClient, alive func() bool) (runtimePlatformProbe, error) {
	if !filepath.IsAbs(ipPath) || !filepath.IsAbs(nftPath) || daemon == nil || alive == nil {
		return runtimePlatformProbe{}, ErrRuntimeProbe
	}
	kernel, e := NewKernelReader(ipPath)
	if e != nil {
		return runtimePlatformProbe{}, ErrRuntimeProbe
	}
	xfrm, e := NewXFRMReader(ipPath)
	if e != nil {
		return runtimePlatformProbe{}, ErrRuntimeProbe
	}
	namespace := func() (string, error) { return os.Readlink("/proc/self/ns/net") }
	p := runtimePlatformProbe{namespace: namespace, clock: readRuntimeClock, alive: alive, privilege: runtimeProbePrivilege, packaged: runtimeProbePackage}
	p.daemon = func(c context.Context) error {
		inventory, e := daemon.Inspect(c)
		if e != nil || inventory.Version != "6.1.0" || inventory.Daemon != "charon" || !runtimeProbePlugins(inventory.Plugins) {
			return ErrRuntimeProbe
		}
		return nil
	}
	p.kernel = func(c context.Context) error { _, e := kernel.Read(c); return e }
	p.xfrm = func(c context.Context) error { _, e := xfrm.Read(c); return e }
	p.environment = func(c context.Context) error {
		rules, e := runKernelCommand(c, ipPath, "-j", "-4", "rule", "show")
		if e != nil || !runtimeDefaultRules(rules) {
			return ErrRuntimeProbe
		}
		raw, e := runKernelCommand(c, nftPath, "-j", "list", "ruleset")
		if e != nil || !runtimeHookCensus(raw, nil) {
			return ErrRuntimeProbe
		}
		return nil
	}
	p.nft = func(c context.Context) error {
		ns, e := namespace()
		if e != nil {
			return ErrRuntimeProbe
		}
		manifest, e := runtimeProbeManifest(ns)
		if e != nil {
			return ErrRuntimeProbe
		}
		// A unique, check-only table avoids colliding with a retained real guard.
		script := strings.ReplaceAll(manifest.NFTJSON, "tunnex_ipsec", "tx_probe_"+strings.ReplaceAll(uuid.NewString(), "-", ""))
		cmd := exec.CommandContext(c, nftPath, "--check", "-j", "-f", "-")
		cmd.Stdin = bytes.NewBufferString(script)
		cmd.Stderr = io.Discard
		var out kernelOutput
		cmd.Stdout = &out
		cmd.WaitDelay = 250 * time.Millisecond
		if cmd.Run() != nil || c.Err() != nil {
			return ErrRuntimeProbe
		}
		return nil
	}
	return p, nil
}
func runtimeProbeManifest(ns string) (GuardManifest, error) {
	return RenderGuard(GuardIntent{Namespace: ns, OwnerID: uuid.New(), Revision: 1, Connections: []GuardConnection{{ID: uuid.New(), Local: []netip.Prefix{netip.MustParsePrefix("10.250.1.0/24")}, Remote: []netip.Prefix{netip.MustParsePrefix("10.250.2.0/24")}, Tunnels: [2]Ownership{{Namespace: ns, InterfaceName: "tx_probe_a", InterfaceIndex: 10001, XFRMID: 10001}, {Namespace: ns, InterfaceName: "tx_probe_b", InterfaceIndex: 10002, XFRMID: 10002}}, LocalIngressIndices: []int{10003}, PermittedInterfaceIndices: []int{10001}, PermitFor: time.Second, EncryptedEgress: []GuardEncryptedEgress{{TunnelInterfaceIndex: 10001, ReqID: 10001, Peer: netip.MustParseAddr("192.0.2.1"), UnderlayInterfaceIndex: 10004}}, Grants: []GuardGrant{{Source: netip.MustParsePrefix("10.250.1.0/24"), Destination: netip.MustParsePrefix("10.250.2.0/24"), Protocol: GuardTCP, PortLow: 443, PortHigh: 443}}}}})
}

func runtimeProbePlugins(plugins []string) bool {
	// strongSwan registers the built-in daemon feature group as charon.
	if len(plugins) != 8 {
		return false
	}
	seen := map[string]bool{}
	for _, v := range plugins {
		if seen[v] {
			return false
		}
		seen[v] = true
	}
	for _, v := range []string{"charon", "random", "nonce", "openssl", "kdf", "kernel-netlink", "socket-default", "vici"} {
		if !seen[v] {
			return false
		}
	}
	return true
}
