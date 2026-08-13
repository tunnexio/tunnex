package dnsforward

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
)

// errWGIfaceNotFound distinguishes "the wg interface is GONE" from a transient read glitch — the security
// half of the bind reconcile's trichotomy (RR1). Interface-gone must CLOSE the listeners (a departed wg0
// address must never keep a live :53 socket that could later answer on a reassigned public interface); a
// transient error must KEEP them (availability). See reconcileBinds.
var errWGIfaceNotFound = errors.New("dnsforward: wg interface not found")

// ── per-source rate limiting (D2 hygiene) ────────────────────────────────────────────────────────────
// A token bucket per source IP: capacity dnsRateBurst, refilled dnsRatePerSec tokens/sec. now() is
// injectable so the red drives the clock without sleeping.

const (
	dnsRateBurst  = 50 // tokens a single source may spend at once
	dnsRatePerSec = 20 // steady-state queries/sec per source

	// F7: bound the bucket map. An idle bucket refills to FULL, so an evicted source that returns gets a
	// fresh full bucket — eviction is LOSSLESS, which is why a periodic idle-sweep beats an LRU here (no
	// ordering structure, nothing of value dropped). The map size is bounded to sources seen within
	// bucketIdleTTL. Without this a peer varying its source address over the tunnel grows the map to OOM,
	// converting DNS-down into tunnel-down — the exact D2 outcome fail-static exists to prevent.
	bucketIdleTTL    = 10 * time.Minute
	bucketSweepEvery = 1 * time.Minute

	// dnsUDPMax is the read buffer for a single UDP datagram: max so we never SELF-truncate an upstream
	// answer (a short read silently discards the datagram's tail). Oversize-for-the-client answers are
	// handled by the upstream setting TC → our TCP fallback, not by our buffer size.
	dnsUDPMax = 65535
)

// dnsPort is the upstream resolver port (53). A var so the net-level red can point the exchange at a
// fake resolver on an unprivileged port; production never changes it.
var dnsPort uint16 = 53

type bucket struct {
	tokens float64
	last   time.Time
}

// allow consumes one token for src, refilling by elapsed time. now() defaults to time.Now (test-injectable).
func (f *Forwarder) allow(src netip.Addr) bool {
	now := time.Now
	if f.now != nil {
		now = f.now
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	t := now()
	// F7: periodically evict idle buckets BEFORE (re)fetching this source's — a source returning after
	// bucketIdleTTL is swept then recreated fresh (same full-bucket state it would have had anyway).
	if t.Sub(f.lastSweep) >= bucketSweepEvery {
		for k, bk := range f.buckets {
			if t.Sub(bk.last) >= bucketIdleTTL {
				delete(f.buckets, k)
			}
		}
		f.lastSweep = t
	}
	b := f.buckets[src]
	if b == nil {
		b = &bucket{tokens: dnsRateBurst, last: t}
		f.buckets[src] = b
	}
	b.tokens += t.Sub(b.last).Seconds() * dnsRatePerSec
	if b.tokens > dnsRateBurst {
		b.tokens = dnsRateBurst
	}
	b.last = t
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// udpExchange relays a raw query to resolver:53 over UDP; on an upstream TRUNCATED (TC) reply it re-asks
// over TCP for the full record set (F2 — never relay a silently-truncated answer). A timeout/unreachable
// resolver, or a TCP fallback that also fails, returns an error → the caller answers SERVFAIL (fail-static,
// degraded honestly, never wrong).
func udpExchange(resolver netip.Addr, query []byte) ([]byte, error) {
	resp, err := udpQuery(resolver, query)
	if err != nil {
		return nil, err
	}
	if dnsTruncated(resp) {
		tcp, terr := tcpQuery(resolver, query)
		if terr != nil {
			return nil, fmt.Errorf("dnsforward: upstream truncated, tcp fallback failed: %w", terr)
		}
		return tcp, nil
	}
	return resp, nil
}

func udpQuery(resolver netip.Addr, query []byte) ([]byte, error) {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(resolver, dnsPort)))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, dnsUDPMax) // never self-truncate: one Read returns one whole datagram
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// dnsTruncated reads the TC bit (byte 2, 0x02) of a DNS message header without a full parse.
func dnsTruncated(resp []byte) bool { return len(resp) >= 3 && resp[2]&0x02 != 0 }

// tcpQuery does a DNS-over-TCP exchange (RFC 1035 §4.2.2: a 2-byte big-endian length prefix frames both
// the query and the response).
func tcpQuery(resolver netip.Addr, query []byte) ([]byte, error) {
	c, err := net.DialTimeout("tcp", netip.AddrPortFrom(resolver, dnsPort).String(), 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	var pfx [2]byte
	binary.BigEndian.PutUint16(pfx[:], uint16(len(query)))
	if _, err := c.Write(append(pfx[:], query...)); err != nil {
		return nil, err
	}
	var rl [2]byte
	if _, err := io.ReadFull(c, rl[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(rl[:]))
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// wgBindAddrs returns the DNS listen addresses — the wg INTERFACE's own addresses ONLY (D2 bind scope). The
// forwarder must NEVER bind a public interface (an open resolver on a cloud VM is an abuse vector), so the
// bind set is derived from the wg iface alone; a non-wg address can never enter it.
//
// ABSENCE IS DETERMINED FROM A SUCCESSFUL ENUMERATION, NEVER INFERRED FROM A CALL FAILURE — "gone" means
// "enumerated and not there." This is the terminal, un-regressable form of the error≠absence distinction
// (the S8.2 -4/-6 ruling → R6 → RR1 → FF1): net.InterfaceByName conflates "no such interface" with a
// TRANSIENT netlink failure (e.g. RTM_GETLINK ENOBUFS under memory pressure), so classifying its error as
// not-found would re-introduce the R6 availability blip on a glitch. Instead: a failed enumeration is
// TRANSIENT → keep (plain error); a SUCCESSFUL enumeration missing wgIface is genuinely GONE → close
// (errWGIfaceNotFound). The next simplifier meets this sentence.
func wgBindAddrs(wgIface string) ([]netip.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err // enumeration itself failed → TRANSIENT → keep current listeners
	}
	var ifi *net.Interface
	for i := range ifaces {
		if ifaces[i].Name == wgIface {
			ifi = &ifaces[i]
			break
		}
	}
	if ifi == nil {
		// Enumerated successfully and wg0 is not among them → genuinely GONE. SECURITY-relevant: the caller
		// CLOSES its listeners so a departed wg0 address can't keep a live :53 socket that could later
		// answer on a reassigned public interface.
		return nil, errWGIfaceNotFound
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err // interface EXISTS but its addresses are momentarily unreadable → transient → keep
	}
	var out []netip.Addr
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ad, ok := netip.AddrFromSlice(ipn.IP); ok && ad.IsValid() {
				out = append(out, ad.Unmap())
			}
		}
	}
	return out, nil
}

// udpListener is the slice of *net.UDPConn the forwarder needs; an interface so the F1 bind-reconcile red
// can inject a fake listener (no real sockets/interfaces).
type udpListener interface {
	ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error)
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
	Close() error
}

func realListen(addr netip.Addr) (udpListener, error) {
	return net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, dnsPort)))
}

// Serve runs the forwarder's BIND-RECONCILE loop until ctx is done (F1). wg0 does NOT exist at agent boot —
// the reconcile loop creates it later — so a bind-once-at-boot is dead on every fresh gateway. Instead this
// re-reads the wg interface's addresses every tick (one-truth applied to lifecycle) and reconciles its live
// listeners to match: it binds :53 when wg0 appears, re-binds after an interface/address flap, and closes a
// listener when its address goes. Best-effort per D5: a bind failure is logged and retried next tick, never
// fatal — DNS-down is never tunnel-down.
func (f *Forwarder) Serve(ctx context.Context, wgIface string) error {
	src := f.bindSource
	if src == nil {
		src = wgBindAddrs
	}
	lst := f.listen
	if lst == nil {
		lst = realListen
	}
	interval := f.bindInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	live := map[netip.Addr]context.CancelFunc{} // addr → stop its serveConn
	defer func() {
		for _, stop := range live {
			stop()
		}
	}()
	f.reconcileBinds(ctx, src, lst, wgIface, live) // bind immediately if wg0 is already up
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			f.reconcileBinds(ctx, src, lst, wgIface, live)
		}
	}
}

// reconcileBinds makes the live listener set match the wg interface's CURRENT addresses. A missing/empty
// interface yields an empty want-set → every live listener is closed (wg0 went). Exported behavior is
// idempotent: an unchanged address set is a no-op.
func (f *Forwarder) reconcileBinds(
	ctx context.Context,
	src func(string) ([]netip.Addr, error),
	lst func(netip.Addr) (udpListener, error),
	wgIface string,
	live map[netip.Addr]context.CancelFunc,
) {
	// TRICHOTOMY (RR1) — error is NOT one thing. Collapsing "transient glitch" and "interface gone" into a
	// single branch is exactly the bug this replaced (the R6 over-correction leaked listeners on a real wg0
	// removal). Three distinct outcomes:
	//   1. interface NOT FOUND (errWGIfaceNotFound) → CLOSE all listeners (the SECURITY half: a departed wg0
	//      address must not keep a live :53 socket that could later answer on a reassigned public interface).
	//   2. other/TRANSIENT error (interface exists, addrs momentarily unreadable) → KEEP current listeners
	//      (the AVAILABILITY half: a glitch must not blip cross-site DNS for a whole tick).
	//   3. success, possibly EMPTY set → reconcile (an empty set closes all — wg0 up but addressless).
	// Whoever "simplifies" this next should meet this reasoning first.
	binds, err := src(wgIface)
	if err != nil && !errors.Is(err, errWGIfaceNotFound) {
		if f.log != nil {
			f.log.Warn("dns_forward_bind_transient_error", "iface", wgIface, "error", err.Error())
		}
		return // (2) transient → keep
	}
	// (1) not-found → err set, binds nil → want empty → close-all below; (3) success → reconcile to binds.
	want := map[netip.Addr]struct{}{}
	for _, b := range binds {
		want[b] = struct{}{}
	}
	// Close listeners no longer wanted (address removed / wg0 addressless / wg0 gone).
	for addr, stop := range live {
		if _, ok := want[addr]; !ok {
			stop()
			delete(live, addr)
		}
	}
	// Open listeners newly wanted (wg0 appeared / new address).
	for addr := range want {
		if _, ok := live[addr]; ok {
			continue
		}
		pc, err := lst(addr)
		if err != nil {
			if f.log != nil {
				f.log.Warn("dns_forward_bind_failed", "addr", addr.String(), "error", err.Error())
			}
			continue // retry next tick
		}
		cctx, cancel := context.WithCancel(ctx)
		live[addr] = cancel
		go f.serveConn(cctx, pc)
	}
}

func (f *Forwarder) serveConn(ctx context.Context, pc udpListener) {
	go func() { <-ctx.Done(); _ = pc.Close() }()
	buf := make([]byte, dnsUDPMax)
	for {
		n, src, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return // conn closed (ctx done / address removed)
		}
		q := append([]byte(nil), buf[:n]...)
		srcAddr := src.Addr().Unmap()
		go func() {
			if resp := f.handle(q, srcAddr); resp != nil {
				_, _ = pc.WriteToUDPAddrPort(resp, src)
			}
		}()
	}
}
