//go:build linux

package flowlog

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	nflog "github.com/florianl/go-nflog/v2"
	"golang.org/x/sys/unix"
)

// DefaultNflogSockBuf is the netlink socket receive buffer for the nflog reader — 4 MiB.
// The deny-log is the port-scan AMPLIFICATION point (an attacker floods deny flow-starts),
// so the socket is sized generously; whatever still overruns is COUNTED (ENOBUFS) and folds
// into the unified drop-count, so a kernel-level gap is as legible as a buffer-level one.
const DefaultNflogSockBuf = 4 * 1024 * 1024

// NflogSource reads flow-start records from an nflog group (the group the gateway forward
// chain logs to, S7.5.1 decision (a)). Implements flowlog.Source. KERNEL path — proven at
// the box-walk, not by unit tests (like the kill-switch); the packet parse + record handoff
// are unit-tested (ParsePacket, the pump).
type NflogSource struct {
	ch      chan Record
	overrun atomic.Int64
	nf      *nflog.Nflog
}

// NewNflogSource opens the nflog group and begins delivering records. sockBuf<=0 uses the
// default. Requires CAP_NET_ADMIN. Cancel ctx (or Close) to stop.
func NewNflogSource(ctx context.Context, group, sockBuf int) (*NflogSource, error) {
	if sockBuf <= 0 {
		sockBuf = DefaultNflogSockBuf
	}
	nf, err := nflog.Open(&nflog.Config{Group: uint16(group), Copymode: nflog.CopyPacket})
	if err != nil {
		return nil, err
	}
	// Generous socket receive buffer so a burst of flow-starts isn't dropped in the socket;
	// best-effort (needs privilege), and the overrun counter catches whatever still drops.
	_ = nf.Con.SetReadBuffer(sockBuf)

	s := &NflogSource{ch: make(chan Record, 4096), nf: nf}
	hook := func(a nflog.Attribute) int {
		if a.Payload == nil {
			return 0
		}
		src, dst, proto, port, ok := ParsePacket(*a.Payload)
		if !ok {
			return 0
		}
		prefix := ""
		if a.Prefix != nil {
			prefix = *a.Prefix
		}
		at := time.Now()
		if a.Timestamp != nil {
			at = *a.Timestamp
		}
		select {
		case s.ch <- Record{Prefix: prefix, SrcIP: src, DstIP: dst, Protocol: proto, DstPort: port, At: at}:
		default:
			s.overrun.Add(1) // userspace handoff full — a drop; folds into the unified count
		}
		return 0
	}
	errFn := func(e error) int {
		// ENOBUFS = the kernel dropped nflog messages under load (an overrun) — count it so it
		// surfaces in the same drop-count as buffer overflow (the 3/n rider).
		if errors.Is(e, unix.ENOBUFS) {
			s.overrun.Add(1)
		}
		return 0
	}
	if err := nf.RegisterWithErrorFunc(ctx, hook, errFn); err != nil {
		_ = nf.Close()
		return nil, err
	}
	return s, nil
}

func (s *NflogSource) Records() <-chan Record { return s.ch }
func (s *NflogSource) Overruns() int64        { return s.overrun.Load() }
func (s *NflogSource) Close() error           { return s.nf.Close() }
