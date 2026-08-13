package flowlog

import (
	"context"
	"time"
)

// Record is one raw kernel flow-log record: the nft log PREFIX token (naming the grant, or
// the deny sentinel) plus the packet's L3/L4 facts. The Linux nflog reader produces these;
// tests use a fake. It carries NO identity — attribution is the kernel-stamped prefix.
type Record struct {
	Prefix   string
	SrcIP    string
	DstIP    string
	Protocol string
	DstPort  int
	At       time.Time
}

// Source yields kernel flow-log records. The Linux impl reads an nflog group over netlink
// with a generously-sized socket receive buffer (the deny-log is the port-scan
// amplification point); the real socket sizing + wiring is a BOX-WALK deliverable (kernel
// packets can't be unit-tested), like the pf/WFP kill-switch. Overruns() reports the
// cumulative KERNEL-side dropped-record count (nflog overrun) so a kernel-level gap folds
// into the same drop-count surface as a buffer-level one; a Source that cannot observe it
// returns 0 (a NAMED accepted blind spot, not a silent one).
type Source interface {
	Records() <-chan Record
	Overruns() int64
}

// Pump reads records from a Source, STAMPS each into an Event (rule_id from the prefix +
// the applied PolicyHash, carried on the wire; CP-side skew consumption is deferred, fold-2
// #2), and buffers it. It is best-effort + async:
// nothing here is on the forward-chain apply path (enforcement isolation), and the buffer
// never blocks.
type Pump struct {
	src         Source
	buf         *Buffer
	hashFn      func() string
	deviceFn    func(srcIP string) string // v3: src /32 -> device_id from the applied artifact ("" = unresolved)
	lastOverrun int64
}

// NewPump wires a Source to a Buffer. hashFn returns the CURRENTLY-applied policy hash to
// stamp per event (nil → empty hash). deviceFn resolves a flow's src /32 to its device_id
// from the applied artifact (nil → no device stamping).
func NewPump(src Source, buf *Buffer, hashFn func() string, deviceFn func(srcIP string) string) *Pump {
	return &Pump{src: src, buf: buf, hashFn: hashFn, deviceFn: deviceFn}
}

// Run pumps records into the buffer until ctx is cancelled or the source closes.
func (p *Pump) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case rec, ok := <-p.src.Records():
			if !ok {
				return
			}
			if e, ok := p.stamp(rec); ok {
				p.buf.Add(e)
			}
		}
	}
}

// stamp turns a raw record into an Event. ok=false for a foreign record (no tnx prefix) —
// attribution rides the kernel-stamped prefix ONLY; there is NO packet-tuple re-derivation.
func (p *Pump) stamp(rec Record) (Event, bool) {
	ruleID, deny, ok := ParsePrefix(rec.Prefix)
	if !ok {
		return Event{}, false
	}
	verdict := VerdictAllow
	if deny {
		verdict = VerdictDeny
	}
	h := ""
	if p.hashFn != nil {
		h = p.hashFn()
	}
	dev := ""
	if p.deviceFn != nil {
		dev = p.deviceFn(rec.SrcIP) // "" when the src has no grant — unresolved, never guessed
	}
	return Event{
		OccurredAt: rec.At, Verdict: verdict, RuleID: ruleID, PolicyHash: h,
		SrcIP: rec.SrcIP, SrcDeviceID: dev, DstIP: rec.DstIP, Protocol: rec.Protocol, DstPort: rec.DstPort,
	}, true
}

// Drain returns the buffered events plus the TOTAL dropped since the last drain — buffer
// overflow PLUS the delta of kernel-side nflog overruns. Both are one legible number so
// the CP writes a single "N events dropped" gap marker on reconnect, whatever the cause.
func (p *Pump) Drain() (events []Event, dropped int64) {
	events, bufDropped := p.buf.Drain()
	over := p.src.Overruns()
	delta := over - p.lastOverrun
	if delta < 0 {
		delta = 0 // a source that resets its counter must never subtract from the gap
	}
	p.lastOverrun = over
	return events, bufDropped + delta
}
