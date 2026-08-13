package flowlog

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

type fakeSource struct {
	ch      chan Record
	overrun atomic.Int64
}

func (f *fakeSource) Records() <-chan Record { return f.ch }
func (f *fakeSource) Overruns() int64        { return f.overrun.Load() }

// stamp: an allow record carries rule_id + the applied hash; a deny carries none; a foreign
// record is skipped. Attribution is the kernel prefix, never a packet re-derivation.
func TestPumpStamp(t *testing.T) {
	p := NewPump(&fakeSource{}, NewBuffer(8), func() string { return "abc123" }, nil)
	rid := "019f5a14-1c1b-7343-bfb9-76e94a54b574"

	e, ok := p.stamp(Record{Prefix: EncodePrefix(rid), SrcIP: "10.99.0.10", DstIP: "10.0.5.5", Protocol: "tcp", DstPort: 5432})
	if !ok || e.Verdict != VerdictAllow || e.RuleID != rid || e.PolicyHash != "abc123" || e.DstPort != 5432 {
		t.Fatalf("allow stamp wrong: %+v ok=%v", e, ok)
	}
	e, ok = p.stamp(Record{Prefix: EncodePrefix(""), SrcIP: "10.99.0.9", DstIP: "10.0.9.9", Protocol: "tcp"})
	if !ok || e.Verdict != VerdictDeny || e.RuleID != "" {
		t.Fatalf("deny stamp wrong: %+v ok=%v", e, ok)
	}
	if _, ok := p.stamp(Record{Prefix: "kernel: martian source"}); ok {
		t.Fatal("a foreign record must be skipped, not stamped")
	}
}

// S7.5.4 v3 — the pump stamps src_device_id from the deviceFn (the applied artifact's
// /32→device map). A src with no mapping stamps "" (unresolved, never guessed).
func TestPumpStampSrcDevice(t *testing.T) {
	byIP := map[string]string{"10.99.0.10": "dev-alice"}
	p := NewPump(&fakeSource{}, NewBuffer(8), nil, func(srcIP string) string { return byIP[srcIP] })

	e, ok := p.stamp(Record{Prefix: EncodePrefix("r1"), SrcIP: "10.99.0.10", DstIP: "10.0.5.5", Protocol: "tcp"})
	if !ok || e.SrcDeviceID != "dev-alice" {
		t.Fatalf("mapped src must stamp its device id, got %q", e.SrcDeviceID)
	}
	// A src not in the map (e.g. a denied packet from a non-granted device) → unresolved.
	e, ok = p.stamp(Record{Prefix: EncodePrefix("r1"), SrcIP: "10.99.0.99", DstIP: "10.0.5.5", Protocol: "tcp"})
	if !ok || e.SrcDeviceID != "" {
		t.Fatalf("unmapped src must stamp empty device id (never guessed), got %q", e.SrcDeviceID)
	}
}

// Run pumps records into the buffer; Drain returns them.
func TestPumpRunBuffers(t *testing.T) {
	src := &fakeSource{ch: make(chan Record, 4)}
	p := NewPump(src, NewBuffer(16), nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go p.Run(ctx)

	for i := 0; i < 3; i++ {
		src.ch <- Record{Prefix: EncodePrefix("r"), SrcIP: "10.99.0.10", DstIP: "10.0.5.5", Protocol: "tcp"}
	}
	// Give the pump a moment to drain the channel.
	deadline := time.Now().Add(2 * time.Second)
	for p.buf.Len() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	events, dropped := p.Drain()
	if len(events) != 3 || dropped != 0 {
		t.Fatalf("drain = %d events, %d dropped; want 3, 0", len(events), dropped)
	}
}

// Drain folds KERNEL nflog overruns into the same drop-count as buffer overflow, and only
// counts the DELTA since the last drain (a kernel-level gap is as legible as a buffer one).
func TestPumpDrainFoldsKernelOverrun(t *testing.T) {
	src := &fakeSource{ch: make(chan Record)}
	buf := NewBuffer(2)
	p := NewPump(src, buf, nil, nil)

	// Overflow the buffer by 3 (cap 2) → 3 buffer drops.
	for i := 0; i < 5; i++ {
		buf.Add(Event{SrcIP: "x"})
	}
	// Kernel reports 4 overruns.
	src.overrun.Store(4)

	_, dropped := p.Drain()
	if dropped != 3+4 {
		t.Fatalf("first drain dropped = %d, want 7 (3 buffer + 4 kernel)", dropped)
	}
	// A second drain with no new drops and the same overrun total reports 0 (delta).
	src.overrun.Store(4)
	if _, d := p.Drain(); d != 0 {
		t.Fatalf("second drain dropped = %d, want 0 (overrun delta only)", d)
	}
	// A further kernel overrun surfaces as its delta.
	src.overrun.Store(9)
	if _, d := p.Drain(); d != 5 {
		t.Fatalf("third drain dropped = %d, want 5 (9-4)", d)
	}
}
