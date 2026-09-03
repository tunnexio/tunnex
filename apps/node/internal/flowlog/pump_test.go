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
	p := NewPump(&fakeSource{}, NewBuffer(8), func(string) Attribution {
		return Attribution{PolicyHash: "abc123def456", PolicyVersion: 7}
	})
	rid := "019f5a14-1c1b-7343-bfb9-76e94a54b574"

	e, ok := p.stamp(Record{Prefix: EncodePrefix(rid), SrcIP: "10.99.0.10", DstIP: "10.0.5.5", Protocol: "tcp", DstPort: 5432})
	if !ok || e.Verdict != VerdictAllow || e.RuleID != rid || e.PolicyHash != "abc123def456" || e.PolicyVersion != 7 || e.Reason != ReasonMatchedGrant || e.DstPort != 5432 {
		t.Fatalf("allow stamp wrong: %+v ok=%v", e, ok)
	}
	e, ok = p.stamp(Record{Prefix: EncodePrefix(""), SrcIP: "10.99.0.9", DstIP: "10.0.9.9", Protocol: "tcp"})
	if !ok || e.Verdict != VerdictDeny || e.RuleID != "" || e.Reason != ReasonNoMatchingGrant {
		t.Fatalf("deny stamp wrong: %+v ok=%v", e, ok)
	}
	if _, ok := p.stamp(Record{Prefix: "kernel: martian source"}); ok {
		t.Fatal("a foreign record must be skipped, not stamped")
	}
}

// F07 — the pump stamps the complete applied-artifact subject snapshot. A source with no
// mapping stamps empty attribution (unresolved, never guessed).
func TestPumpStampSrcDevice(t *testing.T) {
	rev := int64(4)
	p := NewPump(&fakeSource{}, NewBuffer(8), func(srcIP string) Attribution {
		if srcIP == "10.99.0.10" {
			return Attribution{SrcDeviceID: "dev-alice", SrcDeviceKind: "agent", ConfigRevision: &rev}
		}
		return Attribution{}
	})

	e, ok := p.stamp(Record{Prefix: EncodePrefix("r1"), SrcIP: "10.99.0.10", DstIP: "10.0.5.5", Protocol: "tcp"})
	if !ok || e.SrcDeviceID != "dev-alice" || e.SrcDeviceKind != "agent" || e.SrcConfigRevision == nil || *e.SrcConfigRevision != 4 {
		t.Fatalf("mapped src must stamp its event-time subject, got %+v", e)
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
	status := NewStatus(StateActive)
	p := NewPump(src, NewBuffer(16), nil).WithStatus(status)
	ctx, cancel := context.WithCancel(context.Background())
	go p.Run(ctx)

	observedAt := time.Now().UTC().Truncate(time.Microsecond)
	for i := 0; i < 3; i++ {
		src.ch <- Record{Prefix: EncodePrefix("r"), SrcIP: "10.99.0.10", DstIP: "10.0.5.5", Protocol: "tcp", At: observedAt}
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
	if got := status.Snapshot(); got.State != StateActive || !got.LastObservedAt.Equal(observedAt) {
		t.Fatalf("status after observation = %+v, want active at %s", got, observedAt)
	}
}

func TestPumpClosedSourceReportsSourceError(t *testing.T) {
	src := &fakeSource{ch: make(chan Record)}
	status := NewStatus(StateActive)
	p := NewPump(src, NewBuffer(1), nil).WithStatus(status)
	close(src.ch)
	p.Run(context.Background())
	if got := status.Snapshot().State; got != StateSourceError {
		t.Fatalf("state after source closes = %q, want %q", got, StateSourceError)
	}
}

// Drain folds KERNEL nflog overruns into the same drop-count as buffer overflow, and only
// counts the DELTA since the last drain (a kernel-level gap is as legible as a buffer one).
func TestPumpDrainFoldsKernelOverrun(t *testing.T) {
	src := &fakeSource{ch: make(chan Record)}
	buf := NewBuffer(2)
	p := NewPump(src, buf, nil)

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
