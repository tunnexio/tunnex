package flowlog

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type reportCall struct {
	events  int
	dropped int64
}

type fakeReporter struct {
	mu       sync.Mutex
	calls    []reportCall
	failNext int // fail this many calls, then succeed
}

func (f *fakeReporter) ReportFlows(_ context.Context, events []Event, dropped int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, reportCall{len(events), dropped})
	if f.failNext > 0 {
		f.failNext--
		return errors.New("cp down")
	}
	return nil
}

func (f *fakeReporter) snapshot() []reportCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]reportCall(nil), f.calls...)
}

// A failed report loses its batch but CARRIES the count into the next report's `dropped`, so
// the CP still writes a gap — no re-send, no duplicate, the loss stays legible.
func TestRunDrainCarriesLossAsGap(t *testing.T) {
	buf := NewBuffer(64)
	for i := 0; i < 3; i++ {
		buf.Add(Event{SrcIP: "10.99.0.10"})
	}
	pump := NewPump(&fakeSource{}, buf, nil)
	rep := &fakeReporter{failNext: 1} // first report fails

	ctx, cancel := context.WithCancel(context.Background())
	go RunDrain(ctx, pump, rep, 10*time.Millisecond, nil)

	deadline := time.Now().Add(3 * time.Second)
	for len(rep.snapshot()) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()

	calls := rep.snapshot()
	if len(calls) < 2 {
		t.Fatalf("want >=2 report calls, got %d", len(calls))
	}
	// Call 1: the 3 events, 0 dropped — fails.
	if calls[0].events != 3 || calls[0].dropped != 0 {
		t.Fatalf("call 1 = %+v, want {3,0}", calls[0])
	}
	// Call 2: the failed batch's count surfaces as `dropped` (a gap), no events re-sent.
	if calls[1].events != 0 || calls[1].dropped != 3 {
		t.Fatalf("call 2 = %+v, want {0,3} (lost batch carried as a gap)", calls[1])
	}
}
