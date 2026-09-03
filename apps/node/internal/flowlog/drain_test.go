package flowlog

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
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
	status := NewStatus(StateActive)
	pump := NewPump(&fakeSource{}, buf, nil).WithStatus(status)
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
	if got := status.Snapshot(); got.LastDeliveredAt.IsZero() {
		t.Fatal("successful gap report must advance last-delivered status")
	}
}

func TestStatusBoundsUnknownStateAsSourceError(t *testing.T) {
	status := NewStatus(State("future-unbounded-state"))
	if got := status.Snapshot().State; got != StateSourceError {
		t.Fatalf("unknown state = %q, want %q", got, StateSourceError)
	}
}

func TestStatusSourceErrorIsNotMaskedByDeliveryRecovery(t *testing.T) {
	status := NewStatus(StateActive)
	status.RecordDeliveryFailure()
	if got := status.Snapshot().State; got != StateDeliveryError {
		t.Fatalf("failed delivery state = %q, want %q", got, StateDeliveryError)
	}
	status.SetState(StateSourceError)
	status.RecordDelivered(time.Now())
	if got := status.Snapshot().State; got != StateSourceError {
		t.Fatalf("successful delivery masked dead source: state=%q", got)
	}
}

type recoveryReporter struct {
	calls         atomic.Int32
	secondStarted chan struct{}
	releaseSecond chan struct{}
}

func (r *recoveryReporter) ReportFlows(context.Context, []Event, int64) error {
	switch r.calls.Add(1) {
	case 1:
		return errors.New("cp down")
	case 2:
		close(r.secondStarted)
		<-r.releaseSecond
	}
	return nil
}

func TestRunDrainReportsDeliveryErrorAndRecoversToActive(t *testing.T) {
	buf := NewBuffer(8)
	buf.Add(Event{SrcIP: "10.99.0.10"})
	status := NewStatus(StateActive)
	pump := NewPump(&fakeSource{}, buf, nil).WithStatus(status)
	reporter := &recoveryReporter{
		secondStarted: make(chan struct{}),
		releaseSecond: make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go RunDrain(ctx, pump, reporter, 5*time.Millisecond, nil)

	select {
	case <-reporter.secondStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for recovery report")
	}
	if got := status.Snapshot().State; got != StateDeliveryError {
		t.Fatalf("state after failed delivery = %q, want %q", got, StateDeliveryError)
	}
	close(reporter.releaseSecond)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got := status.Snapshot()
		if got.State == StateActive && !got.LastDeliveredAt.IsZero() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("status did not recover after successful delivery: %+v", status.Snapshot())
}
