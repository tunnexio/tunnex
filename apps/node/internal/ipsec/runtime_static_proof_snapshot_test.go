package ipsec

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestStaticProofSnapshotIndependentBranchesRetainReadOrderAndDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	daemonStarted := make(chan struct{})
	xfrmStarted := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	var kernels atomic.Int32
	check := func(c context.Context) {
		if d, _ := c.Deadline(); !d.Equal(deadline) {
			t.Error("deadline changed")
		}
	}
	readers := runtimeStatusReaders{
		daemon: func(c context.Context) (DaemonInventory, error) {
			check(c)
			close(daemonStarted)
			<-release
			return DaemonInventory{}, nil
		},
		xfrm: func(c context.Context) (XFRMInventory, error) {
			check(c)
			close(xfrmStarted)
			<-release
			return XFRMInventory{}, nil
		},
		kernel: func(c context.Context) (KernelInventory, error) {
			check(c)
			kernels.Add(1)
			return KernelInventory{}, nil
		},
	}
	go func() {
		_, _, _, de, ke, xe := runtimeReadStaticProofSnapshot(ctx, readers)
		if de != nil || ke != nil || xe != nil {
			t.Error("complete reads refused")
		}
		close(done)
	}()
	for _, ch := range []chan struct{}{daemonStarted, xfrmStarted} {
		select {
		case <-ch:
		case <-ctx.Done():
			t.Fatal("independent branch serialized")
		}
	}
	if kernels.Load() != 0 {
		t.Fatal("kernel ran before XFRM completed")
	}
	select {
	case <-done:
		t.Fatal("snapshot returned before branches drained")
	default:
	}
	close(release)
	<-done
	if kernels.Load() != 1 {
		t.Fatal("kernel missing")
	}
}

func TestStaticProofSnapshotSerialCostRegressionAndCancellationDrain(t *testing.T) {
	makeReaders := func(active *atomic.Int32) runtimeStatusReaders {
		pause := func(c context.Context) error {
			active.Add(1)
			defer active.Add(-1)
			timer := time.NewTimer(40 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
				return nil
			case <-c.Done():
				return c.Err()
			}
		}
		return runtimeStatusReaders{daemon: func(c context.Context) (DaemonInventory, error) { return DaemonInventory{}, pause(c) }, xfrm: func(c context.Context) (XFRMInventory, error) { return XFRMInventory{}, pause(c) }, kernel: func(c context.Context) (KernelInventory, error) { return KernelInventory{}, pause(c) }}
	}
	var active atomic.Int32
	// Original serial XFRM + daemon + kernel needs120ms and cannot fit100ms.
	old, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	r := makeReaders(&active)
	_, xe := r.xfrm(old)
	_, de := r.daemon(old)
	_, ke := r.kernel(old)
	cancel()
	if xe != nil || de != nil || !errors.Is(ke, context.DeadlineExceeded) {
		t.Fatalf("serial premise x=%v d=%v k=%v", xe, de, ke)
	}
	fresh, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, _, _, de, ke, xe = runtimeReadStaticProofSnapshot(fresh, makeReaders(&active))
	if de != nil || ke != nil || xe != nil || active.Load() != 0 {
		t.Fatalf("same reads parallel d=%v k=%v x=%v active=%d", de, ke, xe, active.Load())
	}
	canceled, stop := context.WithCancel(t.Context())
	stop()
	var calls atomic.Int32
	readers := makeReaders(&active)
	readers.daemon = func(context.Context) (DaemonInventory, error) { calls.Add(1); return DaemonInventory{}, nil }
	runtimeReadStaticProofSnapshot(canceled, readers)
	if calls.Load() != 0 || active.Load() != 0 {
		t.Fatal("launched native work after cancellation")
	}
	short, stop := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer stop()
	_, _, _, de, _, xe = runtimeReadStaticProofSnapshot(short, makeReaders(&active))
	if !errors.Is(de, context.DeadlineExceeded) || !errors.Is(xe, context.DeadlineExceeded) || active.Load() != 0 {
		t.Fatal("canceled native workers not drained")
	}
}

func TestStaticProofSnapshotFailureEvidenceRetained(t *testing.T) {
	sentinel := errors.New("test read refusal")
	for _, stage := range []string{"daemon", "xfrm", "kernel"} {
		t.Run(stage, func(t *testing.T) {
			var kernel atomic.Int32
			r := runtimeStatusReaders{daemon: func(context.Context) (DaemonInventory, error) {
				if stage == "daemon" {
					return DaemonInventory{}, sentinel
				}
				return DaemonInventory{}, nil
			}, xfrm: func(context.Context) (XFRMInventory, error) {
				if stage == "xfrm" {
					return XFRMInventory{}, sentinel
				}
				return XFRMInventory{}, nil
			}, kernel: func(context.Context) (KernelInventory, error) {
				kernel.Add(1)
				if stage == "kernel" {
					return KernelInventory{}, sentinel
				}
				return KernelInventory{}, nil
			}}
			_, _, _, de, ke, xe := runtimeReadStaticProofSnapshot(t.Context(), r)
			if stage == "daemon" && de != sentinel || stage == "xfrm" && xe != sentinel || stage == "kernel" && ke != sentinel {
				t.Fatal("native read failure lost")
			}
			if stage == "xfrm" && kernel.Load() != 0 {
				t.Fatal("launched kernel after failed XFRM")
			}
		})
	}
}

func TestStaticProofTimingDispatchIsOptionalAndDoesNotChangeRefusal(t *testing.T) {
	c := &RuntimeController{config: RuntimeControllerConfig{IPPath: "relative-unqualified-path"}}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	entry := RuntimeJournalEntry{ContractVersion: 2}
	if err := c.proveCurrentTimed(ctx, entry, RuntimeEnvironment{}, nil, nil); err != ErrRuntimeController {
		t.Fatal("original static refusal changed")
	}
	calls := 0
	err := c.proveCurrentTimed(ctx, entry, RuntimeEnvironment{}, nil, func(v runtimeNativePhaseTiming) {
		calls++
		if v.ElapsedMillis < 0 || v.RemainingAtEntryMillis < 1 || v.RemainingAtEntryMillis > 1000 {
			t.Fatal("timing bounds")
		}
	})
	if err != ErrRuntimeController || calls != 1 {
		t.Fatalf("static observation changed outcome err=%v callbacks=%d", err, calls)
	}
	if got, _ := ctx.Deadline(); !got.Equal(deadline) || ctx.Err() != nil {
		t.Fatal("timing changed original context")
	}
}
