package ipsec

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRecoverySnapshotTwoBranchesAndPassBarrier(t *testing.T) {
	e, d, k, x := runtimeProofFixture()
	daemonEntered := make(chan struct{}, 1)
	daemonReady := make(chan struct{})
	releaseDaemon := make(chan struct{})
	kernelDone := make(chan struct{}, 1)
	done := make(chan [2]string, 1)
	var daemonCalls, kernelCalls, xfrmCalls atomic.Int32
	var active, peak atomic.Int32
	enter := func() {
		n := active.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
	}
	leave := func() { active.Add(-1) }
	r := runtimeStatusReaders{alive: func() bool { return true }, daemon: func(context.Context) (DaemonInventory, error) {
		enter()
		defer leave()
		if daemonCalls.Add(1) == 1 {
			close(daemonReady)
			daemonEntered <- struct{}{}
			<-releaseDaemon
		}
		return d, nil
	}, kernel: func(context.Context) (KernelInventory, error) {
		enter()
		defer leave()
		kernelCalls.Add(1)
		<-daemonReady
		return k, nil
	}, xfrm: func(context.Context) (XFRMInventory, error) {
		enter()
		defer leave()
		if xfrmCalls.Add(1) == 1 {
			kernelDone <- struct{}{}
		}
		return x, nil
	}}
	go func() { done <- runtimeObservedStatuses(t.Context(), e, r) }()
	for _, ch := range []chan struct{}{daemonEntered, kernelDone} {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatal("branches did not overlap")
		}
	}
	if daemonCalls.Load() != 1 || kernelCalls.Load() != 1 || xfrmCalls.Load() != 1 {
		t.Fatal("second pass began before first drained")
	}
	select {
	case <-done:
		t.Fatal("returned with daemon still running")
	default:
	}
	close(releaseDaemon)
	if got := <-done; got != [2]string{"up", "up"} || daemonCalls.Load() != 2 || kernelCalls.Load() != 2 || xfrmCalls.Load() != 2 || active.Load() != 0 || peak.Load() != 2 {
		t.Fatal("full independent pass reads changed", got)
	}
}

func TestRecoverySnapshotCancellationDrainsAndRetainsDeadline(t *testing.T) {
	for _, kind := range []string{"cancel", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			e, d, k, _ := runtimeProofFixture()
			parent, cancel := context.WithCancel(t.Context())
			defer cancel()
			if kind == "deadline" {
				var stop context.CancelFunc
				parent, stop = context.WithTimeout(parent, 40*time.Millisecond)
				defer stop()
			}
			entered := make(chan struct{}, 2)
			release := make(chan struct{})
			done := make(chan [2]string, 1)
			var xfrmCalls atomic.Int32
			check := func(c context.Context) {
				want, wok := parent.Deadline()
				got, gok := c.Deadline()
				if !gok || (wok && !want.Equal(got)) {
					t.Error("original earlier deadline changed")
				}
			}
			r := runtimeStatusReaders{alive: func() bool { return true }, daemon: func(c context.Context) (DaemonInventory, error) {
				check(c)
				entered <- struct{}{}
				<-c.Done()
				<-release
				return d, c.Err()
			}, kernel: func(c context.Context) (KernelInventory, error) {
				check(c)
				entered <- struct{}{}
				<-c.Done()
				return k, c.Err()
			}, xfrm: func(context.Context) (XFRMInventory, error) { xfrmCalls.Add(1); return XFRMInventory{}, nil }}
			go func() { done <- runtimeObservedStatuses(parent, e, r) }()
			for i := 0; i < 2; i++ {
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("read did not start")
				}
			}
			if kind == "cancel" {
				cancel()
			}
			<-parent.Done()
			select {
			case <-done:
				t.Fatal("returned before daemon drained")
			default:
			}
			close(release)
			if got := <-done; got != [2]string{"unknown", "unknown"} || xfrmCalls.Load() != 1 {
				t.Fatal("canceled proof admitted or original read set changed", got)
			}
		})
	}
}

func TestRecoverySnapshotFailurePrecedenceAndCompleteReads(t *testing.T) {
	for _, mask := range []int{1, 2, 4, 3, 5, 6, 7} {
		t.Run(string(rune('0'+mask)), func(t *testing.T) {
			e, d, k, x := runtimeProofFixture()
			var counts [3]atomic.Int32
			var reason string
			fail := func(bit int) error {
				if mask&bit != 0 {
					return errors.New("private native error")
				}
				return nil
			}
			r := runtimeStatusReaders{alive: func() bool { return true }, daemon: func(context.Context) (DaemonInventory, error) { counts[0].Add(1); return d, fail(1) }, kernel: func(context.Context) (KernelInventory, error) { counts[1].Add(1); return k, fail(2) }, xfrm: func(context.Context) (XFRMInventory, error) { counts[2].Add(1); return x, fail(4) }}
			got := runtimeObservedStatusesObserved(t.Context(), e, r, func(v string) { reason = v })
			want := "daemon_read"
			if mask&1 == 0 {
				want = "kernel_read"
				if mask&2 == 0 {
					want = "xfrm_read"
				}
			}
			if got != [2]string{"unknown", "unknown"} || reason != want {
				t.Fatal("error precedence changed", got, reason)
			}
			for _, count := range counts {
				if count.Load() != 1 {
					t.Fatal("failed first snapshot skipped read or started second")
				}
			}
		})
	}
}

func TestRecoverySnapshotNativeEvidenceNegativeCases(t *testing.T) {
	for _, kind := range []string{"duplicate_sa", "duplicate_child", "wrong_spi", "kernel_change", "xfrm_change"} {
		t.Run(kind, func(t *testing.T) {
			e, d, k, x := runtimeProofFixture()
			var kernelCalls, xfrmCalls int
			var mu sync.Mutex
			var order []string
			record := func(v string) { mu.Lock(); order = append(order, v); mu.Unlock() }
			if kind == "duplicate_sa" {
				d.SAs = append(d.SAs, d.SAs[0])
			}
			if kind == "duplicate_child" {
				d.SAs[0].Children = append(d.SAs[0].Children, d.SAs[0].Children[0])
			}
			if kind == "wrong_spi" {
				x.States[0].SPI++
			}
			r := runtimeStatusReaders{alive: func() bool { return true }, daemon: func(context.Context) (DaemonInventory, error) { record("daemon"); return d, nil }, kernel: func(context.Context) (KernelInventory, error) {
				record("kernel")
				kernelCalls++
				snapshot := k
				snapshot.Links = append([]KernelLink(nil), k.Links...)
				if kind == "kernel_change" && kernelCalls == 2 {
					snapshot.Links[0].Index += 100
				}
				return snapshot, nil
			}, xfrm: func(context.Context) (XFRMInventory, error) {
				record("xfrm")
				xfrmCalls++
				snapshot := x
				snapshot.States = append([]XFRMState(nil), x.States...)
				if kind == "xfrm_change" && xfrmCalls == 2 {
					snapshot.States[0].SPI++
				}
				return snapshot, nil
			}}
			got := runtimeObservedStatuses(t.Context(), e, r)
			want := [2]string{"unknown", "up"}
			if kind == "kernel_change" || kind == "xfrm_change" {
				want = [2]string{"unknown", "unknown"}
			}
			if got != want || kernelCalls != 2 || xfrmCalls != 2 {
				t.Fatal("unsafe native evidence accepted", got)
			}
			// Kernel precedes XFRM in each pass; no second kernel until its first XFRM.
			var inventory []string
			for _, v := range order {
				if v != "daemon" {
					inventory = append(inventory, v)
				}
			}
			if len(inventory) != 4 || inventory[0] != "kernel" || inventory[1] != "xfrm" || inventory[2] != "kernel" || inventory[3] != "xfrm" {
				t.Fatal("kernel/XFRM ordering changed", order)
			}
		})
	}
}

func TestRecoverySnapshotFirstAliveValidationPrecedesSecond(t *testing.T) {
	e, d, k, x := runtimeProofFixture()
	var daemonReads, kernelReads, xfrmReads atomic.Int32
	aliveCalls := 0
	r := runtimeStatusReaders{alive: func() bool {
		aliveCalls++
		if aliveCalls == 1 {
			return true
		}
		if daemonReads.Load() != 1 || kernelReads.Load() != 1 || xfrmReads.Load() != 1 {
			t.Error("validated an incomplete snapshot")
		}
		return false
	}, daemon: func(context.Context) (DaemonInventory, error) { daemonReads.Add(1); return d, nil }, kernel: func(context.Context) (KernelInventory, error) { kernelReads.Add(1); return k, nil }, xfrm: func(context.Context) (XFRMInventory, error) { xfrmReads.Add(1); return x, nil }}
	if got := runtimeObservedStatuses(t.Context(), e, r); got != [2]string{"unknown", "unknown"} || aliveCalls != 2 || daemonReads.Load() != 1 || kernelReads.Load() != 1 || xfrmReads.Load() != 1 {
		t.Fatal("second snapshot bypassed failed first validation", got)
	}
}
