package main

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type reportAttemptLog struct {
	mu    sync.Mutex
	times []time.Time
}

func (a *reportAttemptLog) record() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.times = append(a.times, time.Now())
}

func (a *reportAttemptLog) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.times)
}

func (a *reportAttemptLog) at(index int) time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.times[index]
}

func (a *reportAttemptLog) snapshot() []time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]time.Time(nil), a.times...)
}

func TestReportLoopWakesPromptlyAndPreservesPeriodicCadence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		wake := make(chan struct{}, 1)
		var attempts reportAttemptLog
		go runReportLoop(ctx, wake, 10*time.Second, func(context.Context) bool {
			attempts.record()
			return true
		})
		synctest.Wait()
		if attempts.count() != 1 {
			t.Fatalf("initial attempts = %d, want immediate report", attempts.count())
		}
		start := attempts.at(0)
		time.Sleep(3 * time.Second)
		wake <- struct{}{}
		synctest.Wait()
		if attempts.count() != 2 || attempts.at(1).Sub(start) != 3*time.Second {
			t.Fatalf("wake did not report promptly: %v", attempts.snapshot())
		}
		time.Sleep(7 * time.Second)
		synctest.Wait()
		if attempts.count() != 3 || attempts.at(2).Sub(start) != 10*time.Second {
			t.Fatalf("wake shifted periodic cadence: %v", attempts.snapshot())
		}
		cancel()
		synctest.Wait()
	})
}

func TestReportLoopRetriesAfterSuccessAndResetsBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		wake := make(chan struct{}, 1)
		var attempts reportAttemptLog
		go runReportLoop(ctx, wake, time.Hour, func(context.Context) bool {
			attempts.record()
			return attempts.count() != 2 && attempts.count() != 3 && attempts.count() != 5
		})
		synctest.Wait()
		wake <- struct{}{}
		synctest.Wait()
		if attempts.count() != 2 {
			t.Fatalf("wake attempts = %d, want failed second report", attempts.count())
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if attempts.count() != 3 {
			t.Fatalf("first retry attempts = %d", attempts.count())
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if attempts.count() != 4 || attempts.at(3).Sub(attempts.at(2)) != 2*time.Second {
			t.Fatalf("steady-state retry did not use backoff: %v", attempts.snapshot())
		}
		wake <- struct{}{}
		synctest.Wait()
		time.Sleep(time.Second)
		synctest.Wait()
		if attempts.count() != 6 || attempts.at(5).Sub(attempts.at(4)) != time.Second {
			t.Fatalf("successful report did not reset retry backoff: %v", attempts.snapshot())
		}
		cancel()
		synctest.Wait()
	})
}

func TestReportLoopCapsRetryBackoffAndStartsPeriodicAfterSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		wake := make(chan struct{}, 1)
		var attempts reportAttemptLog
		go runReportLoop(ctx, wake, 10*time.Second, func(context.Context) bool {
			attempts.record()
			return attempts.count() >= 8
		})
		synctest.Wait()
		for i, delay := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second} {
			time.Sleep(delay)
			synctest.Wait()
			if attempts.count() != i+2 || attempts.at(i+1).Sub(attempts.at(i)) != delay {
				t.Fatalf("retry %d delay = %v, attempts = %v", i+1, delay, attempts.snapshot())
			}
		}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if attempts.count() != 9 || attempts.at(8).Sub(attempts.at(7)) != 10*time.Second {
			t.Fatalf("periodic cadence did not start after first success: %v", attempts.snapshot())
		}
		cancel()
		synctest.Wait()
	})
}

func TestReportLoopWakeInterruptsRetryBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		wake := make(chan struct{}, 1)
		var attempts reportAttemptLog
		go runReportLoop(ctx, wake, time.Hour, func(context.Context) bool {
			attempts.record()
			return attempts.count() > 1
		})
		synctest.Wait()
		time.Sleep(250 * time.Millisecond)
		wake <- struct{}{}
		synctest.Wait()
		if attempts.count() != 2 || attempts.at(1).Sub(attempts.at(0)) != 250*time.Millisecond {
			t.Fatalf("changed status waited for retry timer: %v", attempts.snapshot())
		}
		cancel()
		synctest.Wait()
	})
}

func TestReportLoopSerializesInflightReportsAndRetainsLatestWake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		wake := make(chan struct{}, 1)
		release := make(chan struct{})
		var status atomic.Value
		status.Store("old-applied-hash")
		var active, maxActive atomic.Int32
		var sent []string
		go runReportLoop(ctx, wake, time.Hour, func(context.Context) bool {
			current := active.Add(1)
			if current > maxActive.Load() {
				maxActive.Store(current)
			}
			hash := status.Load().(string)
			sent = append(sent, hash)
			if hash == "old-applied-hash" {
				<-release
			}
			active.Add(-1)
			return true
		})
		synctest.Wait()
		status.Store("intermediate-applied-hash")
		wake <- struct{}{}
		status.Store("latest-applied-hash")
		for range 20 {
			select {
			case wake <- struct{}{}:
			default:
			}
		}
		synctest.Wait()
		if len(sent) != 1 || active.Load() != 1 {
			t.Fatalf("new report overlapped blocked old report: sent = %v, active = %d", sent, active.Load())
		}
		close(release)
		synctest.Wait()
		if len(sent) != 2 || sent[1] != "latest-applied-hash" || maxActive.Load() != 1 {
			t.Fatalf("queued wake lost or reports overlapped: sent = %v, max active = %d", sent, maxActive.Load())
		}
		cancel()
		synctest.Wait()
	})
}

func TestReportLoopCancellationStopsRetryAndPendingWake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		wake := make(chan struct{}, 1)
		attempts := 0
		done := make(chan struct{})
		go func() {
			defer close(done)
			runReportLoop(ctx, wake, time.Hour, func(context.Context) bool {
				attempts++
				return false
			})
		}()
		synctest.Wait()
		cancel()
		wake <- struct{}{}
		synctest.Wait()
		<-done
		time.Sleep(time.Minute)
		if attempts != 1 {
			t.Fatalf("cancelled report loop made %d attempts", attempts)
		}
	})
}
