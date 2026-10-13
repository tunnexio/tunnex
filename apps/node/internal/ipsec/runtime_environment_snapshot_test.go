package ipsec

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEnvironmentReadPoolTwoWorkersAndDraining(t *testing.T) {
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	done := make(chan bool, 1)
	var active, peak, finished atomic.Int32
	tasks := make([]func(context.Context) error, 7)
	for i := range tasks {
		tasks[i] = func(context.Context) error {
			n := active.Add(1)
			for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
			}
			entered <- struct{}{}
			<-release
			active.Add(-1)
			finished.Add(1)
			return nil
		}
	}
	go func() { done <- runtimeEnvironmentReadPool(context.Background(), tasks) }()
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("workers did not start")
		}
	}
	if peak.Load() != 2 {
		t.Fatal("not exactly two workers")
	}
	select {
	case <-done:
		t.Fatal("returned before draining")
	default:
	}
	close(release)
	// Drain the instrumentation so all remaining reads can finish.
	go func() {
		for i := 0; i < 5; i++ {
			<-entered
		}
	}()
	if !<-done || active.Load() != 0 || finished.Load() != 7 || peak.Load() != 2 {
		t.Fatal("incomplete pool or excessive concurrency")
	}
}

func TestEnvironmentReadPoolCancellationDrainsAndStopsLaunch(t *testing.T) {
	for _, kind := range []string{"cancel", "deadline", "failure"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "deadline" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 40*time.Millisecond)
				defer stop()
			}
			entered := make(chan struct{}, 2)
			release := make(chan struct{})
			done := make(chan bool, 1)
			var launched atomic.Int32
			tasks := make([]func(context.Context) error, 8)
			tasks[0] = func(c context.Context) error {
				launched.Add(1)
				entered <- struct{}{}
				if kind == "failure" {
					<-release
					return errors.New("fixed test failure")
				}
				<-c.Done()
				<-release
				return c.Err()
			}
			tasks[1] = func(c context.Context) error {
				launched.Add(1)
				entered <- struct{}{}
				<-c.Done()
				<-release
				return c.Err()
			}
			for i := 2; i < len(tasks); i++ {
				tasks[i] = func(context.Context) error { launched.Add(1); return nil }
			}
			go func() { done <- runtimeEnvironmentReadPool(ctx, tasks) }()
			for i := 0; i < 2; i++ {
				<-entered
			}
			if kind == "failure" {
				close(release)
			} else {
				if kind == "cancel" {
					cancel()
				}
				<-ctx.Done()
				select {
				case <-done:
					t.Fatal("returned with a live worker")
				default:
				}
				close(release)
			}
			if <-done || launched.Load() != 2 {
				t.Fatal("failure admitted or commands launched after cancellation")
			}
		})
	}
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	invoked := false
	if runtimeEnvironmentReadPool(expired, []func(context.Context) error{func(context.Context) error { invoked = true; return nil }}) || invoked {
		t.Fatal("expired context launched a command")
	}
}

func TestEnvironmentReadPoolSnapshotBarrier(t *testing.T) {
	var mu sync.Mutex
	outstanding := 0
	firstFinished := 0
	secondStarted := 0
	first := make([]func(context.Context) error, 7)
	for i := range first {
		first[i] = func(context.Context) error {
			mu.Lock()
			outstanding++
			mu.Unlock()
			time.Sleep(time.Millisecond)
			mu.Lock()
			outstanding--
			firstFinished++
			mu.Unlock()
			return nil
		}
	}
	if !runtimeEnvironmentReadPool(context.Background(), first) {
		t.Fatal("first snapshot")
	}
	// This is the caller barrier: results are only consumed after all reads finish.
	if outstanding != 0 || firstFinished != 7 {
		t.Fatal("incomplete first snapshot")
	}
	second := []func(context.Context) error{func(context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		secondStarted++
		if outstanding != 0 || firstFinished != 7 {
			return errors.New("overlapped snapshots")
		}
		return nil
	}}
	if !runtimeEnvironmentReadPool(context.Background(), second) || secondStarted != 1 {
		t.Fatal("second snapshot")
	}
}

func TestEnvironmentCommandTimingUnionAndBound(t *testing.T) {
	var v runtimeEnvironmentCommandTiming
	start := time.Now()
	v.record(start, start.Add(100*time.Millisecond))
	v.record(start.Add(20*time.Millisecond), start.Add(120*time.Millisecond))
	v.record(start.Add(150*time.Millisecond), start.Add(170*time.Millisecond))
	got := v.result()
	if got.CommandMillis != 140 || got.CommandCount != 3 {
		t.Fatal("overlap double-counted", got)
	}
	for i := 0; i < 100; i++ {
		v.record(start, start.Add(time.Millisecond))
	}
	if v.result().CommandCount != runtimeEnvironmentCommandCeiling {
		t.Fatal("unbounded interval storage")
	}
}

func TestEnvironmentSnapshotSingleAndDualPeerReadCounts(t *testing.T) {
	for _, profile := range []string{AzureActiveActiveBGPProfile, AzureActiveStandbyBGPProfile, AzureActiveActiveStaticProfile, AzureActiveStandbyStaticProfile} {
		t.Run(profile, func(t *testing.T) {
			engines := journalFixture().Engines
			engines[0].ProfileID = profile
			var commands atomic.Int32
			ip := func(context.Context, ...string) ([]byte, error) { commands.Add(1); return []byte(`[]`), nil }
			nft := func(context.Context) ([]byte, error) { commands.Add(1); return nil, nil }
			_, ok := runtimeReadEnvironmentSnapshot(context.Background(), ip, nft, engines)
			expected := 5 + engineTunnelCount(engines)
			if !ok || int(commands.Load()) != expected {
				t.Fatal("omitted or extra peer read", commands.Load())
			}
		})
	}
}
