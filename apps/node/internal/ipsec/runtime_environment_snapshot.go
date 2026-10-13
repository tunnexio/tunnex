package ipsec

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Each snapshot owns its command results. No worker survives the barrier.
type runtimeEnvironmentSnapshot struct {
	rules, links, routes, addresses []byte
	peers                           [2][]byte
}

func runtimeReadEnvironmentSnapshot(ctx context.Context, ip func(context.Context, ...string) ([]byte, error), nft func(context.Context) ([]byte, error), engines [2]EngineTunnel) (runtimeEnvironmentSnapshot, bool) {
	var out runtimeEnvironmentSnapshot
	tasks := []func(context.Context) error{
		func(c context.Context) error { var e error; out.rules, e = ip(c, "-j", "-4", "rule", "show"); return e },
		func(c context.Context) error { var e error; out.links, e = ip(c, "-j", "-d", "link", "show"); return e },
		func(c context.Context) error {
			var e error
			out.routes, e = ip(c, "-j", "-4", "route", "show", "table", "main")
			return e
		},
		func(c context.Context) error {
			var e error
			out.addresses, e = ip(c, "-j", "-4", "address", "show")
			return e
		},
	}
	for i, engine := range engines[:engineTunnelCount(engines)] {
		i, remote := i, engine.RemoteAddress.String()
		tasks = append(tasks, func(c context.Context) error {
			var e error
			out.peers[i], e = ip(c, "-j", "-4", "route", "get", remote)
			return e
		})
	}
	// NFT qualification and the two-worker IP census are independent reads.
	// Both branches share cancellation and drain before any snapshot is consumed.
	ok := runtimeEnvironmentReadPool(ctx, []func(context.Context) error{
		func(c context.Context) error { _, err := nft(c); return err },
		func(c context.Context) error {
			if !runtimeEnvironmentReadPool(c, tasks) {
				return ErrRuntimeEnvironment
			}
			return nil
		},
	})
	return out, ok
}

func runtimeEnvironmentReadPool(parent context.Context, tasks []func(context.Context) error) bool {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var mu sync.Mutex
	next := 0
	failed := false
	var workers sync.WaitGroup
	for n := 0; n < 2; n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				mu.Lock()
				if ctx.Err() != nil || next == len(tasks) {
					mu.Unlock()
					return
				}
				task := tasks[next]
				next++
				mu.Unlock()
				// Recheck immediately before invoking a native read, including cancellation
				// while this worker waited to be scheduled. Command wrappers check again.
				if ctx.Err() != nil {
					return
				}
				if task(ctx) != nil {
					mu.Lock()
					failed = true
					cancel()
					mu.Unlock()
					return
				}
			}
		}()
	}
	workers.Wait()
	return !failed && ctx.Err() == nil && next == len(tasks)
}

const runtimeEnvironmentCommandCeiling = 18

type runtimeEnvironmentCommandInterval struct{ start, end time.Time }
type runtimeEnvironmentCommandTiming struct {
	mu        sync.Mutex
	intervals [runtimeEnvironmentCommandCeiling]runtimeEnvironmentCommandInterval
	count     int
}

func (t *runtimeEnvironmentCommandTiming) record(start, end time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.count < len(t.intervals) {
		t.intervals[t.count] = runtimeEnvironmentCommandInterval{start, end}
		t.count++
	}
}
func (t *runtimeEnvironmentCommandTiming) result() runtimeEnvironmentTiming {
	t.mu.Lock()
	defer t.mu.Unlock()
	intervals := append([]runtimeEnvironmentCommandInterval(nil), t.intervals[:t.count]...)
	sort.Slice(intervals, func(i, j int) bool { return intervals[i].start.Before(intervals[j].start) })
	var duration time.Duration
	if len(intervals) > 0 {
		start, end := intervals[0].start, intervals[0].end
		for _, v := range intervals[1:] {
			if !v.start.After(end) {
				if v.end.After(end) {
					end = v.end
				}
			} else {
				duration += end.Sub(start)
				start, end = v.start, v.end
			}
		}
		duration += end.Sub(start)
	}
	return runtimeEnvironmentTiming{CommandMillis: duration.Milliseconds(), CommandCount: t.count}
}
