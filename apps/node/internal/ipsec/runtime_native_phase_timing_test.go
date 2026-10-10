package ipsec

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type nativePhaseEnvironment struct {
	value  RuntimeEnvironment
	order  *[]string
	expire bool
}

func (e nativePhaseEnvironment) Observe(ctx context.Context, _ KernelAllocation, _ [2]EngineTunnel) (RuntimeEnvironment, error) {
	*e.order = append(*e.order, "environment")
	if e.expire {
		<-ctx.Done()
		return RuntimeEnvironment{}, ctx.Err()
	}
	time.Sleep(3 * time.Millisecond)
	return e.value, nil
}
func (nativePhaseEnvironment) Drain(context.Context, []RuntimeJournalEntry) error { return nil }

func TestNativePhaseTimingPreservesProofAndDeadline(t *testing.T) {
	for _, expire := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "deadline"}[expire], func(t *testing.T) {
			var previousErr error
			var previousOrder []string
			for _, enabled := range []bool{false, true} {
				c, _, _, _ := bgpControllerFixture(t, true)
				var active runtimeActive
				for _, a := range c.active {
					active = a
				}
				var order []string
				original := c.kernel.run
				c.kernel.run = func(ctx context.Context, args ...string) ([]byte, error) {
					order = append(order, "route")
					return original(ctx, args...)
				}
				c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string {
					order = append(order, "recovery")
					time.Sleep(3 * time.Millisecond)
					return [2]string{"up", "up"}
				}
				c.config.Environment = nativePhaseEnvironment{value: active.Environment, order: &order, expire: expire}
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
				var phases runtimeNativePhaseTiming
				calls := 0
				var observer func(runtimeNativePhaseTiming)
				if enabled {
					observer = func(v runtimeNativePhaseTiming) { calls++; phases = v }
				}
				start := time.Now()
				got := c.proveBGPCurrentTimed(ctx, active.Entry, active.Environment, nil, observer)
				elapsed := time.Since(start)
				cancel()
				if !enabled {
					previousErr = got
					previousOrder = order
				} else {
					if !errors.Is(got, previousErr) || !reflect.DeepEqual(order, previousOrder) {
						t.Fatal("timing changed proof/read order")
					}
					if calls != 1 || phases.RecoveryMillis < 2 || phases.EnvironmentMillis < 2 || phases.ElapsedMillis < phases.RecoveryMillis+phases.EnvironmentMillis || phases.RemainingAtEntryMillis < 1 || phases.RemainingAtEntryMillis > 60 {
						t.Fatal("phase scalar incorrect", phases, calls)
					}
					if !validDNSReadTiming(runtimeDNSReadTiming{Native: phases}) {
						t.Fatal("valid phase rejected")
					}
				}
				if expire && (got == nil || elapsed > 250*time.Millisecond) {
					t.Fatal("original deadline changed", got, elapsed)
				}
			}
		})
	}
}

func TestNativePhaseTimingScalarBounds(t *testing.T) {
	fields := []func(*runtimeNativePhaseTiming, int64){func(v *runtimeNativePhaseTiming, n int64) { v.RouteMillis = n }, func(v *runtimeNativePhaseTiming, n int64) { v.RecoveryMillis = n }, func(v *runtimeNativePhaseTiming, n int64) { v.EnvironmentMillis = n }, func(v *runtimeNativePhaseTiming, n int64) { v.ElapsedMillis = n }, func(v *runtimeNativePhaseTiming, n int64) { v.RemainingAtEntryMillis = n }}
	for _, set := range fields {
		for _, n := range []int64{-1, 60001} {
			var v runtimeNativePhaseTiming
			set(&v, n)
			if validDNSReadTiming(runtimeDNSReadTiming{Native: v}) {
				t.Fatal("out-of-bound native scalar accepted")
			}
		}
	}
}
