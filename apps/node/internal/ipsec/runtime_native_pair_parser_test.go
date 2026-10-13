package ipsec

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Compare actual production parsers with the SAME fixed delay for every
// request/command. Counts do not fall; only independent critical paths overlap.
func TestNativeIndependentParsedReaderCost(t *testing.T) {
	e, d, k, x := runtimeProofFixture()
	env := RuntimeEnvironment{Namespace: e.Allocation.Namespace}
	c := &RuntimeController{config: RuntimeControllerConfig{Environment: &mtuEnvironmentFixture{env: env}, DaemonAlive: func() bool { return true }}}
	counts := make([]map[string]int, 2)
	durations := make([]time.Duration, 2)
	for arm := 0; arm < 2; arm++ {
		var mu sync.Mutex
		counts[arm] = map[string]int{}
		readers := sharedParsedReaders(t, d, k, x, func(name string) { time.Sleep(100 * time.Millisecond); mu.Lock(); counts[arm][name]++; mu.Unlock() }, c.config.DaemonAlive)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		start := time.Now()
		var err error
		if arm == 0 {
			err = c.proveRuntimeWithReaders(ctx, e, env, readers)
		} else {
			err = c.proveRuntimeWithIndependentReaders(ctx, e, env, readers)
		}
		durations[arm] = time.Since(start)
		cancel()
		if err != nil {
			t.Fatal("complete actual-parser proof refused", arm, err)
		}
	}
	for arm, m := range counts {
		total := 0
		for _, v := range m {
			total += v
			if v != 2 {
				t.Fatal("original primitive count changed", arm, m)
			}
		}
		if len(m) != 10 || total != 20 {
			t.Fatal("missing production read", arm, m)
		}
	}
	t.Logf("MODELED real delayed production parsers each primitive100ms; serial=%s parallel=%s; both20primitives/2XFRMlegs/no proof or primitive eliminated", durations[0], durations[1])
}
