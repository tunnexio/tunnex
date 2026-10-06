package serveraccess

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestIdleRefreshCannotBeOverwrittenByOlderRenewal(t *testing.T) {
	var deadline atomic.Int64
	deadline.Store(100)
	extendDeadline(&deadline, 300)
	extendDeadline(&deadline, 200)
	if got := deadline.Load(); got != 300 {
		t.Fatalf("idle deadline regressed: %d", got)
	}
	var updates sync.WaitGroup
	for value := int64(301); value <= 500; value++ {
		updates.Add(1)
		go func(next int64) { defer updates.Done(); extendDeadline(&deadline, next) }(value)
	}
	updates.Wait()
	if got := deadline.Load(); got != 500 {
		t.Fatalf("concurrent refresh lost: %d", got)
	}
}
