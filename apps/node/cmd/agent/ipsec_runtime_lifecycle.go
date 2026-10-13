package main

import (
	"context"
	"errors"
	"time"
)

const ipsecShutdownWait = 20 * time.Second

var errIPsecShutdownIncomplete = errors.New("IPsec runtime shutdown incomplete")

// The completion signal follows all owned runtime defers, including child
// process termination and inode-checked cleanup. It never adopts stale files.
func launchIPsecRuntime(parent context.Context, run func(context.Context) error) func() error {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	var result error
	go func() {
		defer close(done)
		result = run(ctx)
	}()
	return func() error {
		cancel()
		if err := awaitIPsecShutdown(done, ipsecShutdownWait); err != nil {
			return err
		}
		return result
	}
}

func awaitIPsecShutdown(done <-chan struct{}, limit time.Duration) error {
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return errIPsecShutdownIncomplete
	}
}
