package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestIPsecShutdownWaitsForOwnedCleanup(t *testing.T) {
	cleaning := make(chan struct{})
	release := make(chan struct{})
	cleaned := make(chan struct{})
	shutdown := launchIPsecRuntime(context.Background(), func(ctx context.Context) error {
		defer func() { close(cleaning); <-release; close(cleaned) }()
		<-ctx.Done()
		return nil
	})
	result := make(chan error, 1)
	go func() { result <- shutdown() }()
	select {
	case <-cleaning:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel runtime")
	}
	select {
	case <-result:
		t.Fatal("shutdown returned before owned cleanup")
	default:
	}
	close(release)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-cleaned:
		default:
			t.Fatal("cleanup incomplete")
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown failed to join")
	}
	if err := shutdown(); err != nil {
		t.Fatal("completed shutdown must remain joinable", err)
	}
}

func TestIPsecShutdownBoundDoesNotClaimCleanup(t *testing.T) {
	done := make(chan struct{})
	if err := awaitIPsecShutdown(done, time.Millisecond); !errors.Is(err, errIPsecShutdownIncomplete) {
		t.Fatal(err)
	}
	close(done)
	if err := awaitIPsecShutdown(done, time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestIPsecShutdownReportsOwnedCleanupFailure(t *testing.T) {
	failure := errors.New("owned cleanup failed")
	shutdown := launchIPsecRuntime(context.Background(), func(ctx context.Context) error { <-ctx.Done(); return failure })
	if err := shutdown(); !errors.Is(err, failure) {
		t.Fatal(err)
	}
}
