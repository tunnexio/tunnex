package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestShutdownDataplaneJoinsWithdrawalBeforeWireGuard(t *testing.T) {
	started, finish, closed, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	shutdown := launchIPsecRuntime(context.Background(), func(ctx context.Context) error {
		<-ctx.Done()
		close(started)
		<-finish
		return nil
	})
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	go func() { shutdownDataplane(shutdown, func() error { close(closed); return nil }, logger); close(done) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("withdrawal did not start")
	}
	select {
	case <-closed:
		t.Fatal("WireGuard deleted before withdrawal completed")
	default:
	}
	close(finish)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not finish")
	}
	select {
	case <-closed:
	default:
		t.Fatal("WireGuard was not closed")
	}
}

func TestShutdownDataplaneStillClosesWireGuardOnRefusal(t *testing.T) {
	for _, failure := range []error{errors.New("refused"), errIPsecShutdownIncomplete} {
		var order []string
		var logs bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&logs, nil))
		shutdownDataplane(func() error { order = append(order, "ipsec"); return failure }, func() error { order = append(order, "wg"); return errors.New("wg refused") }, logger)
		if !reflect.DeepEqual(order, []string{"ipsec", "wg"}) {
			t.Fatalf("shutdown order/callcount: %v", order)
		}
		if !strings.Contains(logs.String(), "ipsec_runtime_shutdown_incomplete") || !strings.Contains(logs.String(), "agent_backend_shutdown_blocked") {
			t.Fatal("shutdown refusal lost")
		}
	}
	calls := 0
	shutdownDataplane(func() error { calls++; return nil }, nil, slog.Default())
	if calls != 1 {
		t.Fatal("early shutdown did not join exactly once")
	}
}
