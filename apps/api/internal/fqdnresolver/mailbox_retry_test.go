package fqdnresolver

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgconn"
	"testing"
	"time"
)

func TestMailboxCompletionRetryOnlyTypedSerialization(t *testing.T) {
	pg := &pgconn.PgError{Code: "40001"}
	network := errors.New("ambiguous commit network")
	for _, tc := range []struct {
		name  string
		err   error
		calls int
	}{
		{"typed", pg, 3}, {"wrapped", fmt.Errorf("server: %w", pg), 3},
		{"text", errors.New("SQLSTATE 40001"), 1}, {"network", network, 1},
		{"deadlock", &pgconn.PgError{Code: "40P01"}, 1}, {"joined", errors.Join(pg, network), 1},
		{"replay", ErrGatewayDNSRPCReplay, 1}, {"stale", ErrGatewayDNSRPCStale, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := retryMailboxCompletion(context.Background(), func() error { calls++; return tc.err })
			if err != tc.err || calls != tc.calls {
				t.Fatal("retry/error precedence changed")
			}
		})
	}
	calls := 0
	err := retryMailboxCompletion(context.Background(), func() error {
		calls++
		if calls < 3 {
			return pg
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Fatal("bounded successful retry refused")
	}
}
func TestMailboxCompletionRetryOriginalContext(t *testing.T) {
	pg := &pgconn.PgError{Code: "40001"}
	for _, cancelBefore := range []bool{true, false} {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		if cancelBefore {
			cancel()
		}
		err := retryMailboxCompletion(ctx, func() error { calls++; cancel(); return pg })
		if !errors.Is(err, context.Canceled) || calls != map[bool]int{true: 0, false: 1}[cancelBefore] {
			t.Fatal("cancellation lost to serialization")
		}
		cancel()
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	calls := 0
	err := retryMailboxCompletion(ctx, func() error { calls++; return nil })
	if !errors.Is(err, context.DeadlineExceeded) || calls != 0 {
		t.Fatal("expired original budget dispatched")
	}
	// A new attempt must execute all validation logic, not replay a prior success.
	calls = 0
	err = retryMailboxCompletion(context.Background(), func() error {
		calls++
		if calls == 1 {
			return pg
		}
		return ErrSuperseded
	})
	if !errors.Is(err, ErrSuperseded) || calls != 2 {
		t.Fatal("changed context retried past refusal")
	}
	calls = 0
	err = retryMailboxCompletion(context.Background(), func() error {
		calls++
		if calls == 1 {
			return pg
		}
		return ErrGatewayDNSRPCStale
	})
	if !errors.Is(err, ErrGatewayDNSRPCStale) || calls != 2 {
		t.Fatal("deadline refusal bypassed")
	}
}
