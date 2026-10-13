package fqdnresolver

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"net/netip"
	"testing"
	"time"
)

func TestGatewayDNSRPCCompletionClock(t *testing.T) {
	for _, tc := range []struct {
		name   string
		delay  time.Duration
		mutate func(*GatewayDNSResponse, time.Time)
		want   error
	}{
		{name: "valid slow response", delay: 1600 * time.Millisecond},
		{name: "late completion ontime observation", delay: 5100 * time.Millisecond, want: context.DeadlineExceeded},
		{name: "future", delay: 1600 * time.Millisecond, mutate: func(r *GatewayDNSResponse, n time.Time) { r.ObservedAt = n.Add(1100 * time.Millisecond) }, want: ErrGatewayDNSRPCStale},
		{name: "stale", delay: 1600 * time.Millisecond, mutate: func(r *GatewayDNSResponse, n time.Time) {
			r.ObservedAt = n.Add(-GatewayDNSResponseMaxAge - time.Second)
		}, want: ErrGatewayDNSRPCStale},
		{name: "foreign", delay: 1600 * time.Millisecond, mutate: func(r *GatewayDNSResponse, _ time.Time) { r.GatewayID = uuid.New() }, want: ErrGatewayDNSRPCIdentity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now().UTC()
			clock := start
			w := rpcWork()
			m := &scriptedMailbox{call: func(_ context.Context, q GatewayDNSRequest) (GatewayDNSResponse, error) {
				clock = start.Add(tc.delay)
				observed := clock
				if tc.delay > 5*time.Second {
					observed = start.Add(4 * time.Second)
				}
				r := responseFor(q, observed, Record{Name: w.Hostname, Type: TypeA, Address: netip.MustParseAddr("10.20.30.40"), TTL: time.Minute})
				if tc.mutate != nil {
					tc.mutate(&r, clock)
				}
				return r, nil
			}}
			tr := NewGatewayDNSRPCTransport(m)
			tr.now = func() time.Time { return clock }
			_, err := tr.LookupWork(context.Background(), w)
			if tc.want == nil && err != nil {
				t.Fatalf("valid refused: %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
}

func TestGatewayDNSRPCCompletionRejectsCanceledParent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	w := rpcWork()
	now := time.Now().UTC()
	m := &scriptedMailbox{call: func(_ context.Context, q GatewayDNSRequest) (GatewayDNSResponse, error) {
		cancel()
		return responseFor(q, now, Record{Name: w.Hostname, Type: TypeA, Address: netip.MustParseAddr("10.20.30.40"), TTL: time.Minute}), nil
	}}
	tr := NewGatewayDNSRPCTransport(m)
	tr.now = func() time.Time { return now }
	if _, err := tr.LookupWork(ctx, w); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled response got %v", err)
	}
}
