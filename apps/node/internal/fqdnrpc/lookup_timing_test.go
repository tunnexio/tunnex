package fqdnrpc

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLookupTimingRequestOwnershipBoundsAndNoUnknownData(t *testing.T) {
	parent, cancel := context.WithTimeout(context.WithValue(t.Context(), struct{}{}, "private-value"), 5*time.Second)
	defer cancel()
	ctx, a := WithLookupTiming(parent)
	other, b := WithLookupTiming(parent)
	if d, _ := ctx.Deadline(); func() bool { p, _ := parent.Deadline(); return !d.Equal(p) }() || ctx.Value(struct{}{}) != "private-value" {
		t.Fatal("context authority changed")
	}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for n := 0; n < 100; n++ {
				RecordLookupPhase(ctx, "before", time.Hour, true)
				RecordLookupPhase(ctx, "after", -time.Second, false)
				RecordLookupPhase(ctx, "socket", time.Second, false)
				RecordLookupPhase(ctx, "private-hostname-payload", time.Hour, true)
				RecordLookupExchange(ctx, n%2 == 0)
			}
		}()
	}
	workers.Wait()
	v := a.Snapshot()
	if !v.StatsSaturated || v.BeforeProof.Count != lookupExchangeCeiling || v.BeforeProof.SummedMillis != 300000 || v.BeforeProof.MaxMillis != 300000 || v.AfterProof.MaxMillis != 0 || v.ReturnedExchanges != lookupExchangeCeiling || v.CompletedExchanges > v.ReturnedExchanges {
		t.Fatal("unbounded summary", v)
	}
	if b.Snapshot().ReturnedExchanges != 0 {
		t.Fatal("request contamination")
	}
	RecordLookupPhase(parent, "before", time.Second, true)
	RecordLookupExchange(parent, true)
	markLookupWorkersDrained(ctx)
	markLookupWorkersDrained(other)
	finishLookupTiming(ctx, errors.New("private-error"))
	finishLookupTiming(other, nil)
	v = a.Snapshot()
	if v.Outcome != "resolver_failure" || !v.ReductionObserved || v.RemainingAtReductionMillis <= 0 || v.RemainingAtReductionMillis > 5000 || b.Snapshot().Outcome != "success" {
		t.Fatal("bad reduction")
	}
	raw, _ := json.Marshal(v)
	if strings.Contains(string(raw), "private") {
		t.Fatal("untrusted input echoed")
	}
	cancel()
	finishLookupTiming(ctx, nil)
	if a.Snapshot().Outcome != "canceled" {
		t.Fatal("cancel mislabeled")
	}
}

func TestLookupTimingResolverSuccessFailureAndExpiredDeadline(t *testing.T) {
	for _, kind := range []string{"success", "failure", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.Context()
			if kind == "deadline" {
				var cancel context.CancelFunc
				parent, cancel = context.WithDeadline(parent, time.Now().Add(-time.Second))
				defer cancel()
			}
			ctx, a := WithLookupTiming(parent)
			d := DirectResolver{exchange: func(c context.Context, _ ResolverEndpoint, name string, _ RecordType) ([]Record, error) {
				if kind == "failure" {
					return nil, errors.New("private-response")
				}
				return resolvedA(name, 30), nil
			}}
			_, err := d.ResolveBound(ctx, "secret.example.test", []RecordType{RecordA}, concurrentResolverConfig(2))
			v := a.Snapshot()
			want := "success"
			if kind == "failure" {
				want = "resolver_failure"
			}
			if kind == "deadline" {
				want = "deadline"
			}
			if !v.EndpointWorkersDrained || !v.ReductionObserved || v.Outcome != want || (err == nil) != (kind == "success") {
				t.Fatal("incorrect result", v, err)
			}
			if v.TransportTimingObserved {
				t.Fatal("generic exchange falsely reported native proofs")
			}
		})
	}
}

func TestLookupTimingCancellationReturnsAfterWorkerDrain(t *testing.T) {
	parent, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx, a := WithLookupTiming(parent)
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	done := make(chan error, 1)
	d := DirectResolver{exchange: func(c context.Context, _ ResolverEndpoint, _ string, _ RecordType) ([]Record, error) {
		entered <- struct{}{}
		<-c.Done()
		<-release
		RecordLookupPhase(c, "before", time.Millisecond, false)
		RecordLookupExchange(c, false)
		return nil, c.Err()
	}}
	go func() {
		_, err := d.ResolveBound(ctx, "private.example.test", []RecordType{RecordA}, concurrentResolverConfig(2))
		done <- err
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("workers did not start")
		}
	}
	cancel()
	v := a.Snapshot()
	if v.EndpointWorkersDrained || v.ReductionObserved || v.ReturnedExchanges != 0 {
		t.Fatal("claimed completion while workers live", v)
	}
	select {
	case <-done:
		t.Fatal("returned before workers drained")
	default:
	}
	close(release)
	if <-done == nil {
		t.Fatal("cancellation succeeded")
	}
	v = a.Snapshot()
	if !v.EndpointWorkersDrained || !v.ReductionObserved || v.Outcome != "canceled" || v.ReturnedExchanges != 2 || v.CompletedExchanges != 0 || v.BeforeProof.Refused != 2 {
		t.Fatal("final worker accounting missing", v)
	}
}

func TestLookupTimingEarlyRefusalDoesNotClaimReduction(t *testing.T) {
	ctx, a := WithLookupTiming(t.Context())
	if _, err := (DirectResolver{}).ResolveBound(ctx, "private", []RecordType{RecordA}, ResolverConfig{}); err == nil {
		t.Fatal("invalid config admitted")
	}
	v := a.Snapshot()
	if v.EndpointWorkersDrained || v.ReductionObserved || v.RemainingAtReductionMillis != 0 || v.Outcome != "resolver_failure" {
		t.Fatal("early refusal claimed a complete reduction", v)
	}
}

func TestLookupTimingExactFallbackBoundAndOverflowFlag(t *testing.T) {
	ctx, a := WithLookupTiming(t.Context())
	for i := 0; i < 288; i++ {
		RecordLookupExchange(ctx, true)
		RecordLookupPhase(ctx, "socket", time.Millisecond, true)
	}
	v := a.Snapshot()
	if v.ReturnedExchanges != 288 || v.CompletedExchanges != 288 || v.Socket.Count != 288 || v.StatsSaturated {
		t.Fatal("valid bounded fallback workload saturated", v)
	}
	RecordLookupExchange(ctx, true)
	RecordLookupPhase(ctx, "socket", time.Millisecond, true)
	v = a.Snapshot()
	if v.ReturnedExchanges != 288 || v.CompletedExchanges != 288 || v.Socket.Count != 288 || !v.StatsSaturated {
		t.Fatal("dropped sample was not indicated", v)
	}
}
