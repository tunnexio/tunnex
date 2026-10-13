package fqdnrpc

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestDirectResolverTypePairProofBudget(t *testing.T) {
	config := concurrentResolverConfig(4)
	exchange := func(ctx context.Context, _ ResolverEndpoint, name string, typ RecordType) ([]Record, error) {
		for range 2 {
			timer := time.NewTimer(50 * time.Millisecond)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			}
		}
		if name == "api.example.test" {
			return []Record{{Name: name, Type: RecordCNAME, Target: "edge.example.test", TTLSeconds: 7}}, nil
		}
		if typ == RecordA {
			return resolvedA(name, 30), nil
		}
		return nil, nil
	}
	// Serial record-pair baseline pays every original proof; two steps cannot fit.
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	var err error
	for _, name := range []string{"api.example.test", "edge.example.test"} {
		for _, typ := range []RecordType{RecordA, RecordAAAA} {
			_, err = exchange(ctx, config.Endpoints[0], name, typ)
			if err != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("serial proof baseline unexpectedly fit")
	}
	ctx, cancel = context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	deadline, _ := ctx.Deadline()
	var calls atomic.Int32
	d := DirectResolver{exchange: func(c context.Context, e ResolverEndpoint, n string, r RecordType) ([]Record, error) {
		got, _ := c.Deadline()
		if got != deadline {
			t.Error("deadline changed")
		}
		calls.Add(1)
		return exchange(c, e, n, r)
	}}
	records, err := d.ResolveBound(ctx, "api.example.test", []RecordType{RecordA, RecordAAAA, RecordCNAME}, config)
	if err != nil || len(records) != 2 || calls.Load() != 16 || ctx.Err() != nil {
		t.Fatalf("complete pair proof failed err=%v count=%d", err, calls.Load())
	}
}
func TestDirectResolverTypeWorkersBoundedDrain(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	started := make(chan struct{}, 16)
	var active, max atomic.Int32
	d := DirectResolver{exchange: func(c context.Context, _ ResolverEndpoint, _ string, _ RecordType) ([]Record, error) {
		v := active.Add(1)
		defer active.Add(-1)
		for old := max.Load(); v > old; old = max.Load() {
			if max.CompareAndSwap(old, v) {
				break
			}
		}
		started <- struct{}{}
		<-c.Done()
		return nil, c.Err()
	}}
	done := make(chan error, 1)
	go func() {
		_, e := d.ResolveBound(ctx, "api.example.test", []RecordType{RecordA, RecordAAAA, RecordCNAME}, concurrentResolverConfig(8))
		done <- e
	}()
	for range 8 {
		select {
		case <-started:
		case <-time.After(time.Second):
			cancel()
			t.Fatal("bounded type pairs did not overlap")
		}
	}
	select {
	case <-started:
		cancel()
		t.Fatal("fanout exceeds eight")
	default:
	}
	cancel()
	select {
	case e := <-done:
		if e == nil || active.Load() != 0 || max.Load() != 8 {
			t.Fatal("cancel did not fully drain")
		}
	case <-time.After(time.Second):
		t.Fatal("drain timeout")
	}
}
func TestDirectResolverTypeOrderedErrorsAndCNAMEDisagreement(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		d := DirectResolver{exchange: func(ctx context.Context, _ ResolverEndpoint, name string, r RecordType) ([]Record, error) {
			if !mismatch {
				if r == RecordAAAA {
					return nil, resolverStatusError{StatusServFail}
				}
				time.Sleep(10 * time.Millisecond)
				return nil, resolverStatusError{StatusNXDomain}
			}
			target := "a.example.test"
			if r == RecordAAAA {
				target = "b.example.test"
			}
			return []Record{{Name: name, Type: RecordCNAME, Target: target, TTLSeconds: 10}}, nil
		}}
		records, e := d.ResolveBound(t.Context(), "api.example.test", []RecordType{RecordA, RecordAAAA, RecordCNAME}, concurrentResolverConfig(4))
		if len(records) != 0 || e == nil {
			t.Fatal("inconsistent pair accepted")
		}
		if !mismatch {
			var status resolverStatusError
			if !errors.As(e, &status) || status.status != StatusNXDomain {
				t.Fatal("completion order changed requested error precedence")
			}
		}
	}
}

func TestDirectResolverExpiredTypeWorkersNeverStart(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var calls atomic.Int32
	d := DirectResolver{exchange: func(context.Context, ResolverEndpoint, string, RecordType) ([]Record, error) {
		calls.Add(1)
		return nil, nil
	}}
	records, err := d.ResolveBound(ctx, "api.example.test", []RecordType{RecordA, RecordAAAA, RecordCNAME}, concurrentResolverConfig(8))
	if err == nil || len(records) != 0 || calls.Load() != 0 {
		t.Fatal("expired context started exchange or returned records")
	}
}
