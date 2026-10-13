package fqdnrpc

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

type admissionResolver struct {
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (r *admissionResolver) Resolve(ctx context.Context, _ string, _ []RecordType) ([]Record, error) {
	r.calls.Add(1)
	select {
	case r.entered <- struct{}{}:
	default:
	}
	select {
	case <-r.release:
		return []Record{{Name: "api.example.test", Type: RecordA, Address: "10.10.0.8", TTLSeconds: 30}}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func TestResponderInflightChangedIdentityNeverReachesDNS(t *testing.T) {
	x := &admissionResolver{entered: make(chan struct{}, 2), release: make(chan struct{})}
	r := NewResponder(x)
	q := testRequest(time.Now())
	done := make(chan Response, 1)
	go func() { done <- r.Handle(t.Context(), testGateway, q) }()
	<-x.entered
	changed := q
	changed.Hostname = "other.example.test"
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	got := r.Handle(ctx, testGateway, changed)
	close(x.release)
	<-done
	if got.ErrorCode != "resolver_unavailable" || x.calls.Load() != 1 {
		t.Fatalf("changed request admitted: %+v calls%d", got, x.calls.Load())
	}
}
func TestResponderInflightCancellationAndResponseIsolation(t *testing.T) {
	x := &admissionResolver{entered: make(chan struct{}, 2), release: make(chan struct{})}
	r := NewResponder(x)
	q := testRequest(time.Now())
	done := make(chan Response, 1)
	go func() { done <- r.Handle(t.Context(), testGateway, q) }()
	<-x.entered
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	got := r.Handle(ctx, testGateway, q)
	close(x.release)
	leader := <-done
	replay := r.Handle(t.Context(), testGateway, q)
	if got.Status != StatusServFail || leader.Status != StatusNoError || replay.Status != StatusNoError || x.calls.Load() != 1 {
		t.Fatalf("outcomes %v %v %v calls%d", got, leader, replay, x.calls.Load())
	}
	replay.Records[0].Address = "10.10.0.99"
	replay.RecordTypes[0] = RecordAAAA
	again := r.Handle(t.Context(), testGateway, q)
	if again.Records[0].Address != "10.10.0.8" || again.RecordTypes[0] != RecordA {
		t.Fatal("cache mutated")
	}
}

type admissionBoundResolver struct {
	admissionResolver
	validations atomic.Int32
	invalid     atomic.Bool
	deadline    chan time.Time
}

func (r *admissionBoundResolver) ResolveBound(ctx context.Context, h string, types []RecordType, _ ResolverConfig) ([]Record, error) {
	d, _ := ctx.Deadline()
	r.deadline <- d
	return r.Resolve(ctx, h, types)
}
func (r *admissionBoundResolver) ValidateBound(ctx context.Context, _ ResolverConfig) error {
	r.validations.Add(1)
	if r.invalid.Load() {
		return errResolverConfig
	}
	return ctx.Err()
}
func TestResponderInflightSharedLookupStillRevalidatesFollowers(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "current", true: "revoked"}[invalid], func(t *testing.T) {
			x := &admissionBoundResolver{admissionResolver: admissionResolver{entered: make(chan struct{}, 4), release: make(chan struct{})}, deadline: make(chan time.Time, 4)}
			r := NewResponder(x)
			q := testRequest(time.Now())
			q.ResolverIPsecPath = &IPsecPath{ConnectionID: "88888888-8888-4888-8888-888888888888", ConfigurationRevision: 3, SourceAddress: "10.10.0.1"}
			q.Deadline = time.Now().Add(time.Second)
			leader := make(chan Response, 1)
			go func() { leader <- r.Handle(t.Context(), testGateway, q) }()
			<-x.entered
			follower := make(chan Response, 1)
			go func() { follower <- r.Handle(t.Context(), testGateway, q) }()
			select {
			case got := <-follower:
				t.Fatalf("follower returned before lookup: %+v", got)
			case <-time.After(30 * time.Millisecond):
			}
			x.invalid.Store(invalid)
			close(x.release)
			a, b := <-leader, <-follower
			if a.Status != StatusNoError || x.calls.Load() != 1 || x.validations.Load() != 1 {
				t.Fatalf("lookup/validation: %v %v calls%d proofs%d", a, b, x.calls.Load(), x.validations.Load())
			}
			if invalid && b.ErrorCode != "resolver_unavailable" || !invalid && b.Status != StatusNoError {
				t.Fatalf("fresh proof outcome %+v", b)
			}
			if d := <-x.deadline; !d.Equal(q.Deadline) {
				t.Fatalf("deadline renewed %v != %v", d, q.Deadline)
			}
		})
	}
}

func TestResponderInflightOriginalDeadlineExpiresBothCalls(t *testing.T) {
	x := &admissionResolver{entered: make(chan struct{}, 2), release: make(chan struct{})}
	r := NewResponder(x)
	q := testRequest(time.Now())
	q.Deadline = time.Now().Add(80 * time.Millisecond)
	leader := make(chan Response, 1)
	go func() { leader <- r.Handle(t.Context(), testGateway, q) }()
	<-x.entered
	follower := r.Handle(t.Context(), testGateway, q)
	first := <-leader
	if follower.ErrorCode != "deadline_exceeded" || first.ErrorCode != "deadline_exceeded" || x.calls.Load() != 1 {
		t.Fatalf("deadline escaped: %+v %+v calls%d", first, follower, x.calls.Load())
	}
}
