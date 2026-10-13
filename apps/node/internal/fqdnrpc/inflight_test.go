package fqdnrpc

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type inflightResolver struct {
	entered chan struct{}
	release chan struct{}
}

func (r inflightResolver) ResolveBound(ctx context.Context, n string, _ []RecordType, _ ResolverConfig) ([]Record, error) {
	r.entered <- struct{}{}
	select {
	case <-r.release:
		return []Record{{Name: n, Type: RecordA, Address: "10.231.1.4", TTLSeconds: 30}}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func TestResponderRunOnePendingHandleAndReport(t *testing.T) {
	r := inflightResolver{make(chan struct{}, 2), make(chan struct{})}
	s := NewResponder(r)
	req := testRequest(time.Now())
	var reports atomic.Int32
	var wg sync.WaitGroup
	wg.Add(1)
	callback := func() {
		response := s.Handle(context.Background(), testGateway, req)
		if response.RequestID != req.RequestID {
			t.Error("identity changed")
		}
		reports.Add(1)
	}
	go func() { defer wg.Done(); s.Run(context.Background(), testGateway, req, callback) }()
	<-r.entered
	done := make(chan RunDisposition, 1)
	go func() { done <- s.Run(context.Background(), testGateway, req, callback) }()
	var disposition RunDisposition
	select {
	case disposition = <-done:
	case <-r.entered:
		close(r.release)
		wg.Wait()
		<-done
		t.Fatal("same immutable pending request executed second Handle/proof fanout")
	case <-time.After(time.Second):
		close(r.release)
		wg.Wait()
		t.Fatal("duplicate admission blocked")
	}
	if disposition != RunDuplicatePending {
		close(r.release)
		wg.Wait()
		t.Fatal("not duplicate")
	}
	changed := req
	changed.Hostname = "other.example.test"
	if s.Run(context.Background(), testGateway, changed, func() { t.Fatal("changed sameID ran") }) != RunConflictingPending {
		t.Fatal("conflict not refused")
	}
	close(r.release)
	wg.Wait()
	if reports.Load() != 1 {
		t.Fatal("more than one report")
	}
	// Existing completed replay still runs/report again; it is not a permanent
	// dedup or answer-sharing admission cache.
	if s.Run(context.Background(), testGateway, req, callback) != RunCompleted || reports.Load() != 2 {
		t.Fatal("completed replay changed")
	}
}
func TestResponderRunDifferentIDIndependentAndRelease(t *testing.T) {
	s := NewResponder(nil)
	req := testRequest(time.Now())
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(context.Background(), testGateway, req, func() { close(entered); <-release })
	}()
	<-entered
	different := req
	different.RequestID = "85555555-5555-5555-5555-555555555555"
	called := false
	if s.Run(context.Background(), testGateway, different, func() { called = true }) != RunCompleted || !called {
		t.Fatal("differentID blocked")
	}
	close(release)
	<-done
	for _, kind := range []string{"failure", "cancel", "panic"} {
		func() {
			defer func() { recover() }()
			s.Run(context.Background(), testGateway, req, func() {
				if kind == "panic" {
					panic("synthetic callback")
				}
				if kind == "cancel" {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					<-ctx.Done()
				}
			})
		}()
		called = false
		if s.Run(context.Background(), testGateway, req, func() { called = true }) != RunCompleted || !called {
			t.Fatal("failed lifecycle retained admission", kind)
		}
	}
}
func TestResponderRunMalformedExpiredUnchangedAndBounded(t *testing.T) {
	s := NewResponder(nil)
	req := testRequest(time.Now())
	for _, mutate := range []func(*Request){func(r *Request) { r.RequestID = "" }, func(r *Request) { r.Version = 999 }, func(r *Request) { r.Deadline = time.Now().Add(-time.Second) }} {
		bad := req
		mutate(&bad)
		called := false
		if s.Run(context.Background(), testGateway, bad, func() {
			called = true
			response := s.Handle(context.Background(), testGateway, bad)
			if response.Status != StatusServFail {
				t.Fatal("typed refusal changed")
			}
		}) != RunCompleted || !called {
			t.Fatal("invalid path altered")
		}
	}
	var wg sync.WaitGroup
	release := make(chan struct{})
	entered := make(chan struct{}, maxInflightRequests)
	for i := 0; i < maxInflightRequests; i++ {
		r := req
		r.RequestID = fmt.Sprintf("%08x-5555-5555-5555-555555555555", i+1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Run(context.Background(), testGateway, r, func() { entered <- struct{}{}; <-release })
		}()
	}
	for range maxInflightRequests {
		<-entered
	}
	extra := req
	extra.RequestID = "95555555-5555-5555-5555-555555555555"
	if s.Run(context.Background(), testGateway, extra, func() { t.Fatal("capacity ran/displaced") }) != RunAtCapacity {
		close(release)
		wg.Wait()
		t.Fatal("no bound")
	}
	close(release)
	wg.Wait()
	called := false
	if s.Run(context.Background(), testGateway, extra, func() { called = true }) != RunCompleted || !called {
		t.Fatal("released capacity retained")
	}
}

func TestResponderRunCanceledLookupAndFailedReportRelease(t *testing.T) {
	r := inflightResolver{make(chan struct{}, 1), make(chan struct{})}
	s := NewResponder(r)
	req := testRequest(time.Now())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var reports atomic.Int32
	go func() {
		defer close(done)
		s.Run(ctx, testGateway, req, func() {
			response := s.Handle(ctx, testGateway, req)
			if response.Status != StatusServFail {
				t.Error("cancelled actual lookup did not refuse")
			}
			reports.Add(1) /* failed report returns from original callback, no retry */
		})
	}()
	<-r.entered
	cancel()
	<-done
	called := false
	if s.Run(context.Background(), testGateway, req, func() { called = true; reports.Add(1) }) != RunCompleted || !called || reports.Load() != 2 {
		t.Fatal("cancel/report failure left active admission")
	}
}
