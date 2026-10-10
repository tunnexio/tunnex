package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFQDNTimingPreservesCallsContextAndResponse(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		ctx := context.WithValue(t.Context(), struct{}{}, "private-context")
		dispatch := time.Date(2026, 10, 10, 18, 0, 0, 0, time.UTC)
		request := fqdnrpc.Request{RequestID: "private-nonce", Hostname: "secret-host", Deadline: dispatch.Add(5 * time.Second)}
		response := fqdnrpc.Response{RequestID: "private-nonce", Hostname: "secret-host", Status: fqdnrpc.Status("untrusted-secret-status"), ErrorCode: "private-error"}
		deliveryErr := errors.New("private-delivery-error")
		order := []string{}
		events := []fqdnRPCTiming{}
		times := []time.Time{dispatch.Add(100 * time.Millisecond), dispatch.Add(2100 * time.Millisecond), dispatch.Add(2300 * time.Millisecond)}
		clock := func() time.Time {
			if !enabled {
				t.Fatal("default-off accessed clock")
			}
			v := times[0]
			times = times[1:]
			return v
		}
		got, err := timedFQDNResolve(ctx, "private-node", request, dispatch, enabled, func(c context.Context, node string, r fqdnrpc.Request) fqdnrpc.Response {
			order = append(order, "handle")
			if c != ctx || node != "private-node" || !reflect.DeepEqual(r, request) {
				t.Fatal("handle inputs changed")
			}
			return response
		}, func(c context.Context, r fqdnrpc.Response) error {
			order = append(order, "report")
			if c != ctx || !reflect.DeepEqual(r, response) {
				t.Fatal("report inputs changed")
			}
			return deliveryErr
		}, clock, func(e fqdnRPCTiming) { events = append(events, e) })
		if err != deliveryErr || !reflect.DeepEqual(got, response) || !reflect.DeepEqual(order, []string{"handle", "report"}) {
			t.Fatal("call flow/response changed")
		}
		if !enabled {
			if len(events) != 0 {
				t.Fatal("default-off emitted")
			}
			continue
		}
		if len(events) != 1 {
			t.Fatal("expected one event")
		}
		e := events[0]
		if e.DeadlineRemainingMillis != 5000 || e.StartDelayMillis != 100 || e.HandleMillis != 2000 || e.ReportMillis != 200 || e.Status != "unknown" || e.Result != "unknown" || e.Delivery != "failure" || e.Context != "active" {
			t.Fatalf("incorrect fixed timing %+v", e)
		}
		encoded, _ := json.Marshal(e)
		if strings.Contains(string(encoded), "private") || strings.Contains(string(encoded), "secret") {
			t.Fatal("private data echoed")
		}
	}
}
func TestFQDNTimingBoundsAndContext(t *testing.T) {
	for _, tc := range []struct {
		duration time.Duration
		signed   bool
		want     int64
	}{{time.Hour, true, 300000}, {-time.Hour, true, -300000}, {-time.Hour, false, 0}, {time.Hour, false, 300000}} {
		if boundedFQDNMillis(tc.duration, tc.signed) != tc.want {
			t.Fatal("unbounded timing")
		}
	}
	for _, deadline := range []bool{false, true} {
		var ctx context.Context
		var cancel context.CancelFunc
		want := "canceled"
		if deadline {
			ctx, cancel = context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
			want = "deadline"
		} else {
			ctx, cancel = context.WithCancel(t.Context())
			cancel()
		}
		defer cancel()
		now := time.Now()
		var event fqdnRPCTiming
		_, err := timedFQDNResolve(ctx, "", fqdnrpc.Request{Deadline: now}, now, true, func(context.Context, string, fqdnrpc.Request) fqdnrpc.Response {
			return fqdnrpc.Response{Status: fqdnrpc.StatusNoError, ErrorCode: "deadline_exceeded"}
		}, func(context.Context, fqdnrpc.Response) error { return nil }, func() time.Time { return now }, func(e fqdnRPCTiming) { event = e })
		if err != nil || event.Context != want || event.Status != "NOERROR" || event.Result != "deadline_exceeded" || event.Delivery != "success" {
			t.Fatal("typed context/result classification changed")
		}
	}
}
